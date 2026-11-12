"""Loopback-only CERN web OIDC diagnostic; never creates an ASCA identity/session.

This is a separately launched, single-process development laboratory, NOT a
production BFF. Authorization is always disabled, including after valid checks.
No tokens, claims, browser bindings, codes, or secrets are ever printed.
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qsl

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from starlette.middleware.trustedhost import TrustedHostMiddleware

from asca.application.identity import OidcAuthorizationService, OidcClientConfiguration
from asca.application.oidc_claims import _parse_claims
from asca.application.oidc_discovery import (
    CERN_OIDC_ISSUER,
    OidcDiscoveryPolicy,
    validate_oidc_metadata,
)
from asca.application.oidc_role_claims import inspect_untrusted_cern_application_role
from asca.application.oidc_token_response import parse_unverified_oidc_token_response
from asca.domain.identity import AuthorizationCodeGrant
from asca.domain.oidc_browser_cookie import (
    OidcBrowserCookie,
    OidcBrowserCookieError,
    read_browser_binding_cookie,
)
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_role_claims import OidcRoleClaimsError
from asca.domain.oidc_token_http import UnverifiedOidcTokenHttpResponse
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken
from asca.infrastructure.identity_memory import InMemoryAuthorizationAttemptStore
from asca.infrastructure.oidc_http import HttpsOidcMetadataFetcher
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

ROOT = Path(__file__).resolve().parents[1]
SECRET_FILE = ROOT / "diagnostics/cern-web-probe/client_secret"
BASE_URL = "https://localhost:8443"
CALLBACK_URI = BASE_URL + "/oidc/callback"
AUTH_ENDPOINT = CERN_OIDC_ISSUER + "/protocol/openid-connect/auth"
TOKEN_ENDPOINT = CERN_OIDC_ISSUER + "/protocol/openid-connect/token"
JWKS_ENDPOINT = CERN_OIDC_ISSUER + "/protocol/openid-connect/certs"
ATTEMPT_TTL_SECONDS = 180
MAX_TOKEN_BYTES = 65_536
HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; style-src 'none'; frame-ancestors 'none'",
}
_CLIENT_ID = re.compile(r"[A-Za-z0-9._~:-]{1,256}\Z", re.ASCII)
_SECRET = re.compile(r"[\x21-\x7e]{16,512}\Z", re.ASCII)
_STATE = re.compile(r"[A-Za-z0-9_-]{43,128}\Z", re.ASCII)
_CODE = re.compile(r"[\x21-\x7e]{1,2048}\Z", re.ASCII)
_ERROR = re.compile(r"[A-Za-z0-9._~-]{1,128}\Z", re.ASCII)
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})", re.ASCII)
_ALLOWED_CALLBACK = frozenset(
    {"state", "code", "error", "iss", "session_state", "error_description", "error_uri"}
)


class ProbeError(ValueError):
    """Sanitized rejection; do not attach source exceptions or sensitive data."""


def _validate_metadata(metadata: OidcProviderMetadata) -> OidcProviderMetadata:
    if (
        not isinstance(metadata, OidcProviderMetadata)
        or metadata.issuer != CERN_OIDC_ISSUER
        or metadata.authorization_endpoint != AUTH_ENDPOINT
        or metadata.token_endpoint != TOKEN_ENDPOINT
        or metadata.jwks_uri != JWKS_ENDPOINT
        or metadata.supports_authorization_code is not True
        or metadata.supports_pkce_s256 is not True
        or not metadata.approved_id_token_algorithms
        or any(a not in {"RS256", "PS256", "ES256"} for a in metadata.approved_id_token_algorithms)
    ):
        raise ProbeError("Unapproved CERN provider metadata")
    return metadata


def discover_cern_metadata() -> OidcProviderMetadata:
    """Trust TLS and the pinned CERN issuer, never a caller-supplied URL."""
    policy = OidcDiscoveryPolicy()
    fetcher = HttpsOidcMetadataFetcher(policy)
    document = fetcher.fetch(policy.discovery_url)
    if not isinstance(document, dict):
        raise ProbeError("Invalid CERN provider metadata")
    methods = document.get("token_endpoint_auth_methods_supported")
    if methods is not None and (
        not isinstance(methods, list) or "client_secret_basic" not in methods
    ):
        raise ProbeError("CERN client_secret_basic is not advertised")
    return _validate_metadata(validate_oidc_metadata(document, policy))


def _safe_secret_file() -> str:
    """Read an owner-only credential file. Never print its path or contents on errors."""
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(SECRET_FILE, flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or not 0 < info.st_size <= 1024
        ):
            raise ProbeError("Client secret file is not protected")
        secret = os.read(descriptor, 1025).decode("ascii").strip("\r\n")
        if _SECRET.fullmatch(secret) is None:
            raise ProbeError("Client secret is not valid")
        return secret
    except (OSError, ValueError, UnicodeError):
        raise ProbeError("Client secret file is unavailable or invalid") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def provision_secret() -> None:
    """One-time terminal-only entry; never include a client secret in CLI arguments."""
    SECRET_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if SECRET_FILE.parent.is_symlink():
        raise ProbeError("Invalid credential directory")
    secret = getpass.getpass("CERN asca-web-dev client secret (not echoed): ")
    if _SECRET.fullmatch(secret) is None:
        raise ProbeError("Client secret must be a nonempty printable ASCII value")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(SECRET_FILE, flags, 0o600)
    except OSError:
        raise ProbeError("Credential file already exists or cannot be created") from None
    try:
        os.write(descriptor, secret.encode("ascii"))
    finally:
        os.close(descriptor)
    print("CLIENT_SECRET=STORED_LOCALLY_OUTSIDE_GIT")


def _assert_local_https(request: Request) -> None:
    if request.scope.get("scheme") != "https":
        raise ProbeError("HTTPS loopback required")
    raw_headers = request.scope.get("headers")
    if not isinstance(raw_headers, list):
        raise ProbeError("Invalid request headers")
    hosts = [value for name, value in raw_headers if name.lower() == b"host"]
    if hosts != [b"localhost:8443"]:
        raise ProbeError("Invalid loopback host")


def _single_cookie(request: Request) -> str:
    raw_headers = request.scope.get("headers")
    if not isinstance(raw_headers, list):
        raise ProbeError("Invalid request headers")
    headers = [value for name, value in raw_headers if name.lower() == b"cookie"]
    if len(headers) != 1 or not 0 < len(headers[0]) <= 8192:
        raise ProbeError("Missing or ambiguous browser cookie")
    try:
        return read_browser_binding_cookie(headers[0].decode("ascii"))
    except (UnicodeError, OidcBrowserCookieError):
        raise ProbeError("Browser cookie was rejected") from None


def _parse_callback(request: Request) -> dict[str, str]:
    raw = request.scope.get("query_string")
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 4096:
        raise ProbeError("Invalid authorization callback")
    try:
        query = raw.decode("ascii")
        if (
            _BAD_PERCENT.search(query)
            or "#" in query
            or any(ord(c) < 33 or ord(c) >= 127 for c in query)
        ):
            raise ValueError
        pairs = parse_qsl(query, strict_parsing=True, keep_blank_values=True, max_num_fields=7)
        values: dict[str, str] = {}
        for k, v in pairs:
            if k not in _ALLOWED_CALLBACK or k in values:
                raise ValueError
            values[k] = v
        if (
            _STATE.fullmatch(values.get("state", "")) is None
            or ("code" in values) == ("error" in values)
            or ("code" in values and _CODE.fullmatch(values["code"]) is None)
            or ("error" in values and _ERROR.fullmatch(values["error"]) is None)
            or ("iss" in values and values["iss"] != CERN_OIDC_ISSUER)
            or ("session_state" in values and len(values["session_state"]) > 512)
        ):
            raise ValueError
        return values
    except (UnicodeError, ValueError):
        raise ProbeError("Authorization callback was rejected") from None


def exchange_confidential_code(grant: AuthorizationCodeGrant, client_id: str, secret: str) -> bytes:
    """One no-redirect, bounded TLS POST with HTTP Basic client authentication."""
    with (
        httpx.Client(follow_redirects=False, timeout=10, trust_env=False) as client,
        client.stream(
            "POST",
            TOKEN_ENDPOINT,
            auth=httpx.BasicAuth(client_id, secret),
            headers={"Accept": "application/json", "Accept-Encoding": "identity"},
            data={
                "grant_type": "authorization_code",
                "code": grant.code,
                "code_verifier": grant.code_verifier,
                "redirect_uri": CALLBACK_URI,
            },
        ) as response,
    ):
        if (
            response.status_code != 200
            or response.headers.get("content-type", "").split(";", 1)[0].lower()
            != "application/json"
            or response.headers.get("content-encoding", "identity") != "identity"
        ):
            raise ProbeError("CERN code exchange failed")
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > MAX_TOKEN_BYTES:
                raise ProbeError("CERN token response exceeded limit")
        if not body:
            raise ProbeError("Empty CERN token response")
        return bytes(body)


@dataclass(frozen=True, slots=True)
class CernWebClaimObservation:
    """Diagnostic-only view; no subject, claims, tokens, grants, or sessions."""

    checked: CheckedUntrustedCernOidcToken = field(repr=False)
    role_status: Literal[
        "CLAIMED", "ABSENT", "MFA_REQUIRED", "LOA_REQUIRED", "MFA_AND_LOA_REQUIRED"
    ]
    acr_claim: Literal["PRESENT", "ABSENT"]
    amr_claim: Literal["PRESENT", "ABSENT", "EMPTY"]
    auth_time_claim: Literal["PRESENT", "ABSENT"]


def _assurance_claim_presence(payload: bytes, *, now: int) -> tuple[str, str, str]:
    """Validate shapes, never infer assurance level/method semantics or freshness."""
    claims = _parse_claims(payload)
    acr = "ABSENT"
    if "acr" in claims:
        value = claims["acr"]
        if type(value) is not str or re.fullmatch(r"[\x21-\x7e]{1,256}", value) is None:
            raise ProbeError("OIDC assurance claim was rejected")
        acr = "PRESENT"

    amr = "ABSENT"
    if "amr" in claims:
        value = claims["amr"]
        if (
            type(value) is not list
            or len(value) > 16
            or any(
                type(item) is not str or re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", item) is None
                for item in value
            )
            or len(set(value)) != len(value)
        ):
            raise ProbeError("OIDC assurance claim was rejected")
        amr = "PRESENT" if value else "EMPTY"

    auth_time = "ABSENT"
    if "auth_time" in claims:
        value = claims["auth_time"]
        if type(value) is not int or not 1 <= value < 2**53 or value > now + 60:
            raise ProbeError("OIDC assurance claim was rejected")
        auth_time = "PRESENT"
    return acr, amr, auth_time


class CernWebClaimObservationVerifier:
    """One pinned JWKS check, then strictly scoped role and assurance observation.

    This deliberately calls an internal verification method for the unmounted
    experiment. It must not become a production authorization interface.
    """

    def __init__(self) -> None:
        self._pipeline = CernOidcVerificationPipeline()

    def check(
        self,
        tokens: object,
        metadata: OidcProviderMetadata,
        *,
        expected_client_id: str,
        expected_nonce: str,
        now: int,
    ) -> CernWebClaimObservation:
        if expected_client_id != "asca-web-dev":
            raise ProbeError("Only the registered web diagnostic client is permitted")
        signed, claims = self._pipeline._verified_payload(
            tokens,
            metadata,
            expected_client_id=expected_client_id,
            expected_nonce=expected_nonce,
            now=now,
        )
        try:
            role = inspect_untrusted_cern_application_role(
                signed,
                expected_client_id=expected_client_id,
                expected_nonce=expected_nonce,
                expected_role="asca-developer",
                now=now,
                expected_access_token=tokens.access_token,
            )
            acr, amr, auth_time = _assurance_claim_presence(signed.payload, now=now)
        except (OidcRoleClaimsError, ValueError, TypeError, AttributeError):
            raise ProbeError("CERN claim observation was rejected") from None
        statuses = {
            "claimed": "CLAIMED",
            "absent": "ABSENT",
            "mfa_required": "MFA_REQUIRED",
            "loa_required": "LOA_REQUIRED",
            "mfa_and_loa_required": "MFA_AND_LOA_REQUIRED",
        }
        if role.status not in statuses:
            raise ProbeError("Unexpected role observation")
        checked = CheckedUntrustedCernOidcToken(
            issuer=claims.issuer,
            subject=claims.subject,
            audiences=claims.audiences,
            expires_at=claims.expires_at,
            algorithm=claims.algorithm,
            kid=claims.kid,
            source_url=metadata.jwks_uri,
        )
        return CernWebClaimObservation(
            checked=checked,
            role_status=statuses[role.status],
            acr_claim=acr,
            amr_claim=amr,
            auth_time_claim=auth_time,
        )


def _format_claim_observation(value: CernWebClaimObservation) -> str:
    """Emit fixed categorical labels, not user identifiers or claim values."""
    allowed_roles = {"CLAIMED", "ABSENT", "MFA_REQUIRED", "LOA_REQUIRED", "MFA_AND_LOA_REQUIRED"}
    if (
        type(value) is not CernWebClaimObservation
        or value.role_status not in allowed_roles
        or value.acr_claim not in {"PRESENT", "ABSENT"}
        or value.amr_claim not in {"PRESENT", "ABSENT", "EMPTY"}
        or value.auth_time_claim not in {"PRESENT", "ABSENT"}
    ):
        raise ProbeError("Unexpected claim observation")
    return (
        "\nROLE_STATUS="
        + value.role_status
        + "\nACR_CLAIM="
        + value.acr_claim
        + "\nAMR_CLAIM="
        + value.amr_claim
        + "\nAUTH_TIME_CLAIM="
        + value.auth_time_claim
        + "\nMFA_PROOF=INDETERMINATE"
        + "\nLOA_PROOF=INDETERMINATE"
        + "\nAUTH_FRESHNESS=INDETERMINATE"
        + "\nROLE_AUTHORIZATION=DISABLED"
    )


def _generic_rejection() -> PlainTextResponse:
    result = PlainTextResponse(
        "CERN OIDC diagnostic rejected. No ASCA login or session was created.",
        status_code=400,
        headers=HEADERS,
    )
    result.headers["Set-Cookie"] = OidcBrowserCookie.clear_cookie_header()
    return result


def create_probe_app(
    client_id: str,
    client_secret: str,
    metadata: OidcProviderMetadata,
    *,
    token_exchange: object | None = None,
    token_verifier: object | None = None,
    observe_claims: bool = False,
) -> FastAPI:
    """Create an unmounted diagnostic. Injected adapters are ONLY for offline tests.

    The executable CLI never accepts injected adapters. Success is deliberately
    not represented as a verified application principal or a login capability.
    """
    if (
        not isinstance(client_id, str)
        or _CLIENT_ID.fullmatch(client_id) is None
        or client_id == "asca-glibotte-dev"
        or not isinstance(client_secret, str)
        or _SECRET.fullmatch(client_secret) is None
    ):
        raise ProbeError("Invalid web-only CERN client configuration")
    if type(observe_claims) is not bool or (observe_claims and client_id != "asca-web-dev"):
        raise ProbeError("Invalid web claim-observation configuration")
    metadata = _validate_metadata(metadata)
    config = OidcClientConfiguration(
        issuer=CERN_OIDC_ISSUER,
        authorization_endpoint=AUTH_ENDPOINT,
        client_id=client_id,
        redirect_uri=CALLBACK_URI,
        scopes=("openid",),
    )
    attempts = InMemoryAuthorizationAttemptStore(max_pending=64)
    auth = OidcAuthorizationService(config, attempts, ttl_seconds=ATTEMPT_TTL_SECONDS)
    verifier = (
        token_verifier
        if token_verifier is not None
        else (
            CernWebClaimObservationVerifier() if observe_claims else CernOidcVerificationPipeline()
        )
    )
    exchange = token_exchange if token_exchange is not None else exchange_confidential_code
    app = FastAPI(title="ASCA isolated CERN OIDC diagnostic", docs_url=None, redoc_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost"])

    @app.get("/")
    def landing(request: Request) -> Response:
        try:
            _assert_local_https(request)
        except ProbeError:
            return _generic_rejection()
        return HTMLResponse(
            "<h1>ASCA CERN web OIDC diagnostic (no login)</h1>"
            "<p>This is a local developer-only probe. No ASCA identity or permission "
            "will be granted.</p><a href='/probe/start'>Start CERN SSO diagnostic</a>",
            headers=HEADERS,
        )

    @app.get("/probe/status")
    def status(request: Request) -> Response:
        try:
            _assert_local_https(request)
        except ProbeError:
            return _generic_rejection()
        return JSONResponse(
            {
                "provider": "cern_pinned_issuer",
                "mode": "isolated_diagnostic_only",
                "client_type": "confidential",
                "asca_identity": "not_configured",
                "authorization": "disabled",
                "session": "disabled",
                "chatlas_access": "disabled",
            },
            headers=HEADERS,
        )

    @app.get("/probe/start")
    def start(request: Request) -> Response:
        try:
            _assert_local_https(request)
            started = auth.begin()
            response = RedirectResponse(started.authorization_url, status_code=303, headers=HEADERS)
            response.headers["Set-Cookie"] = OidcBrowserCookie(
                started.browser_binding, max_age_seconds=ATTEMPT_TTL_SECONDS
            ).set_cookie_header()
            return response
        except (ProbeError, ValueError, TypeError):
            return _generic_rejection()

    @app.get("/oidc/callback")
    def callback(request: Request) -> PlainTextResponse:
        try:
            _assert_local_https(request)
            values = _parse_callback(request)
            binding = _single_cookie(request)
            grant = auth.finish(
                browser_binding=binding,
                state=values["state"],
                code=values.get("code"),
                error=values.get("error"),
                response_issuer=values.get("iss"),
            )
            # Critical: state was atomically consumed before any outbound POST.
            raw = exchange(grant, client_id, client_secret)
            parsed = parse_unverified_oidc_token_response(UnverifiedOidcTokenHttpResponse(body=raw))
            checked = verifier.check(
                parsed,
                metadata,
                expected_client_id=client_id,
                expected_nonce=grant.nonce,
                now=int(time.time()),
            )
            observation = checked if observe_claims else None
            if observe_claims:
                if type(observation) is not CernWebClaimObservation:
                    raise ProbeError("Claim observation was rejected")
                checked = observation.checked
            if (
                not isinstance(checked, CheckedUntrustedCernOidcToken)
                or checked.issuer != CERN_OIDC_ISSUER
                or client_id not in checked.audiences
                or checked.expires_at <= int(time.time())
                or not checked.subject
            ):
                raise ProbeError("OIDC check was rejected")
        except Exception:
            # Never echo remote error details, URL codes, ID tokens, claims or exception text.
            return _generic_rejection()
        message = (
            "CERN OIDC token signature and claims checks completed. "
            "DIAGNOSTIC ONLY: no ASCA identity, session, role grant or access was created."
        )
        if observe_claims:
            message += _format_claim_observation(observation)
        response = PlainTextResponse(
            message,
            status_code=200,
            headers=HEADERS,
        )
        response.headers["Set-Cookie"] = OidcBrowserCookie.clear_cookie_header()
        return response

    return app


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--init-secret", action="store_true")
    mode.add_argument("--serve", action="store_true")
    parser.add_argument("--client-id", help="Client ID shown in the CERN SSO registration")
    parser.add_argument(
        "--observe-claims",
        action="store_true",
        help="Categorical role/assurance diagnostic only",
    )
    parser.add_argument("--certfile", type=Path)
    parser.add_argument("--keyfile", type=Path)
    args = parser.parse_args()
    try:
        if args.observe_claims and not args.serve:
            raise ProbeError("Claim observation only supported for --serve")
        if args.init_secret:
            provision_secret()
            return 0
        metadata = discover_cern_metadata()
        if args.preflight:
            del metadata
            print("DISCOVERY=PINNED_CERN_METADATA_VALID")
            print("ROLE_AUTHORIZATION=DISABLED")
            print("RESULT=WEB_PROBE_NOT_AUTHORIZED")
            return 0
        if not args.client_id or args.certfile is None or args.keyfile is None:
            raise ProbeError("Missing BFF development parameters")
        if not args.certfile.is_file() or not args.keyfile.is_file():
            raise ProbeError("Local development TLS files are unavailable")
        app = create_probe_app(
            args.client_id, _safe_secret_file(), metadata, observe_claims=args.observe_claims
        )
    except (ProbeError, OSError, ValueError, TypeError):
        print("RESULT=WEB_PROBE_NOT_READY")
        return 2
    print("MODE=ISOLATED_CERN_WEB_OIDC_DIAGNOSTIC")
    print("LISTEN=https://localhost:8443/")
    print("ASCA_LOGIN=DISABLED")
    print("ASCA_SESSION=DISABLED")
    print("ROLE_AUTHORIZATION=DISABLED")
    if args.observe_claims:
        print("CLAIM_OBSERVATION=ENABLED_NON_AUTHORITATIVE")
    # Never allow externally supplied proxy headers or access logs with auth codes.
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8443,
        ssl_certfile=str(args.certfile),
        ssl_keyfile=str(args.keyfile),
        proxy_headers=False,
        access_log=False,
        log_level="warning",
        workers=1,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
