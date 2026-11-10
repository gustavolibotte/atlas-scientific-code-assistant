"""Constrained HTTPS adapter for native OIDC token requests, not a login path.

Nothing in the production ASCA application invokes this adapter. It is tested
with injected in-memory openers; no real CERN authorization is performed.
"""

from __future__ import annotations

import math
import re
import ssl
from http.client import HTTPException
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    OpenerDirector,
    ProxyHandler,
    Request,
    build_opener,
)

from asca.application.identity import pkce_s256_challenge
from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.domain.oidc_token_http import OidcTokenHttpError, UnverifiedOidcTokenHttpResponse
from asca.domain.oidc_token_request import UnsentOidcTokenRequest

# A future provider-configuration change must be reviewed, not inferred from
# arbitrary user-supplied metadata or callback parameters.
CERN_OIDC_TOKEN_ENDPOINT = CERN_OIDC_ISSUER + "/protocol/openid-connect/token"
_MAX_RESPONSE_BYTES = 65_536
_MAX_REQUEST_BYTES = 4_096
_EXPECTED_FIELDS = frozenset({"grant_type", "code", "redirect_uri", "client_id", "code_verifier"})
_BAD_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")


class _RejectRedirects(HTTPRedirectHandler):
    """Prohibit forwarding authorization codes and verifiers on any redirect."""

    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        return None


def _validate_unsent_request(
    prepared: UnsentOidcTokenRequest, registration: OidcClientRegistration
) -> None:
    """Do not send an arbitrary form, even if wrapped in a domain dataclass."""
    if (
        not isinstance(prepared, UnsentOidcTokenRequest)
        or not isinstance(registration, OidcClientRegistration)
        or registration.mode is not OidcClientMode.NATIVE_LOOPBACK
        or prepared.token_endpoint != CERN_OIDC_TOKEN_ENDPOINT
        or not isinstance(prepared.form_body, bytes)
        or not 0 < len(prepared.form_body) <= _MAX_REQUEST_BYTES
        or not isinstance(prepared.expected_nonce, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", prepared.expected_nonce)
    ):
        raise OidcTokenHttpError("OIDC native token HTTP request is not approved")

    try:
        raw = prepared.form_body.decode("ascii")
        if _BAD_PERCENT.search(raw) or any(ord(c) < 33 or ord(c) >= 127 for c in raw):
            raise ValueError("invalid encoding")
        pairs = parse_qsl(
            raw,
            strict_parsing=True,
            keep_blank_values=True,
            max_num_fields=5,
            encoding="ascii",
            errors="strict",
        )
        params = dict(pairs)
        if len(pairs) != 5 or len(params) != 5 or set(params) != _EXPECTED_FIELDS:
            raise ValueError("unexpected form members")
        if (
            params["grant_type"] != "authorization_code"
            or params["redirect_uri"] != registration.redirect_uri
            or params["client_id"] != registration.client_id
            or not 1 <= len(params["code"]) <= 2048
            or not params["code"].strip()
            or any(not 32 <= ord(c) <= 126 for c in params["code"])
        ):
            raise ValueError("invalid code exchange fields")
        pkce_s256_challenge(params["code_verifier"])
    except (ValueError, TypeError, UnicodeError):
        raise OidcTokenHttpError("OIDC native token HTTP request is not approved") from None


def _single_response_header(headers: Any, name: str, *, required: bool) -> str | None:
    """Reject duplicate response headers and malformed non-ASCII values."""
    try:
        values = headers.get_all(name, [])
    except (AttributeError, TypeError, ValueError):
        raise OidcTokenHttpError("Invalid OIDC token HTTP response headers") from None
    if (
        not isinstance(values, list)
        or len(values) > 1
        or (required and len(values) != 1)
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > 256
            or any(ord(ch) < 32 or ord(ch) >= 127 for ch in item)
            for item in values
        )
    ):
        raise OidcTokenHttpError("Invalid OIDC token HTTP response headers")
    return str(values[0]) if values else None


def _validate_response_headers(headers: Any) -> int | None:
    content_type = _single_response_header(headers, "Content-Type", required=True)
    if content_type is None or content_type.lower().strip() not in (
        "application/json",
        "application/json; charset=utf-8",
    ):
        raise OidcTokenHttpError("Invalid OIDC token HTTP content type")
    content_encoding = _single_response_header(headers, "Content-Encoding", required=False)
    if content_encoding is not None and content_encoding.lower().strip() != "identity":
        raise OidcTokenHttpError("Encoded OIDC token HTTP responses are not allowed")
    content_length = _single_response_header(headers, "Content-Length", required=False)
    if content_length is not None and (
        not content_length.isascii()
        or len(content_length) > 10
        or not content_length.isdecimal()
        or not 0 < int(content_length) <= _MAX_RESPONSE_BYTES
    ):
        raise OidcTokenHttpError("Invalid OIDC token HTTP content length")

    return int(content_length) if content_length is not None else None


class HttpsOidcTokenTransport:
    """Single approved CERN token endpoint, TLS verification and no redirects.

    Injecting an opener is intended only for deterministic tests. The standard
    opener disables environment proxies, verifies TLS, and blocks all redirects.
    Neither this class nor any token callback is mounted in the ASCA API.
    """

    def __init__(
        self,
        *,
        timeout_seconds: float = 5.0,
        opener: OpenerDirector | None = None,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0.1 <= timeout_seconds <= 15.0
        ):
            raise ValueError("Token HTTP timeout must be between 0.1 and 15 seconds")
        self._timeout = float(timeout_seconds)
        self._opener = opener or build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=ssl.create_default_context()),
            _RejectRedirects(),
        )

    def exchange(
        self,
        prepared: UnsentOidcTokenRequest,
        registration: OidcClientRegistration,
    ) -> UnverifiedOidcTokenHttpResponse:
        """Send one validated POST; return only *unverified* opaque response bytes.

        The caller must first use trusted CERN discovery and the approved
        token-request builder. This method does not verify provider registration
        or allow any response data to become an authenticated identity.
        """
        _validate_unsent_request(prepared, registration)
        request = Request(
            CERN_OIDC_TOKEN_ENDPOINT,
            data=prepared.form_body,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Cache-Control": "no-store",
                "User-Agent": "ASCA-OIDC-token/1.0",
            },
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                if response.status != 200:
                    raise OidcTokenHttpError("OIDC token HTTP response was rejected")
                declared_length = _validate_response_headers(response.headers)
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_RESPONSE_BYTES:
                    raise OidcTokenHttpError("OIDC token HTTP response was rejected")
                if declared_length is not None and len(raw) != declared_length:
                    raise OidcTokenHttpError("OIDC token HTTP response was rejected")
                return UnverifiedOidcTokenHttpResponse(body=raw)
        except OidcTokenHttpError:
            raise
        except (HTTPError, URLError, HTTPException, TimeoutError, OSError, ValueError, TypeError):
            raise OidcTokenHttpError("OIDC token HTTPS exchange failed") from None
