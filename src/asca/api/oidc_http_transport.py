"""Strict, unmounted HTTP transport primitives for future CERN OIDC BFF callbacks.

No route is installed by this module. Parsing a callback never exchanges a code,
validates an identity, creates a session, or sends an outbound request.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from starlette.requests import Request
from starlette.responses import PlainTextResponse

from asca.domain.oidc_browser_cookie import (
    OidcBrowserCookie,
    OidcBrowserCookieError,
    read_browser_binding_cookie,
)
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration

_MAX_QUERY_BYTES = 4096
_MAX_COOKIE_BYTES = 8192
_MAX_QUERY_FIELDS = 7
_MAX_AUTH_CODE_LENGTH = 2048
_MAX_ISSUER_LENGTH = 512
_STATE = re.compile(r"[A-Za-z0-9_-]{43,128}\Z", re.ASCII)
_ERROR = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z", re.ASCII)
_BAD_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
_ALLOWED_QUERY_FIELDS = frozenset(
    {"state", "code", "error", "iss", "session_state", "error_description", "error_uri"}
)


class OidcHttpTransportError(ValueError):
    """Fail-closed transport error with no callback, token, or cookie data."""


@dataclass(frozen=True, slots=True)
class UnverifiedOidcHttpCallback:
    """Sanitized transport envelope, not a verified identity or a login session.

    Each potentially sensitive field is excluded from dataclass representations.
    """

    state: str = field(repr=False)
    cookie_header: str = field(repr=False)
    code: str | None = field(default=None, repr=False)
    error: str | None = field(default=None, repr=False)
    response_issuer: str | None = field(default=None, repr=False)


def _single_header(request: Request, name: bytes, *, max_bytes: int) -> str:
    """Reject duplicate raw ASGI headers before any framework consolidation."""
    headers: object = request.scope.get("headers")
    if not isinstance(headers, list):
        raise OidcHttpTransportError("Invalid OIDC HTTP headers")
    values: list[bytes] = []
    for entry in headers:
        if not isinstance(entry, (tuple, list)) or len(entry) != 2:
            raise OidcHttpTransportError("Invalid OIDC HTTP headers")
        key, value = entry
        if not isinstance(key, bytes) or not isinstance(value, bytes):
            raise OidcHttpTransportError("Invalid OIDC HTTP headers")
        if key.lower() == name:
            values.append(value)
    if len(values) != 1 or not 0 < len(values[0]) <= max_bytes:
        raise OidcHttpTransportError("Missing or ambiguous OIDC HTTP header")
    try:
        decoded = values[0].decode("ascii")
    except UnicodeError:
        raise OidcHttpTransportError("Invalid OIDC HTTP header") from None
    if any(ord(c) < 32 or ord(c) >= 127 for c in decoded):
        raise OidcHttpTransportError("Invalid OIDC HTTP header")
    return decoded


def require_web_bff_https_origin(request: Request, registration: OidcClientRegistration) -> None:
    """Validate the direct ASGI TLS and Host origin, not spoofable forwarded headers.

    The deployed ASGI server/reverse proxy MUST enforce TLS and configure trusted
    proxy handling. This function deliberately does not trust X-Forwarded-Proto.
    """
    if registration.mode is not OidcClientMode.WEB_BFF:
        raise OidcHttpTransportError("OIDC web transport requires a BFF registration")
    expected = urlsplit(registration.redirect_uri)
    if request.scope.get("scheme") != "https":
        raise OidcHttpTransportError("OIDC web transport requires HTTPS")
    host = _single_header(request, b"host", max_bytes=256)
    if host.casefold() != expected.netloc.casefold():
        raise OidcHttpTransportError("OIDC HTTP host does not match registered callback")


def _strict_callback_query(raw: object) -> dict[str, str]:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= _MAX_QUERY_BYTES:
        raise OidcHttpTransportError("Invalid OIDC callback parameters")
    try:
        raw_text = raw.decode("ascii")
        if (
            _BAD_PERCENT.search(raw_text)
            or "#" in raw_text
            or any(ord(c) < 33 or ord(c) >= 127 for c in raw_text)
        ):
            raise ValueError("ambiguous encoding")
        pairs = parse_qsl(
            raw_text,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=_MAX_QUERY_FIELDS,
        )
    except (ValueError, UnicodeError):
        raise OidcHttpTransportError("Invalid OIDC callback parameters") from None
    params: dict[str, str] = {}
    for name, value in pairs:
        if name not in _ALLOWED_QUERY_FIELDS or name in params:
            raise OidcHttpTransportError("Ambiguous OIDC callback parameters")
        if len(value) > _MAX_QUERY_BYTES or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise OidcHttpTransportError("Invalid OIDC callback parameters")
        params[name] = value
    state = params.get("state", "")
    code = params.get("code")
    error = params.get("error")
    if not _STATE.fullmatch(state):
        raise OidcHttpTransportError("Invalid OIDC callback state")
    if (code is None) == (error is None):
        raise OidcHttpTransportError("OIDC callback must contain either code or error")
    if code is not None and (not 1 <= len(code) <= _MAX_AUTH_CODE_LENGTH or not code.strip()):
        raise OidcHttpTransportError("Invalid OIDC authorization response")
    if error is not None and not _ERROR.fullmatch(error):
        raise OidcHttpTransportError("Invalid OIDC error response")
    issuer = params.get("iss")
    if issuer is not None and (not issuer or len(issuer) > _MAX_ISSUER_LENGTH):
        raise OidcHttpTransportError("Invalid OIDC response issuer")
    return params


def parse_web_bff_callback(
    request: Request, registration: OidcClientRegistration
) -> UnverifiedOidcHttpCallback:
    """Parse one HTTPS top-level GET callback before server-side state checking.

    Callers MUST pass the result to finish_web_bff_callback for single-use state
    correlation, and later a cryptographic token verifier. It is never identity.
    """
    require_web_bff_https_origin(request, registration)
    if request.method != "GET":
        raise OidcHttpTransportError("OIDC callback requires GET")
    callback = urlsplit(registration.redirect_uri)
    raw_path = request.scope.get("raw_path")
    if not isinstance(raw_path, bytes) or raw_path != callback.path.encode("utf-8"):
        raise OidcHttpTransportError("OIDC callback path does not match registration")
    params = _strict_callback_query(request.scope.get("query_string"))
    cookie = _single_header(request, b"cookie", max_bytes=_MAX_COOKIE_BYTES)
    try:
        read_browser_binding_cookie(cookie)
    except OidcBrowserCookieError:
        raise OidcHttpTransportError("Invalid OIDC browser cookie") from None
    return UnverifiedOidcHttpCallback(
        state=params["state"],
        code=params.get("code"),
        error=params.get("error"),
        response_issuer=params.get("iss"),
        cookie_header=cookie,
    )


def unavailable_oidc_callback_response() -> PlainTextResponse:
    """Fail closed and clear any stale pre-authentication cookie.

    HTTP routes for real callbacks are intentionally not mounted. A future route
    must send this generic response on every pre-authentication rejection.
    """
    response = PlainTextResponse("CERN authentication is not available.", status_code=503)
    response.headers["Set-Cookie"] = OidcBrowserCookie.clear_cookie_header()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
