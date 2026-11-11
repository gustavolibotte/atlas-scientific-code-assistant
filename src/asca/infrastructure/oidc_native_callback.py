"""Unmounted, fail-closed HTTP parsing policy for native OIDC loopback callbacks.

No socket is opened, no request is received and no authorization attempt is
consumed here. The future listener must populate socket peer/local information
from OS APIs, not HTTP/query fields, and must separately bind the request to a
pending native authorization transaction. A syntactically accepted callback is
never evidence of CERN identity or trustworthy browser origin.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, urlsplit

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.oidc_native_callback import (
    NativeLoopbackHttpRequest,
    OidcNativeCallbackError,
    ParsedUntrustedNativeCallback,
)
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration

_STATE = re.compile(r"[A-Za-z0-9_-]{43,128}\Z", re.ASCII)
_CODE = re.compile(r"[\x21-\x7E]{1,2048}\Z", re.ASCII)
_ERROR = re.compile(r"[A-Za-z0-9._~-]{1,128}\Z", re.ASCII)
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}\Z", re.ASCII)
_HEX = frozenset("0123456789abcdefABCDEF")
_FORBIDDEN_HEADERS = frozenset(
    {
        "origin",
        "forwarded",
        "proxy-authorization",
        "proxy-connection",
        "transfer-encoding",
        "authorization",
        "cookie",
        "content-length",
        "content-type",
        "expect",
        "upgrade",
    }
)
_ALLOWED_QUERY = frozenset({"state", "code", "error", "iss"})


def _ip_literal(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse only a canonical, non-scoped literal with no implicit conversions."""
    if not isinstance(value, str) or not value or "\x00" in value or "%" in value:
        raise OidcNativeCallbackError("Invalid native callback socket address")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        raise OidcNativeCallbackError("Invalid native callback socket address") from None
    if str(parsed) != value or parsed not in (
        ipaddress.ip_address("127.0.0.1"),
        ipaddress.ip_address("::1"),
    ):
        raise OidcNativeCallbackError("Invalid native callback socket address")
    return parsed


def _parse_query(raw: str) -> ParsedUntrustedNativeCallback:
    """Accept one strictly encoded code/error and one state; reject ambiguity."""
    if (
        not raw
        or len(raw) > 4096
        or any(ord(ch) < 33 or ord(ch) > 126 or ch in "#\\;?" for ch in raw)
    ):
        raise OidcNativeCallbackError("Invalid native callback query")
    for index, char in enumerate(raw):
        if char == "%" and (
            index + 2 >= len(raw) or any(x not in _HEX for x in raw[index + 1 : index + 3])
        ):
            raise OidcNativeCallbackError("Invalid native callback query")
    try:
        pairs = parse_qsl(
            raw,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=3,
            encoding="ascii",
            errors="strict",
        )
    except (ValueError, UnicodeError):
        raise OidcNativeCallbackError("Invalid native callback query") from None
    params = dict(pairs)
    if len(pairs) != len(params) or set(params) - _ALLOWED_QUERY or "state" not in params:
        raise OidcNativeCallbackError("Invalid native callback parameters")
    state = params["state"]
    code = params.get("code")
    error = params.get("error")
    response_issuer = params.get("iss")
    if (
        _STATE.fullmatch(state) is None
        or (code is None) == (error is None)
        or (code is not None and _CODE.fullmatch(code) is None)
        or (error is not None and _ERROR.fullmatch(error) is None)
        or (response_issuer is not None and response_issuer != CERN_OIDC_ISSUER)
    ):
        raise OidcNativeCallbackError("Invalid native callback parameters")
    return ParsedUntrustedNativeCallback(
        state=state, code=code, error=error, response_issuer=response_issuer
    )


class CernNativeLoopbackCallbackPolicy:
    """Check a future listener's untrusted HTTP envelope against one native URI.

    No actual sockets are opened. Host/peer address checks prevent some
    misrouting, not malicious requests from other processes on the same host.
    """

    def __init__(self, registration: OidcClientRegistration) -> None:
        if (
            type(registration) is not OidcClientRegistration
            or registration.mode is not OidcClientMode.NATIVE_LOOPBACK
        ):
            raise OidcNativeCallbackError("Invalid native callback registration")
        try:
            validated = OidcClientRegistration(
                client_id=registration.client_id,
                redirect_uri=registration.redirect_uri,
                mode=registration.mode,
                scopes=registration.scopes,
            )
            uri = urlsplit(validated.redirect_uri)
            host = uri.hostname
            port = uri.port
            if host not in ("127.0.0.1", "::1") or port is None or not uri.path:
                raise OidcNativeCallbackError("Unsupported native callback address")
        except (ValueError, TypeError, AttributeError):
            raise OidcNativeCallbackError("Invalid native callback registration") from None
        self._host = host
        self._port = port
        self._path = uri.path
        self._authority = f"[{host}]:{port}" if host == "::1" else f"{host}:{port}"

    def parse(self, request: NativeLoopbackHttpRequest) -> ParsedUntrustedNativeCallback:
        """Check HTTP request shape; never consume state or authenticate identity."""
        if (
            type(request) is not NativeLoopbackHttpRequest
            or request.method != "GET"
            or request.http_version != "HTTP/1.1"
            or not isinstance(request.request_target, str)
            or len(request.request_target) > 8192
            or not isinstance(request.headers, tuple)
            or not 1 <= len(request.headers) <= 32
            or not isinstance(request.body, bytes)
            or request.body
            or not isinstance(request.local_port, int)
            or isinstance(request.local_port, bool)
            or request.local_port != self._port
        ):
            raise OidcNativeCallbackError("Invalid native callback HTTP request")
        if (
            _ip_literal(request.local_ip) != _ip_literal(request.peer_ip)
            or request.local_ip != self._host
        ):
            raise OidcNativeCallbackError("Invalid native callback socket binding")
        hosts: list[str] = []
        for header in request.headers:
            if not isinstance(header, tuple) or len(header) != 2:
                raise OidcNativeCallbackError("Invalid native callback HTTP headers")
            name, value = header
            if (
                not isinstance(name, str)
                or _HEADER_NAME.fullmatch(name) is None
                or not isinstance(value, str)
                or len(value) > 2048
                or any(ord(ch) < 32 or ord(ch) > 126 for ch in value)
            ):
                raise OidcNativeCallbackError("Invalid native callback HTTP headers")
            lowered = name.lower()
            if lowered in _FORBIDDEN_HEADERS or lowered.startswith(
                ("x-forwarded-", "x-original-", "proxy-")
            ):
                raise OidcNativeCallbackError("Forbidden native callback HTTP header")
            if lowered == "host":
                hosts.append(value)
        if hosts != [self._authority]:
            raise OidcNativeCallbackError("Invalid native callback Host header")
        path, separator, raw_query = request.request_target.partition("?")
        if path != self._path or not separator:
            raise OidcNativeCallbackError("Invalid native callback request target")
        return _parse_query(raw_query)
