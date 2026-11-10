"""Adversarial ASGI-level OIDC HTTP parsing tests with no provider connection."""

from dataclasses import FrozenInstanceError
from urllib.parse import urlencode

import pytest
from starlette.requests import Request

from asca.api.oidc_http_transport import (
    OidcHttpTransportError,
    parse_web_bff_callback,
    require_web_bff_https_origin,
    unavailable_oidc_callback_response,
)
from asca.domain.oidc_browser_cookie import COOKIE_NAME
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration

STATE = "S" * 43
BINDING = "B" * 43
HOST = "asca.example.org"
PATH = "/api/v1/identity/callback"


def registration() -> OidcClientRegistration:
    return OidcClientRegistration(
        client_id="example-not-registered",
        redirect_uri=f"https://{HOST}{PATH}",
        mode=OidcClientMode.WEB_BFF,
    )


def request(
    *,
    scheme: str = "https",
    host: bytes = b"asca.example.org",
    path: str = PATH,
    raw_path: bytes | None = PATH.encode("ascii"),
    query: bytes | None = None,
    method: str = "GET",
    cookie: bytes = f"{COOKIE_NAME}={BINDING}".encode("ascii"),
    extra_headers: tuple[tuple[bytes, bytes], ...] = (),
) -> Request:
    headers = [(b"host", host), (b"cookie", cookie), *extra_headers]
    scope: dict[str, object] = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "scheme": scheme,
        "path": path,
        "query_string": (
            query
            if query is not None
            else urlencode({"state": STATE, "code": "mock-code"}).encode("ascii")
        ),
        "headers": headers,
        "server": ("asca.example.org", 443),
        "client": ("192.0.2.1", 12345),
    }
    if raw_path is not None:
        scope["raw_path"] = raw_path
    return Request(scope)


def test_valid_code_callback_is_unverified_and_redacted() -> None:
    callback = parse_web_bff_callback(request(), registration())
    assert callback.state == STATE
    assert callback.code == "mock-code"
    assert callback.cookie_header == f"{COOKIE_NAME}={BINDING}"
    assert callback.error is None
    assert callback.response_issuer is None
    assert callback.state not in repr(callback)
    assert callback.code not in repr(callback)
    assert callback.cookie_header not in repr(callback)
    assert not hasattr(callback, "authenticated_identity")
    assert not hasattr(callback, "access_token")
    with pytest.raises(FrozenInstanceError):
        callback.code = "changed"  # type: ignore[misc]


def test_provider_error_and_optional_issuer_are_parsed_without_echo() -> None:
    query = urlencode(
        {
            "state": STATE,
            "error": "access_denied",
            "iss": "https://auth.cern.ch/auth/realms/cern",
            "error_description": "The request was denied",
            "session_state": "harmless",
        }
    ).encode("ascii")
    callback = parse_web_bff_callback(request(query=query), registration())
    assert callback.code is None
    assert callback.error == "access_denied"
    assert callback.response_issuer == "https://auth.cern.ch/auth/realms/cern"
    assert "access_denied" not in repr(callback)
    assert "auth.cern.ch" not in repr(callback)


@pytest.mark.parametrize("scheme", ["http", "", "ws", "HTTPS"])
def test_non_https_asgi_schemes_rejected(scheme: str) -> None:
    with pytest.raises(OidcHttpTransportError, match="HTTPS"):
        parse_web_bff_callback(request(scheme=scheme), registration())


def test_spoofed_forwarded_https_cannot_override_insecure_asgi_scheme() -> None:
    with pytest.raises(OidcHttpTransportError, match="HTTPS"):
        parse_web_bff_callback(
            request(scheme="http", extra_headers=((b"x-forwarded-proto", b"https"),)),
            registration(),
        )


@pytest.mark.parametrize(
    "host",
    [
        b"evil.example.org",
        b"asca.example.org:8443",
        b"asca.example.org ",
        b"a@asca.example.org",
        b"",
        b"asc\xffa.example.org",
    ],
)
def test_wrong_or_ambiguous_host_rejected(host: bytes) -> None:
    with pytest.raises(OidcHttpTransportError):
        parse_web_bff_callback(request(host=host), registration())


def test_case_insensitive_host_is_allowed() -> None:
    require_web_bff_https_origin(request(host=b"ASCA.EXAMPLE.ORG"), registration())


def test_duplicate_host_rejected_even_if_identical() -> None:
    with pytest.raises(OidcHttpTransportError):
        parse_web_bff_callback(
            request(extra_headers=((b"HOST", b"asca.example.org"),)), registration()
        )


def test_duplicate_cookie_header_rejected_even_if_unrelated() -> None:
    with pytest.raises(OidcHttpTransportError):
        parse_web_bff_callback(
            request(extra_headers=((b"COOKIE", b"other=value"),)), registration()
        )


@pytest.mark.parametrize("method", ["POST", "PUT", "HEAD", "DELETE"])
def test_non_get_callbacks_rejected(method: str) -> None:
    with pytest.raises(OidcHttpTransportError, match="GET"):
        parse_web_bff_callback(request(method=method), registration())


@pytest.mark.parametrize(
    "path,raw_path",
    [
        ("/callback", b"/callback"),
        (PATH, b"/api/v1/identity/%63allback"),
        (PATH, b"/api/v1/identity/callback/"),
        (PATH, b"/api/v1/identity//callback"),
        (PATH, None),
    ],
)
def test_callback_raw_path_must_match_exact_registration(path: str, raw_path: bytes | None) -> None:
    with pytest.raises(OidcHttpTransportError, match="path"):
        parse_web_bff_callback(request(path=path, raw_path=raw_path), registration())


def test_native_registration_never_uses_web_callback_policy() -> None:
    native = OidcClientRegistration(
        client_id="example",
        redirect_uri="http://127.0.0.1:8765/callback",
        mode=OidcClientMode.NATIVE_LOOPBACK,
    )
    with pytest.raises(OidcHttpTransportError, match="BFF"):
        parse_web_bff_callback(request(), native)


@pytest.mark.parametrize(
    "cookie",
    [
        b"",
        b"other=abc",
        f"{COOKIE_NAME}=short".encode("ascii"),
        f"{COOKIE_NAME}={BINDING}; {COOKIE_NAME}={BINDING}".encode("ascii"),
        f"{COOKIE_NAME}={BINDING}\x00".encode("ascii"),
        f"{COOKIE_NAME}={BINDING}\r\nspoof=value".encode("ascii"),
        b"x" * 8193,
    ],
)
def test_bad_cookie_header_rejected(cookie: bytes) -> None:
    with pytest.raises(OidcHttpTransportError, match=r"cookie|header"):
        parse_web_bff_callback(request(cookie=cookie), registration())


@pytest.mark.parametrize(
    "query",
    [
        b"",
        f"state={STATE}".encode("ascii"),
        f"state={STATE}&code=mock&error=access_denied".encode("ascii"),
        f"state={STATE}&code=mock&state={STATE}".encode("ascii"),
        f"state={STATE}&code=mock&code=duplicate".encode("ascii"),
        f"state={STATE}&code=".encode("ascii"),
        b"state=bad&code=mock",
        f"state={STATE}&error=bad%00value".encode("ascii"),
        f"state={STATE}&error=wrong%20value".encode("ascii"),
        f"state={STATE}&code=abc&unknown=1".encode("ascii"),
        f"state={STATE}&code=%ZZ".encode("ascii"),
        f"state={STATE}&code=%FF".encode("ascii"),
        f"state={STATE}&code=abc#fragment".encode("ascii"),
        f"state={STATE}&code=abc&broken".encode("ascii"),
        f"state={STATE}&code=abc&iss=".encode("ascii"),
        f"state={STATE}&code=abc&iss={'x' * 513}".encode("ascii"),
        f"state={STATE}&code={'A' * 2049}".encode("ascii"),
        f"state={STATE}&code=abc".encode("ascii") + b"&a=1" * 9,
        b"x" * 4097,
    ],
)
def test_invalid_or_ambiguous_callback_parameters_rejected(query: bytes) -> None:
    with pytest.raises(OidcHttpTransportError):
        parse_web_bff_callback(request(query=query), registration())


def test_callback_errors_are_sanitized() -> None:
    secret = "CERN-secret-do-not-log"
    with pytest.raises(OidcHttpTransportError) as exc:
        parse_web_bff_callback(
            request(query=f"state={STATE}&code={secret}&other=bad".encode("ascii")),
            registration(),
        )
    assert secret not in str(exc.value)
    assert secret not in repr(exc.value)


def test_unavailable_response_clears_cookie_and_does_not_authenticate() -> None:
    response = unavailable_oidc_callback_response()
    assert response.status_code == 503
    assert response.headers["set-cookie"] == (
        f"{COOKIE_NAME}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax"
    )
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "cookie" not in response.body.decode("utf-8").lower()
    assert STATE not in response.body.decode("utf-8")
