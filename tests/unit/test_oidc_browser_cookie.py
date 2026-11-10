"""No-network unit tests for HTTPS BFF OIDC attempt-cookie policy."""

import secrets
from dataclasses import FrozenInstanceError

import pytest

from asca.domain.oidc_browser_cookie import (
    COOKIE_NAME,
    OidcBrowserCookie,
    OidcBrowserCookieError,
    read_browser_binding_cookie,
    validate_browser_binding,
)


@pytest.fixture
def binding() -> str:
    return secrets.token_urlsafe(32)


def test_cookie_attributes_are_host_bound_secure_and_http_only(binding: str) -> None:
    cookie = OidcBrowserCookie(binding)
    header = cookie.set_cookie_header()
    assert header.startswith(f"{COOKIE_NAME}={binding};")
    assert "Max-Age=300" in header
    assert "Path=/" in header
    assert "Secure" in header
    assert "HttpOnly" in header
    assert "SameSite=Lax" in header
    assert "Domain=" not in header
    assert "SameSite=None" not in header
    assert "Expires=" not in header
    assert binding not in repr(cookie)


def test_cookie_clear_header_is_host_bound(binding: str) -> None:
    header = OidcBrowserCookie(binding).clear_cookie_header()
    assert header == (f"{COOKIE_NAME}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert binding not in header


def test_cookie_round_trip_ignores_unrelated_values(binding: str) -> None:
    assert read_browser_binding_cookie(f"other=123; {COOKIE_NAME}={binding}; test=x=y") == binding
    assert validate_browser_binding(binding) == binding


def test_cookie_is_immutable(binding: str) -> None:
    cookie = OidcBrowserCookie(binding)
    with pytest.raises(FrozenInstanceError):
        cookie.binding = "other"  # type: ignore[misc]


@pytest.mark.parametrize("lifetime", [0, 29, 901, -1, True, 300.5, "300"])
def test_cookie_lifetime_is_bounded(lifetime: object, binding: str) -> None:
    with pytest.raises(OidcBrowserCookieError, match="lifetime"):
        OidcBrowserCookie(binding, max_age_seconds=lifetime)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "short",
        "a" * 42,
        "x" * 129,
        "a" * 42 + ";",
        "a" * 42 + "=",
        "a" * 42 + "\n",
        "é" * 43,
    ],
)
def test_bad_binding_is_rejected_without_echo(value: object) -> None:
    with pytest.raises(OidcBrowserCookieError) as caught:
        validate_browser_binding(value)
    assert "a" * 42 not in str(caught.value)
