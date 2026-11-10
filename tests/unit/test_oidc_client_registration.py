"""Offline registration data invariants; never contact CERN."""

import pytest

from asca.domain.oidc_registration import (
    OidcClientMode,
    OidcClientRegistration,
    OidcRegistrationError,
)


def test_native_loopback_and_minimal_scope() -> None:
    value = OidcClientRegistration(
        client_id="mock-client-123",
        redirect_uri="http://127.0.0.1:8765/api/v1/identity/callback",
        mode=OidcClientMode.NATIVE_LOOPBACK,
    )
    assert value.scopes == ("openid",)
    assert "mock-client-123" not in repr(value)


def test_ipv6_loopback_is_accepted() -> None:
    value = OidcClientRegistration(
        client_id="example",
        redirect_uri="http://[::1]:8765/callback",
        mode=OidcClientMode.NATIVE_LOOPBACK,
    )
    assert value.mode == OidcClientMode.NATIVE_LOOPBACK


def test_web_bff_requires_https_dns_callback() -> None:
    value = OidcClientRegistration(
        client_id="example",
        redirect_uri="https://asca.example.org/api/v1/identity/callback",
        mode=OidcClientMode.WEB_BFF,
        scopes=("openid", "profile"),
    )
    assert value.scopes == ("openid", "profile")


@pytest.mark.parametrize(
    ("url", "mode"),
    [
        ("http://localhost:8765/callback", OidcClientMode.NATIVE_LOOPBACK),
        ("http://192.0.2.1:8765/callback", OidcClientMode.NATIVE_LOOPBACK),
        ("http://127.0.0.1/callback", OidcClientMode.NATIVE_LOOPBACK),
        ("https://127.0.0.1:8765/callback", OidcClientMode.NATIVE_LOOPBACK),
        ("http://127.0.0.1:0/callback", OidcClientMode.NATIVE_LOOPBACK),
        ("http://127.0.0.1:bad/callback", OidcClientMode.NATIVE_LOOPBACK),
        ("http://127.0.0.1:8765/callback?", OidcClientMode.NATIVE_LOOPBACK),
        ("http://127.0.0.1:8765/callback#", OidcClientMode.NATIVE_LOOPBACK),
        ("http://127.0.0.1:8765/callback?code=abc", OidcClientMode.NATIVE_LOOPBACK),
        ("http://127.0.0.1:8765/callback#fragment", OidcClientMode.NATIVE_LOOPBACK),
        ("http://127.0.0.1:8765/%2Fcallback", OidcClientMode.NATIVE_LOOPBACK),
        ("http://127.0.0.1:8765/../callback", OidcClientMode.NATIVE_LOOPBACK),
        ("http://127.0.0.1:8765//callback", OidcClientMode.NATIVE_LOOPBACK),
        ("http://user:pass@127.0.0.1:8765/callback", OidcClientMode.NATIVE_LOOPBACK),
        ("http://127.0.0.1:8765/callback*", OidcClientMode.NATIVE_LOOPBACK),
        ("http://127.0.0.1:8765/callback\\evil", OidcClientMode.NATIVE_LOOPBACK),
        ("http://127.0.0.1:8765/callback\n", OidcClientMode.NATIVE_LOOPBACK),
        ("http://asca.example.org/callback", OidcClientMode.WEB_BFF),
        ("https://localhost/callback", OidcClientMode.WEB_BFF),
        ("https://127.0.0.1/callback", OidcClientMode.WEB_BFF),
        ("https://evil.example.org@asca.example.org/callback", OidcClientMode.WEB_BFF),
        ("https://asca.example.org:0/callback", OidcClientMode.WEB_BFF),
        ("https://asca.example.org", OidcClientMode.WEB_BFF),
        ("https://asca.example.org/callback?", OidcClientMode.WEB_BFF),
        ("https://asca.example.org/callback#", OidcClientMode.WEB_BFF),
        ("https://*.example.org/callback", OidcClientMode.WEB_BFF),
    ],
)
def test_unsafe_or_ambiguous_callback_rejected(url: str, mode: OidcClientMode) -> None:
    with pytest.raises(OidcRegistrationError):
        OidcClientRegistration(client_id="test", redirect_uri=url, mode=mode)


@pytest.mark.parametrize("client_id", ["", "has space", "abc\n", "../unsafe", "x" * 257, "abc/def"])
def test_invalid_client_ids_rejected(client_id: str) -> None:
    with pytest.raises(OidcRegistrationError, match="identifier"):
        OidcClientRegistration(
            client_id=client_id,
            redirect_uri="http://127.0.0.1:8765/callback",
            mode=OidcClientMode.NATIVE_LOOPBACK,
        )


@pytest.mark.parametrize(
    "scopes",
    [
        (),
        ("profile",),
        ("openid", "openid"),
        ("openid", "offline_access"),
        ("openid", "api"),
        ["openid"],
    ],
)
def test_scopes_are_restricted(scopes: object) -> None:
    with pytest.raises(OidcRegistrationError, match="scopes"):
        OidcClientRegistration(
            client_id="example",
            redirect_uri="http://127.0.0.1:8765/callback",
            mode=OidcClientMode.NATIVE_LOOPBACK,
            scopes=scopes,  # type: ignore[arg-type]
        )
