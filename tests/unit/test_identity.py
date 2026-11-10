"""Deterministic unit tests for the OIDC authorization preparation domain."""

from dataclasses import FrozenInstanceError
from urllib.parse import parse_qs, urlsplit

import pytest

from asca.application.identity import (
    OidcAuthorizationService,
    OidcClientConfiguration,
    pkce_s256_challenge,
)
from asca.domain.identity import PendingAuthorization, VerifiedIdentity
from asca.infrastructure.identity_memory import InMemoryAuthorizationAttemptStore


@pytest.fixture
def configuration() -> OidcClientConfiguration:
    return OidcClientConfiguration(
        issuer="https://auth.example.invalid/realms/test",
        authorization_endpoint=(
            "https://auth.example.invalid/realms/test/protocol/openid-connect/auth"
        ),
        client_id="asca-local-test",
        redirect_uri="http://127.0.0.1:8000/oidc/callback",
    )


def test_rfc7636_pkce_s256_known_vector() -> None:
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert pkce_s256_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


@pytest.mark.parametrize("verifier", ["", "a" * 42, "b" * 129, "x/y" + "a" * 41, " é " * 20])
def test_reject_invalid_pkce_verifier(verifier: str) -> None:
    with pytest.raises(ValueError, match="PKCE"):
        pkce_s256_challenge(verifier)


@pytest.mark.parametrize(
    "value",
    [
        "http://auth.example.invalid/realm",
        "https://user:pass@auth.example.invalid/realm",
        "https://auth.example.invalid/realm?leak=1",
        "https://auth.example.invalid/realm#bad",
        "https://auth.example.invalid:bad/realm",
        " https://auth.example.invalid/realm",
        "https://[bad/realm",
    ],
)
def test_insecure_oidc_issuer_is_rejected(value: str) -> None:
    with pytest.raises(ValueError, match="secure HTTPS"):
        OidcClientConfiguration(
            issuer=value,
            authorization_endpoint="https://auth.example.invalid/authorize",
            client_id="asca",
            redirect_uri="http://localhost:8000/callback",
        )


@pytest.mark.parametrize(
    "value",
    [
        "http://evil.example.invalid/callback",
        "http://127.0.0.2:8000/callback",
        "http://localhost/callback",
        "http://user@127.0.0.1:8000/callback",
        "http://127.0.0.1:8000/callback?x=1",
        "https://example.invalid/callback#fragment",
        "javascript:alert(1)",
    ],
)
def test_unsafe_redirect_is_rejected(value: str) -> None:
    with pytest.raises(ValueError, match="Redirect URI"):
        OidcClientConfiguration(
            issuer="https://auth.example.invalid/realm",
            authorization_endpoint="https://auth.example.invalid/authorize",
            client_id="asca",
            redirect_uri=value,
        )


def test_https_hosted_redirect_is_allowed() -> None:
    config = OidcClientConfiguration(
        issuer="https://auth.example.invalid/realm",
        authorization_endpoint="https://auth.example.invalid/authorize",
        client_id="asca",
        redirect_uri="https://asca.example.invalid/oidc/callback",
    )
    assert config.redirect_uri.startswith("https://")


@pytest.mark.parametrize(
    "scopes", [(), ("profile",), ("openid", "openid"), ("openid", "profile read")]
)
def test_scopes_are_validated(scopes: tuple[str, ...]) -> None:
    with pytest.raises(ValueError, match="scopes"):
        OidcClientConfiguration(
            issuer="https://auth.example.invalid/realm",
            authorization_endpoint="https://auth.example.invalid/authorize",
            client_id="asca",
            redirect_uri="https://asca.example.invalid/callback",
            scopes=scopes,
        )


@pytest.mark.parametrize("client_id", ["", "   ", "contains space", "with\nnewline"])
def test_client_id_is_validated(client_id: str) -> None:
    with pytest.raises(ValueError, match="client_id"):
        OidcClientConfiguration(
            issuer="https://auth.example.invalid/realm",
            authorization_endpoint="https://auth.example.invalid/authorize",
            client_id=client_id,
            redirect_uri="https://asca.example.invalid/callback",
        )


def test_begin_creates_distinct_secret_values_and_correct_url(
    configuration: OidcClientConfiguration,
) -> None:
    store = InMemoryAuthorizationAttemptStore()
    service = OidcAuthorizationService(configuration, store, clock=lambda: 100.0)
    first, second = service.begin(), service.begin()
    first_parts = urlsplit(first.authorization_url)
    params = parse_qs(first_parts.query)
    assert first_parts.scheme == "https"
    assert params["response_type"] == ["code"]
    assert params["client_id"] == [configuration.client_id]
    assert params["redirect_uri"] == [configuration.redirect_uri]
    assert params["scope"] == ["openid profile"]
    assert params["code_challenge_method"] == ["S256"]
    assert len(params["state"][0]) >= 40
    assert len(params["nonce"][0]) >= 40
    assert len(params["code_challenge"][0]) == 43
    assert "code_verifier" not in params
    assert first.browser_binding != second.browser_binding
    assert params["state"][0] != parse_qs(urlsplit(second.authorization_url).query)["state"][0]
    assert "browser_binding" not in first.authorization_url
    assert first.browser_binding not in first.authorization_url
    assert "state=" not in repr(first)
    assert "browser_binding" not in repr(first)


def test_success_returns_unverified_grant_not_identity(
    configuration: OidcClientConfiguration,
) -> None:
    service = OidcAuthorizationService(
        configuration, InMemoryAuthorizationAttemptStore(), clock=lambda: 100.0
    )
    start = service.begin()
    params = parse_qs(urlsplit(start.authorization_url).query)
    grant = service.finish(
        browser_binding=start.browser_binding,
        state=params["state"][0],
        code="test-only-unverified-code",
        response_issuer=configuration.issuer,
    )
    assert grant.code == "test-only-unverified-code"
    assert grant.redirect_uri == configuration.redirect_uri
    assert pkce_s256_challenge(grant.code_verifier) == params["code_challenge"][0]
    assert grant.nonce == params["nonce"][0]
    assert not isinstance(grant, VerifiedIdentity)
    assert "test-only-unverified-code" not in repr(grant)
    assert grant.code_verifier not in repr(grant)
    with pytest.raises(FrozenInstanceError):
        grant.code = "changed"  # type: ignore[misc]


def test_attempt_ttl_validated(configuration: OidcClientConfiguration) -> None:
    with pytest.raises(ValueError, match="TTL"):
        OidcAuthorizationService(configuration, InMemoryAuthorizationAttemptStore(), ttl_seconds=10)


def test_attempts_are_immutable() -> None:
    attempt = PendingAuthorization("binding", "state", "nonce", "verifier", 0, 60)
    with pytest.raises(FrozenInstanceError):
        attempt.state = "bad"  # type: ignore[misc]


def test_verified_identity_requires_nonblank_identifiers() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        VerifiedIdentity("https://issuer", "", "client")
