"""Security expectations for CERN client preflight without token operations."""

from dataclasses import replace

import pytest

from asca.application.oidc_client_preflight import build_cern_client_configuration
from asca.application.oidc_discovery import CERN_OIDC_ISSUER, OidcDiscoveryPolicy
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_registration import (
    OidcClientMode,
    OidcClientRegistration,
    OidcRegistrationError,
)


def provider() -> OidcProviderMetadata:
    return OidcProviderMetadata(
        issuer=CERN_OIDC_ISSUER,
        authorization_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        token_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        jwks_uri=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        approved_id_token_algorithms=("ES256", "RS256"),
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )


def registration() -> OidcClientRegistration:
    return OidcClientRegistration(
        client_id="example-not-registered",
        redirect_uri="http://127.0.0.1:8765/api/v1/identity/callback",
        mode=OidcClientMode.NATIVE_LOOPBACK,
    )


def test_preflight_constructs_existing_unverified_client_contract() -> None:
    result = build_cern_client_configuration(registration(), provider())
    assert result.issuer == CERN_OIDC_ISSUER
    assert result.client_id == "example-not-registered"
    assert result.scopes == ("openid",)
    assert result.redirect_uri.endswith("/api/v1/identity/callback")


@pytest.mark.parametrize(
    "bad_provider",
    [
        replace(provider(), issuer="https://other.example.invalid"),
        replace(provider(), supports_authorization_code=False),
        replace(provider(), supports_pkce_s256=False),
        replace(provider(), approved_id_token_algorithms=("none", "HS256")),
        replace(provider(), approved_id_token_algorithms=("ES256", "HS256")),
        replace(provider(), authorization_endpoint=CERN_OIDC_ISSUER + "/auth?"),
        replace(provider(), authorization_endpoint="https://evil.invalid/auth"),
        replace(provider(), authorization_endpoint="http://auth.cern.ch/auth"),
        replace(provider(), authorization_endpoint=CERN_OIDC_ISSUER + "/auth?redirect=evil"),
        replace(provider(), authorization_endpoint="https://user:pass@auth.cern.ch/auth"),
        replace(provider(), authorization_endpoint="https://auth.cern.ch:0/auth"),
        replace(provider(), authorization_endpoint="https://auth.cern.ch/auth\nevil"),
        replace(provider(), token_endpoint="https://evil.invalid/token"),
        replace(provider(), jwks_uri=CERN_OIDC_ISSUER + "/certs#"),
        replace(provider(), jwks_uri="http://auth.cern.ch/certs"),
    ],
)
def test_untrusted_metadata_cannot_set_client_endpoint(
    bad_provider: OidcProviderMetadata,
) -> None:
    with pytest.raises(OidcRegistrationError):
        build_cern_client_configuration(registration(), bad_provider)


def test_policy_cannot_switch_to_a_different_issuer() -> None:
    with pytest.raises(OidcRegistrationError, match="trust anchor"):
        build_cern_client_configuration(
            registration(),
            provider(),
            policy=OidcDiscoveryPolicy(
                expected_issuer="https://other.example.invalid/issuer",
                discovery_url=(
                    "https://other.example.invalid/issuer/.well-known/openid-configuration"
                ),
            ),
        )


def test_preflight_uses_no_network_and_no_browser_login() -> None:
    """Only a pure object-to-object configuration operation is performed."""
    result = build_cern_client_configuration(registration(), provider())
    assert not hasattr(result, "access_token")
    assert not hasattr(result, "refresh_token")
    assert not hasattr(result, "client_secret")
    assert not hasattr(result, "authenticated_identity")
