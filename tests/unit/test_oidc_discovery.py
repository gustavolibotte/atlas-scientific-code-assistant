"""Deterministic, network-free tests for OIDC trust anchors and public metadata."""

from copy import deepcopy

import pytest

from asca.application.oidc_discovery import (
    CERN_OIDC_DISCOVERY_URL,
    CERN_OIDC_ISSUER,
    OidcDiscoveryPolicy,
    OidcDiscoveryService,
    validate_oidc_metadata,
)
from asca.domain.oidc_discovery import OidcDiscoveryError, OidcProviderMetadata


def valid_document() -> dict[str, object]:
    return {
        "issuer": CERN_OIDC_ISSUER,
        "authorization_endpoint": CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        "token_endpoint": CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        "jwks_uri": CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        "response_types_supported": ["code", "id_token", "token"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "id_token_signing_alg_values_supported": ["none", "HS256", "RS256", "ES256"],
    }


def test_cern_policy_is_fixed_and_secret_free() -> None:
    policy = OidcDiscoveryPolicy()
    assert policy.expected_issuer == CERN_OIDC_ISSUER
    assert policy.discovery_url == CERN_OIDC_DISCOVERY_URL
    assert "client_secret" not in repr(policy)


def test_valid_metadata_selects_only_approved_algorithms() -> None:
    result = validate_oidc_metadata(valid_document(), OidcDiscoveryPolicy())
    assert isinstance(result, OidcProviderMetadata)
    assert result.issuer == CERN_OIDC_ISSUER
    assert result.approved_id_token_algorithms == ("ES256", "RS256")
    assert result.supports_authorization_code
    assert result.supports_pkce_s256


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("issuer", "https://other.example.invalid/realms/cern", "issuer"),
        ("issuer", CERN_OIDC_ISSUER + "/", "issuer"),
        ("issuer", None, "issuer"),
        ("authorization_endpoint", "http://auth.cern.ch/auth", "unsafe"),
        ("authorization_endpoint", "https://auth.cern.ch.evil.invalid/auth", "origin"),
        ("authorization_endpoint", "https://user:pass@auth.cern.ch/auth", "unsafe"),
        ("authorization_endpoint", "https://auth.cern.ch/auth#fragment", "unsafe"),
        ("authorization_endpoint", "https://auth.cern.ch/auth?token=secret", "unsafe"),
        ("authorization_endpoint", "https://auth.cern.ch\\evil.invalid/a", "unsafe"),
        ("authorization_endpoint", "https://auth.cern.ch:0/a", "unsafe"),
        ("token_endpoint", "https://other.example.invalid/token", "origin"),
        ("token_endpoint", "https://auth.cern.ch:444/token", "origin"),
        ("jwks_uri", "http://127.0.0.1/internal", "unsafe"),
        ("jwks_uri", "https://auth.cern.ch:bad/certs", "unsafe"),
        ("jwks_uri", "https://auth.cern.ch/certs\n", "unsafe"),
        ("response_types_supported", ["id_token"], "Authorization Code"),
        ("response_types_supported", "code", "nonempty string array"),
        ("code_challenge_methods_supported", ["plain"], "PKCE S256"),
        ("code_challenge_methods_supported", None, "nonempty string array"),
        ("id_token_signing_alg_values_supported", ["none", "HS256"], "approved"),
        ("id_token_signing_alg_values_supported", [], "nonempty string array"),
        ("id_token_signing_alg_values_supported", ["RS256", 5], "nonempty string array"),
    ],
)
def test_rejects_untrusted_metadata(field: str, replacement: object, message: str) -> None:
    document = valid_document()
    document[field] = replacement
    with pytest.raises(OidcDiscoveryError, match=message):
        validate_oidc_metadata(document, OidcDiscoveryPolicy())


@pytest.mark.parametrize("document", [None, [], "{}", 1, {1: "value"}])
def test_requires_json_object_with_string_keys(document: object) -> None:
    with pytest.raises(OidcDiscoveryError, match="JSON object"):
        validate_oidc_metadata(document, OidcDiscoveryPolicy())


@pytest.mark.parametrize(
    ("issuer", "discovery"),
    [
        ("http://auth.cern.ch", CERN_OIDC_DISCOVERY_URL),
        ("https://auth.cern.ch", "http://auth.cern.ch/.well-known/openid-configuration"),
        ("https://auth.cern.ch/a", "https://attacker.invalid/a/.well-known/openid-configuration"),
        ("https://auth.cern.ch/a", "https://auth.cern.ch/b/.well-known/openid-configuration"),
        ("https://auth.cern.ch/a", "https://auth.cern.ch/a/.well-known/openid-configuration?x=1"),
    ],
)
def test_rejects_bad_policy(issuer: str, discovery: str) -> None:
    with pytest.raises(OidcDiscoveryError, match=r"policy|origin|path"):
        OidcDiscoveryPolicy(expected_issuer=issuer, discovery_url=discovery)


def test_service_fetches_only_the_preconfigured_document() -> None:
    class FakeFetcher:
        def __init__(self) -> None:
            self.seen: list[str] = []

        def fetch(self, url: str) -> object:
            self.seen.append(url)
            return deepcopy(valid_document())

    fetcher = FakeFetcher()
    service = OidcDiscoveryService(OidcDiscoveryPolicy(), fetcher)
    result = service.discover()
    assert result.approved_id_token_algorithms == ("ES256", "RS256")
    assert fetcher.seen == [CERN_OIDC_DISCOVERY_URL]


def test_service_propagates_invalid_issuer() -> None:
    class FakeFetcher:
        def fetch(self, url: str) -> object:
            del url
            return {**valid_document(), "issuer": "https://impostor.invalid"}

    with pytest.raises(OidcDiscoveryError, match="issuer"):
        OidcDiscoveryService(OidcDiscoveryPolicy(), FakeFetcher()).discover()
