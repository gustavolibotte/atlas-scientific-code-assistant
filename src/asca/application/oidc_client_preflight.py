"""Bind declared CERN client settings to already validated public OIDC metadata.

This offline configuration function does not prove actual client registration,
exchange authorization codes, validate ID tokens, create sessions, or enable SSO.
"""

from urllib.parse import urlsplit

from asca.application.identity import OidcClientConfiguration
from asca.application.oidc_discovery import CERN_OIDC_ISSUER, OidcDiscoveryPolicy
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_registration import OidcClientRegistration, OidcRegistrationError

_ALLOWED_SIGNING_ALGORITHMS = frozenset({"ES256", "PS256", "RS256"})


def _has_expected_origin(endpoint: str, expected_issuer: str) -> bool:
    """Reject ambiguous OIDC endpoints even if a metadata object was forged."""
    if (
        not isinstance(endpoint, str)
        or endpoint != endpoint.strip()
        or any(ord(ch) < 33 or ord(ch) == 127 for ch in endpoint)
        or any(ch in endpoint for ch in ("\\", "?", "#"))
    ):
        return False
    try:
        actual = urlsplit(endpoint)
        expected = urlsplit(expected_issuer)
        return bool(
            actual.scheme == "https"
            and actual.hostname == expected.hostname
            and actual.port != 0
            and (actual.port or 443) == (expected.port or 443)
            and actual.username is None
            and actual.password is None
            and not actual.query
            and not actual.fragment
            and actual.path.startswith("/")
        )
    except ValueError:
        return False


def build_cern_client_configuration(
    registration: OidcClientRegistration,
    metadata: OidcProviderMetadata,
    *,
    policy: OidcDiscoveryPolicy | None = None,
) -> OidcClientConfiguration:
    """Prepare offline authorization settings from a separately verified source.

    The caller must obtain ``metadata`` through trusted OIDC discovery and
    confirm ``registration`` in the official CERN portal. This function checks
    the fixed trust anchor again, but cannot validate portal-side registration.
    """
    effective_policy = policy or OidcDiscoveryPolicy()
    if effective_policy.expected_issuer != CERN_OIDC_ISSUER:
        raise OidcRegistrationError("CERN issuer trust anchor is required")
    if metadata.issuer != CERN_OIDC_ISSUER:
        raise OidcRegistrationError("Provider issuer does not match CERN")
    if not metadata.supports_authorization_code or not metadata.supports_pkce_s256:
        raise OidcRegistrationError("Provider does not meet required OIDC capabilities")
    if not metadata.approved_id_token_algorithms or any(
        algorithm not in _ALLOWED_SIGNING_ALGORITHMS
        for algorithm in metadata.approved_id_token_algorithms
    ):
        raise OidcRegistrationError("No exclusively approved asymmetric ID-token algorithms")
    if not all(
        _has_expected_origin(endpoint, effective_policy.expected_issuer)
        for endpoint in (
            metadata.authorization_endpoint,
            metadata.token_endpoint,
            metadata.jwks_uri,
        )
    ):
        raise OidcRegistrationError("OIDC endpoint violates CERN trust policy")

    return OidcClientConfiguration(
        issuer=effective_policy.expected_issuer,
        authorization_endpoint=metadata.authorization_endpoint,
        client_id=registration.client_id,
        redirect_uri=registration.redirect_uri,
        scopes=registration.scopes,
    )
