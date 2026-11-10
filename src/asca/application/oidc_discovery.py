"""Fail-closed OIDC metadata validation without HTTP or framework dependencies."""

from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from asca.domain.oidc_discovery import OidcDiscoveryError, OidcProviderMetadata

# The URL is documented publicly by CERN's Keycloak SSO integrations.
# Treat it as a configured trust anchor, not as proof of live availability.
CERN_OIDC_ISSUER = "https://auth.cern.ch/auth/realms/cern"
CERN_OIDC_DISCOVERY_URL = "https://auth.cern.ch/auth/realms/cern/.well-known/openid-configuration"
_ALLOWED_SIGNING_ALGORITHMS = frozenset({"RS256", "PS256", "ES256"})


@dataclass(frozen=True, slots=True)
class OidcDiscoveryPolicy:
    """Explicitly configured trust anchor; metadata cannot change its issuer."""

    expected_issuer: str = CERN_OIDC_ISSUER
    discovery_url: str = CERN_OIDC_DISCOVERY_URL

    def __post_init__(self) -> None:
        if not _is_https_url(self.expected_issuer):
            raise OidcDiscoveryError("OIDC policy has an invalid expected issuer")
        if not _is_https_url(self.discovery_url):
            raise OidcDiscoveryError("OIDC policy has an invalid discovery URL")
        if _origin(self.expected_issuer) != _origin(self.discovery_url):
            raise OidcDiscoveryError("OIDC policy issuer and discovery origins must match")
        expected_path = urlsplit(self.expected_issuer).path.rstrip("/")
        actual_path = urlsplit(self.discovery_url).path
        if actual_path != expected_path + "/.well-known/openid-configuration":
            raise OidcDiscoveryError("OIDC discovery path does not match the issuer")


def _is_https_url(value: object) -> bool:
    if not isinstance(value, str) or value != value.strip():
        return False
    if any(char.isspace() or ord(char) < 32 or char == "\\" for char in value):
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
        if port is not None and port == 0:
            return False
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
    )


def _origin(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(value)
    if not _is_https_url(value) or parsed.hostname is None:
        raise OidcDiscoveryError("OIDC metadata contains an unsafe HTTPS URL")
    return (parsed.scheme, parsed.hostname.lower(), parsed.port or 443)


def _required_string(document: dict[str, object], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value.strip():
        raise OidcDiscoveryError(f"OIDC discovery field {key} must be a string")
    return value


def _required_string_list(document: dict[str, object], key: str) -> tuple[str, ...]:
    value = document.get(key)
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise OidcDiscoveryError(f"OIDC discovery field {key} must be a nonempty string array")
    return tuple(value)


def validate_oidc_metadata(document: object, policy: OidcDiscoveryPolicy) -> OidcProviderMetadata:
    """Check the trusted issuer, public endpoints, and mandatory capabilities.

    This is public-provider metadata validation, not JWT signature validation.
    Metadata can never grant authentication or access to CERN resources.
    """
    if not isinstance(document, dict) or any(not isinstance(k, str) for k in document):
        raise OidcDiscoveryError("OIDC discovery document must be a JSON object")

    issuer = _required_string(document, "issuer")
    if issuer != policy.expected_issuer:
        raise OidcDiscoveryError("OIDC issuer does not match configured trust anchor")

    fields = ("authorization_endpoint", "token_endpoint", "jwks_uri")
    endpoints = {field: _required_string(document, field) for field in fields}
    for endpoint in endpoints.values():
        if _origin(endpoint) != _origin(policy.expected_issuer):
            raise OidcDiscoveryError("OIDC endpoint is outside the configured issuer origin")

    response_types = _required_string_list(document, "response_types_supported")
    if "code" not in response_types:
        raise OidcDiscoveryError("OIDC provider does not advertise Authorization Code")

    pkce_methods = _required_string_list(document, "code_challenge_methods_supported")
    if "S256" not in pkce_methods:
        raise OidcDiscoveryError("OIDC provider does not advertise PKCE S256")

    signing_algs = _required_string_list(document, "id_token_signing_alg_values_supported")
    approved = tuple(sorted(_ALLOWED_SIGNING_ALGORITHMS.intersection(signing_algs)))
    if not approved:
        raise OidcDiscoveryError("OIDC provider has no approved ID-token signing algorithm")

    return OidcProviderMetadata(
        issuer=issuer,
        authorization_endpoint=endpoints["authorization_endpoint"],
        token_endpoint=endpoints["token_endpoint"],
        jwks_uri=endpoints["jwks_uri"],
        approved_id_token_algorithms=approved,
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )


class OidcMetadataFetcher(Protocol):
    """Port for fetching public JSON from an explicitly configured URL."""

    def fetch(self, url: str) -> object: ...


class OidcDiscoveryService:
    """Use a fetch adapter; never retrieve a URL provided by an HTTP caller."""

    def __init__(self, policy: OidcDiscoveryPolicy, fetcher: OidcMetadataFetcher) -> None:
        self._policy = policy
        self._fetcher = fetcher

    def discover(self) -> OidcProviderMetadata:
        document = self._fetcher.fetch(self._policy.discovery_url)
        return validate_oidc_metadata(document, self._policy)
