"""Validated public OIDC provider metadata; never an authenticated identity."""

from dataclasses import dataclass


class OidcDiscoveryError(ValueError):
    """Safe error for rejected or unavailable public provider metadata."""


@dataclass(frozen=True, slots=True)
class OidcProviderMetadata:
    """Trusted subset of an OIDC discovery document.

    Only algorithms explicitly approved here can be selected by future JWT
    verification adapters. Discovery does not verify or accept any ID token.
    """

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    approved_id_token_algorithms: tuple[str, ...]
    supports_authorization_code: bool
    supports_pkce_s256: bool
