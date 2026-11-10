"""Immutable *unverified-provenance* OIDC public-key declarations.

An accepted JWK is structured public material, not a verified JWT, a trusted
fetch, an authenticated principal, or an authorization decision.
"""

from dataclasses import dataclass, field


class OidcJwksError(ValueError):
    """Sanitized error for malformed or unsupported OIDC signing-key data."""


@dataclass(frozen=True, slots=True)
class OidcPublicJwk:
    """Bounded RSA or P-256 public parameters, not a constructed crypto key."""

    kid: str
    algorithm: str
    key_type: str
    modulus: bytes | None = field(default=None, repr=False)
    exponent: bytes | None = field(default=None, repr=False)
    curve: str | None = None
    x_coordinate: bytes | None = field(default=None, repr=False)
    y_coordinate: bytes | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class ParsedUnverifiedOidcJwks:
    """Filtered key declarations; provenance must be established independently."""

    issuer: str
    jwks_uri: str
    approved_algorithms: tuple[str, ...]
    keys: tuple[OidcPublicJwk, ...] = field(repr=False)
