"""Bounded, unparsed JWKS bytes from an explicitly invoked HTTPS retrieval.

This object is not evidence of a valid signing key, verified JWT or identity.
The same data shape can be manually constructed, so callers must preserve the
fetcher's provenance boundary and separately parse the public key declarations.
"""

from dataclasses import dataclass, field


class OidcJwksHttpError(ValueError):
    """Sanitized failure of the constrained CERN JWKS HTTP retrieval."""


@dataclass(frozen=True, slots=True)
class FetchedUnverifiedOidcJwks:
    """Opaque, bounded JWKS bytes; the contained JSON remains untrusted."""

    body: bytes = field(repr=False)
    source_url: str
    status_code: int = 200

    def __post_init__(self) -> None:
        if (
            not isinstance(self.body, bytes)
            or not 0 < len(self.body) <= 262_144
            or not isinstance(self.source_url, str)
            or not self.source_url.startswith("https://")
            or self.status_code != 200
        ):
            raise OidcJwksHttpError("Invalid unverified OIDC JWKS HTTP response")
