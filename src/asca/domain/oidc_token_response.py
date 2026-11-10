"""Opaque, unverified data extracted from one OIDC token response.

A syntactically valid JWT is not a verified ID token. Do not use these values to
create an identity, authorize a principal, or persist a session.
"""

from dataclasses import dataclass, field


class OidcTokenResponseError(ValueError):
    """Secret-free failure for an invalid or unsupported OIDC token response."""


@dataclass(frozen=True, slots=True)
class ParsedUnverifiedOidcTokenResponse:
    """Parsed but unauthenticated credentials; never log or serialize this object.

    The optional expiry is not a trusted expiration timestamp. A future JWT
    verifier must validate the ID token independently before any identity use.
    """

    access_token: str = field(repr=False)
    id_token: str = field(repr=False)
    token_type: str = field(repr=False)
    expires_in: int | None = field(repr=False)
    refresh_token: str | None = field(repr=False)
    scope: tuple[str, ...] | None = field(repr=False)
