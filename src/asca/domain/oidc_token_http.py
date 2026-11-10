"""Unverified and secret-bearing HTTP result of a native public OIDC exchange.

Obtaining a successful HTTP response is not proof of an authenticated identity.
Token parsing, signature verification, and session creation are separate steps.
"""

from dataclasses import dataclass, field


class OidcTokenHttpError(ValueError):
    """Sanitized failure; never includes server messages or request credentials."""


@dataclass(frozen=True, slots=True)
class UnverifiedOidcTokenHttpResponse:
    """Bounded, opaque response bytes that must not be logged or trusted."""

    body: bytes = field(repr=False)
    status_code: int = 200

    def __post_init__(self) -> None:
        if (
            not isinstance(self.body, bytes)
            or not self.body
            or len(self.body) > 65_536
            or self.status_code != 200
        ):
            raise OidcTokenHttpError("Invalid unverified OIDC token HTTP response")
