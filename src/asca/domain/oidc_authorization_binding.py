"""Replay-correlated CERN OIDC checks without authenticated identity authority.

This data shape is forgeable and MUST NOT be used as an authentication,
authorization, session, or CERN membership capability.
"""

from dataclasses import dataclass, field


class OidcAuthorizationBindingError(ValueError):
    """Sanitized failure of a single-use OIDC browser authorization attempt."""


@dataclass(frozen=True, slots=True)
class BoundUntrustedCernOidcToken:
    """Checked token with a consumed local browser attempt; NOT an authenticated user.

    An unverified token response is supplied separately by the caller. This
    component does not prove that the response came from the consumed code.
    """

    issuer: str = field(repr=False)
    subject: str = field(repr=False)
    audiences: tuple[str, ...] = field(repr=False)
    expires_at: int = field(repr=False)
    algorithm: str = field(repr=False)
    kid: str = field(repr=False)
