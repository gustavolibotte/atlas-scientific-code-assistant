"""Immutable, unsent authorization-code token-request data.

This contract holds a sensitive request body. Never log, serialize or publish it.
It does not perform HTTP, validate tokens or authenticate an identity.
"""

from dataclasses import dataclass, field


class OidcTokenRequestError(ValueError):
    """Sanitized error for a rejected, untrusted token-request declaration."""


@dataclass(frozen=True, slots=True)
class UnsentOidcTokenRequest:
    """A prepared, unsent POST for a native public client only.

    A future authorized HTTP adapter must enforce network, timeout, TLS,
    redirect, response-size, and logging restrictions before sending any body.
    """

    token_endpoint: str
    form_body: bytes = field(repr=False)
    expected_nonce: str = field(repr=False)

    @property
    def method(self) -> str:
        return "POST"

    @property
    def headers(self) -> tuple[tuple[str, str], ...]:
        """Fixed headers; no Authorization header, cookies or dynamic secrets."""
        return (
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Accept", "application/json"),
            ("Cache-Control", "no-store"),
        )
