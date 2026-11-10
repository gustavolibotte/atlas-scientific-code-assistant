"""Non-authenticating result and sanitized errors for the CERN OIDC check pipeline.

A successful check is NOT a login capability. Python dataclasses are forgeable,
HTTPS provenance depends on the configured transport, and authorization attempts
are not consumed by this component. Do not infer CERN membership or permissions.
"""

from dataclasses import dataclass, field


class OidcVerificationError(ValueError):
    """Sanitized failure of a CERN OIDC token-verification check."""


@dataclass(frozen=True, slots=True)
class CheckedUntrustedCernOidcToken:
    """Signature and claims checked, without proof of a complete login flow.

    Values are hidden from repr. The source_url label is NOT a provenance
    attestation: injected transports and Python objects can be fabricated.
    """

    issuer: str = field(repr=False)
    subject: str = field(repr=False)
    audiences: tuple[str, ...] = field(repr=False)
    expires_at: int = field(repr=False)
    algorithm: str = field(repr=False)
    kid: str = field(repr=False)
    source_url: str = field(repr=False)
