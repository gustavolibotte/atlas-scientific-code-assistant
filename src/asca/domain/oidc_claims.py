"""Claims checked against a declared authorization flow, NOT an authenticated identity.

Signature verification was performed against key material whose CERN provenance
has not yet been established. Ordinary Python dataclasses are forgeable and
must never be interpreted as principals or permission grants.
"""

from dataclasses import dataclass, field


class OidcClaimsError(ValueError):
    """Secret-free rejection of invalid or unsupported OIDC ID-token claims."""


@dataclass(frozen=True, slots=True)
class ClaimsCheckedUntrustedOidcPayload:
    """Validated claim values from a caller-supplied, signature-checked payload.

    This object does NOT confirm CERN key provenance or user authentication.
    Claim values are deliberately omitted from repr, including subject/nonce.
    """

    issuer: str = field(repr=False)
    subject: str = field(repr=False)
    audiences: tuple[str, ...] = field(repr=False)
    authorized_party: str | None = field(repr=False)
    nonce: str = field(repr=False)
    expires_at: int = field(repr=False)
    issued_at: int = field(repr=False)
    not_before: int | None = field(repr=False)
    algorithm: str = field(repr=False)
    kid: str = field(repr=False)
