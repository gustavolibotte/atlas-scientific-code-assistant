"""Non-authenticating outcome of a single-use CERN native code exchange.

Even a successful HTTPS token POST and JWS/claims check cannot prove a CERN
client registration or grant a principal. This type is forgeable Python data.
"""

from dataclasses import dataclass, field


class OidcNativeExchangeError(ValueError):
    """Sanitized refusal of an isolated native OIDC authorization transaction."""


@dataclass(frozen=True, slots=True)
class ExchangedUntrustedCernOidcToken:
    """A checked ID token from the same locally consumed authorization-code POST.

    No token, session or permission is retained. This is NOT a verified identity.
    The transport and verifier may be injected by tests, so this is never an
    authentication capability.
    """

    issuer: str = field(repr=False)
    subject: str = field(repr=False)
    audiences: tuple[str, ...] = field(repr=False)
    expires_at: int = field(repr=False)
    algorithm: str = field(repr=False)
    kid: str = field(repr=False)
