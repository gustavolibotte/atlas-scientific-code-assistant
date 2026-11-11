"""Framework-independent identity types; no principal is trusted until token validation."""

from dataclasses import dataclass, field


class AuthenticationFlowError(ValueError):
    """Safe, non-secret-bearing error for an incomplete authorization flow."""


@dataclass(frozen=True, slots=True)
class PendingAuthorization:
    """One browser-bound OIDC authorization attempt, before token verification.

    Do not serialize or log this object. A pending authorization is not a session.
    """

    browser_binding: str = field(repr=False)
    state: str = field(repr=False)
    nonce: str = field(repr=False)
    code_verifier: str = field(repr=False)
    created_at: float
    expires_at: float
    cancellation_handle: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class AuthorizationCodeGrant:
    """Unverified code received from an OIDC callback, not an authenticated user."""

    code: str = field(repr=False)
    nonce: str = field(repr=False)
    code_verifier: str = field(repr=False)
    redirect_uri: str


@dataclass(frozen=True, slots=True)
class VerifiedIdentity:
    """Data shape reserved for a future cryptographically verified ID token."""

    issuer: str
    subject: str
    audience: str

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str) and value.strip()
            for value in (
                self.issuer,
                self.subject,
                self.audience,
            )
        ):
            raise ValueError("Verified identity fields must be non-empty")
