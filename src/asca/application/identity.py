"""Offline OIDC authorization-code preparation with PKCE and session-bound state.

No CERN HTTP request, authorization-code exchange, JWT validation, or login takes
place here. The caller must eventually bind ``browser_binding`` to a secure
server-side browser session; it must not send this secret in a URL or JavaScript.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlencode, urlsplit

from asca.domain.identity import (
    AuthenticationFlowError,
    AuthorizationCodeGrant,
    PendingAuthorization,
    VerifiedIdentity,
)

_SCOPE_PATTERN = re.compile(r"^[A-Za-z0-9._:-]+$")


def _valid_url(url: str, *, redirect: bool = False) -> bool:
    """Reject insecure, ambiguous, or credential-bearing OIDC endpoints."""
    if not isinstance(url, str) or url != url.strip() or any(ch.isspace() for ch in url):
        return False
    try:
        parsed = urlsplit(url)
        _ = parsed.port  # Reject malformed port syntax.
    except ValueError:
        return False
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        return False
    if parsed.fragment or parsed.query:
        return False
    if parsed.scheme == "https":
        return True
    return bool(
        redirect
        and parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        and parsed.port is not None
    )


@dataclass(frozen=True, slots=True)
class OidcClientConfiguration:
    """Validated non-secret OIDC configuration from authorized discovery/registration."""

    issuer: str
    authorization_endpoint: str
    client_id: str
    redirect_uri: str
    scopes: tuple[str, ...] = ("openid", "profile")

    def __post_init__(self) -> None:
        if not _valid_url(self.issuer) or not _valid_url(self.authorization_endpoint):
            raise ValueError("OIDC issuer and authorization endpoint must be secure HTTPS URLs")
        if not _valid_url(self.redirect_uri, redirect=True):
            raise ValueError("Redirect URI must be HTTPS or an explicit loopback HTTP URI")
        if (
            not self.client_id
            or self.client_id != self.client_id.strip()
            or any(ch.isspace() for ch in self.client_id)
        ):
            raise ValueError("OIDC client_id is invalid")
        if (
            not self.scopes
            or "openid" not in self.scopes
            or len(set(self.scopes)) != len(self.scopes)
            or any(not _SCOPE_PATTERN.fullmatch(scope) for scope in self.scopes)
        ):
            raise ValueError("OIDC scopes must be unique safe tokens including openid")


@dataclass(frozen=True, slots=True)
class AuthorizationStart:
    """Private return value; the browser receives only the authorization URL."""

    authorization_url: str = field(repr=False)
    browser_binding: str = field(repr=False)
    cancellation_handle: str | None = field(default=None, repr=False)


class AuthorizationAttemptStore(Protocol):
    """Storage boundary; production needs session-compatible durable storage."""

    def save(self, attempt: PendingAuthorization, *, now: float) -> None: ...

    def consume(self, binding: str, state: str, *, now: float) -> PendingAuthorization: ...

    def cancel(self, cancellation_handle: str) -> None: ...


class OidcIdTokenVerifier(Protocol):
    """Future adapter MUST validate JWT signature, issuer, audience and nonce."""

    async def verify(
        self, id_token: str, *, issuer: str, audience: str, nonce: str
    ) -> VerifiedIdentity: ...


def pkce_s256_challenge(code_verifier: str) -> str:
    """RFC 7636 S256 challenge; verifier must be a 43-128 character PKCE token."""
    if not 43 <= len(code_verifier) <= 128 or not re.fullmatch(r"[A-Za-z0-9._~-]+", code_verifier):
        raise ValueError("Invalid PKCE code verifier")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class OidcAuthorizationService:
    """Prepare and consume OIDC callbacks without authenticating a user."""

    def __init__(
        self,
        config: OidcClientConfiguration,
        store: AuthorizationAttemptStore,
        *,
        clock: Callable[[], float] = time.time,
        ttl_seconds: int = 300,
    ) -> None:
        if not 30 <= ttl_seconds <= 900:
            raise ValueError("Authorization attempt TTL must be between 30 and 900 seconds")
        self._config = config
        self._store = store
        self._clock = clock
        self._ttl = ttl_seconds

    def begin(self) -> AuthorizationStart:
        """Generate a fresh browser binding, state, nonce and PKCE S256 verifier."""
        now = self._clock()
        attempt = PendingAuthorization(
            browser_binding=secrets.token_urlsafe(32),
            state=secrets.token_urlsafe(32),
            nonce=secrets.token_urlsafe(32),
            code_verifier=secrets.token_urlsafe(48),
            created_at=now,
            expires_at=now + self._ttl,
            cancellation_handle=secrets.token_urlsafe(32),
        )
        self._store.save(attempt, now=now)
        try:
            return self._build_authorization_start(attempt)
        except Exception:
            # A saved attempt must not survive a failed authorization URL build.
            self._store.cancel(attempt.cancellation_handle or "")
            raise

    def _build_authorization_start(self, attempt: PendingAuthorization) -> AuthorizationStart:
        """Build a URL after save; always retain its independent cancel handle."""
        params = {
            "response_type": "code",
            "client_id": self._config.client_id,
            "redirect_uri": self._config.redirect_uri,
            "scope": " ".join(self._config.scopes),
            "state": attempt.state,
            "nonce": attempt.nonce,
            "code_challenge": pkce_s256_challenge(attempt.code_verifier),
            "code_challenge_method": "S256",
        }
        return AuthorizationStart(
            authorization_url=f"{self._config.authorization_endpoint}?{urlencode(params)}",
            browser_binding=attempt.browser_binding,
            cancellation_handle=attempt.cancellation_handle,
        )

    def finish(
        self,
        *,
        browser_binding: str,
        state: str,
        code: str | None = None,
        error: str | None = None,
        response_issuer: str | None = None,
    ) -> AuthorizationCodeGrant:
        """Verify callback correlation and consume it, without exchanging the code.

        ``browser_binding`` must come from the initiating browser's protected
        session, never from a callback query parameter.
        """
        if bool(code) == bool(error):
            raise AuthenticationFlowError("Invalid authorization callback")
        if not isinstance(state, str) or not state:
            raise AuthenticationFlowError("Invalid authorization callback")
        if response_issuer is not None and not hmac.compare_digest(
            response_issuer, self._config.issuer
        ):
            raise AuthenticationFlowError("Unexpected authorization issuer")
        attempt = self._store.consume(browser_binding, state, now=self._clock())
        if error is not None:
            raise AuthenticationFlowError("Authorization was not granted")
        if not isinstance(code, str) or not code.strip():
            raise AuthenticationFlowError("Invalid authorization callback")
        return AuthorizationCodeGrant(
            code=code,
            nonce=attempt.nonce,
            code_verifier=attempt.code_verifier,
            redirect_uri=self._config.redirect_uri,
        )
