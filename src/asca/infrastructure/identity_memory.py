"""Bounded ephemeral authorization-attempt store for offline tests and local prototype.

This is NOT suitable for multiworker or hosted login. Never store user tokens here.
"""

import hashlib
import hmac
from threading import RLock

from asca.domain.identity import AuthenticationFlowError, PendingAuthorization


class InMemoryAuthorizationAttemptStore:
    """Single-use, session-bound, thread-safe, bounded OIDC attempt storage."""

    def __init__(self, *, max_pending: int = 256) -> None:
        if not 1 <= max_pending <= 100_000:
            raise ValueError("max_pending must be between 1 and 100000")
        self._lock = RLock()
        self._pending: dict[str, PendingAuthorization] = {}
        self._max_pending = max_pending

    @staticmethod
    def _key(binding: str) -> str:
        if not isinstance(binding, str) or not binding:
            raise AuthenticationFlowError("Invalid or expired authorization attempt")
        return hashlib.sha256(binding.encode("utf-8")).hexdigest()

    def save(self, attempt: PendingAuthorization, *, now: float) -> None:
        with self._lock:
            self._purge_expired(now)
            key = self._key(attempt.browser_binding)
            if key in self._pending:
                raise AuthenticationFlowError("Duplicate authorization attempt")
            if attempt.expires_at <= now:
                raise AuthenticationFlowError("Invalid or expired authorization attempt")
            if len(self._pending) >= self._max_pending:
                raise AuthenticationFlowError("Authorization attempt limit reached")
            self._pending[key] = attempt

    def consume(self, binding: str, state: str, *, now: float) -> PendingAuthorization:
        with self._lock:
            key = self._key(binding)
            attempt = self._pending.get(key)
            if attempt is None:
                raise AuthenticationFlowError("Invalid or expired authorization attempt")
            if attempt.expires_at <= now:
                self._pending.pop(key, None)
                raise AuthenticationFlowError("Invalid or expired authorization attempt")
            if not isinstance(state, str) or not hmac.compare_digest(attempt.state, state):
                raise AuthenticationFlowError("Authorization state mismatch")
            del self._pending[key]
            return attempt

    def _purge_expired(self, now: float) -> None:
        for key, attempt in tuple(self._pending.items()):
            if attempt.expires_at <= now:
                del self._pending[key]
