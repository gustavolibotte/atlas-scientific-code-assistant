"""Bounded ephemeral authorization-attempt store for offline tests and local prototype.

This is NOT suitable for multiworker or hosted login. Never store user tokens here.
"""

import hashlib
import hmac
import math
import re
from threading import RLock

from asca.domain.identity import AuthenticationFlowError, PendingAuthorization


class InMemoryAuthorizationAttemptStore:
    """Single-use, session-bound, thread-safe, bounded OIDC attempt storage."""

    def __init__(self, *, max_pending: int = 256) -> None:
        if not 1 <= max_pending <= 100_000:
            raise ValueError("max_pending must be between 1 and 100000")
        self._lock = RLock()
        self._pending: dict[str, PendingAuthorization] = {}
        self._cancellations: dict[str, str] = {}
        self._handles_by_binding: dict[str, str] = {}
        self._max_pending = max_pending

    @staticmethod
    def _key(binding: str) -> str:
        if not isinstance(binding, str) or not binding:
            raise AuthenticationFlowError("Invalid or expired authorization attempt")
        return hashlib.sha256(binding.encode("utf-8")).hexdigest()

    @staticmethod
    def _cancel_key(handle: str) -> str:
        if (
            type(handle) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]{43,128}", handle, re.ASCII) is None
        ):
            raise AuthenticationFlowError("Invalid or expired authorization attempt")
        return hashlib.sha256(handle.encode("ascii")).hexdigest()

    @staticmethod
    def _validate_now(now: float) -> float:
        """Reject invalid explicit clock readings before any store mutation."""
        if type(now) not in (int, float):
            raise AuthenticationFlowError("Invalid authorization time")
        try:
            checked = float(now)
        except OverflowError:
            raise AuthenticationFlowError("Invalid authorization time") from None
        if not math.isfinite(checked):
            raise AuthenticationFlowError("Invalid authorization time")
        return checked

    def _remove(self, key: str) -> None:
        """Remove both the attempt and its independent revocation index."""
        self._pending.pop(key, None)
        handle_key = self._handles_by_binding.pop(key, None)
        if handle_key is not None:
            self._cancellations.pop(handle_key, None)

    def cancel(self, cancellation_handle: str, *, now: float | None = None) -> None:
        """Revoke once by an opaque capability, optionally checking its TTL.

        A supplied clock reaps expired entries under the same atomic lock.
        An omitted clock retains legacy best-effort revocation semantics.
        """
        handle_key = self._cancel_key(cancellation_handle)
        checked_now = self._validate_now(now) if now is not None else None
        with self._lock:
            if checked_now is not None:
                self._purge_expired(checked_now)
            key = self._cancellations.get(handle_key)
            if key is None or key not in self._pending:
                raise AuthenticationFlowError("Invalid or expired authorization attempt")
            self._remove(key)

    def has_cancel_handle(self, cancellation_handle: str, *, now: float | None = None) -> bool:
        """Check an opaque index, optionally reaping expired attempts first.

        Index presence alone is never proof of an authenticated identity.
        """
        key = self._cancel_key(cancellation_handle)
        checked_now = self._validate_now(now) if now is not None else None
        with self._lock:
            if checked_now is not None:
                self._purge_expired(checked_now)
            return key in self._cancellations

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
            handle_key = (
                self._cancel_key(attempt.cancellation_handle)
                if attempt.cancellation_handle is not None
                else None
            )
            if handle_key is not None and handle_key in self._cancellations:
                raise AuthenticationFlowError("Duplicate authorization attempt")
            self._pending[key] = attempt
            if handle_key is not None:
                self._cancellations[handle_key] = key
                self._handles_by_binding[key] = handle_key

    def consume(self, binding: str, state: str, *, now: float) -> PendingAuthorization:
        with self._lock:
            key = self._key(binding)
            attempt = self._pending.get(key)
            if attempt is None:
                raise AuthenticationFlowError("Invalid or expired authorization attempt")
            if attempt.expires_at <= now:
                self._remove(key)
                raise AuthenticationFlowError("Invalid or expired authorization attempt")
            if not isinstance(state, str) or not hmac.compare_digest(attempt.state, state):
                raise AuthenticationFlowError("Authorization state mismatch")
            self._remove(key)
            return attempt

    def _purge_expired(self, now: float) -> None:
        for key, attempt in tuple(self._pending.items()):
            if attempt.expires_at <= now:
                self._remove(key)
