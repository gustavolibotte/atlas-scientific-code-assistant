"""Deterministic expiry-aware OIDC cancellation without changing legacy callers."""

from __future__ import annotations

import math
from threading import RLock

import pytest

from asca.application.identity import (
    AuthorizationStart,
    OidcAuthorizationService,
    OidcClientConfiguration,
)
from asca.domain.identity import AuthenticationFlowError, PendingAuthorization
from asca.infrastructure.identity_memory import InMemoryAuthorizationAttemptStore
from asca.infrastructure.oidc_native_exchange import CernOidcNativeCodeExchange

START = 1_800_000_000.0
TTL = 300.0


def attempt(
    n: int = 0, *, created_at: float = START, expires_at: float = START + TTL
) -> PendingAuthorization:
    return PendingAuthorization(
        browser_binding=f"binding-{n}",
        state=f"state-{n}",
        nonce=f"nonce-{n}",
        code_verifier=f"verifier-{n}",
        created_at=created_at,
        expires_at=expires_at,
        cancellation_handle=(chr(65 + n) * 43),
    )


def assert_indexes_empty(store: InMemoryAuthorizationAttemptStore) -> None:
    assert store._pending == store._cancellations == store._handles_by_binding == {}


@pytest.mark.parametrize("delta", [-1.0, 0.0, 1.0])
def test_cancel_exact_expiry_boundary(delta: float) -> None:
    store = InMemoryAuthorizationAttemptStore()
    entry = attempt()
    store.save(entry, now=START)
    if delta < 0:
        store.cancel(entry.cancellation_handle or "", now=START + TTL + delta)
    else:
        with pytest.raises(AuthenticationFlowError, match="Invalid or expired"):
            store.cancel(entry.cancellation_handle or "", now=START + TTL + delta)
    assert_indexes_empty(store)


@pytest.mark.parametrize("delta", [-1.0, 0.0, 1.0])
def test_handle_lookup_observes_expiry_and_reaps_indices(delta: float) -> None:
    store = InMemoryAuthorizationAttemptStore()
    entry = attempt()
    store.save(entry, now=START)
    alive = store.has_cancel_handle(entry.cancellation_handle or "", now=START + TTL + delta)
    assert alive is (delta < 0)
    if delta < 0:
        assert len(store._pending) == len(store._cancellations) == 1
    else:
        assert_indexes_empty(store)


def test_legacy_cancel_without_explicit_time_still_revokes_and_cleans() -> None:
    store = InMemoryAuthorizationAttemptStore()
    entry = attempt()
    store.save(entry, now=START)
    store.cancel(entry.cancellation_handle or "")
    assert_indexes_empty(store)


def test_legacy_handle_lookup_does_not_assume_real_wall_clock() -> None:
    store = InMemoryAuthorizationAttemptStore()
    entry = attempt(created_at=2.0, expires_at=302.0)
    store.save(entry, now=2.0)
    assert store.has_cancel_handle(entry.cancellation_handle or "") is True
    assert store.has_cancel_handle(entry.cancellation_handle or "", now=302.0) is False
    assert_indexes_empty(store)


@pytest.mark.parametrize(
    "now",
    [
        True,
        False,
        math.nan,
        math.inf,
        -math.inf,
        "300",
        object(),
        pytest.param(10**500, id="huge-int"),
    ],
)
@pytest.mark.parametrize("operation", ["cancel", "lookup"])
def test_invalid_explicit_time_is_rejected_without_state_mutation(
    now: object, operation: str
) -> None:
    store = InMemoryAuthorizationAttemptStore()
    entry = attempt()
    store.save(entry, now=START)
    with pytest.raises(AuthenticationFlowError, match="Invalid authorization time"):
        if operation == "cancel":
            store.cancel(entry.cancellation_handle or "", now=now)  # type: ignore[arg-type]
        else:
            store.has_cancel_handle(entry.cancellation_handle or "", now=now)  # type: ignore[arg-type]
    assert len(store._pending) == len(store._cancellations) == 1
    store.cancel(entry.cancellation_handle or "")
    assert_indexes_empty(store)


def test_lookup_reaps_only_expired_attempts_not_live_siblings() -> None:
    store = InMemoryAuthorizationAttemptStore()
    old = attempt(0)
    live = attempt(1, created_at=START + 100, expires_at=START + 500)
    store.save(old, now=START)
    store.save(live, now=START + 100)
    assert store.has_cancel_handle(old.cancellation_handle or "", now=START + TTL) is False
    assert store.has_cancel_handle(live.cancellation_handle or "", now=START + TTL) is True
    assert len(store._pending) == len(store._cancellations) == 1
    store.cancel(live.cancellation_handle or "", now=START + TTL)
    assert_indexes_empty(store)


def test_cancel_with_time_reaps_expired_siblings_and_preserves_live_target() -> None:
    store = InMemoryAuthorizationAttemptStore()
    old = attempt(0)
    live = attempt(1, created_at=START + 100, expires_at=START + 500)
    store.save(old, now=START)
    store.save(live, now=START + 100)
    store.cancel(live.cancellation_handle or "", now=START + TTL)
    assert_indexes_empty(store)


def test_wrong_cancel_handle_cannot_revoke_live_sibling() -> None:
    store = InMemoryAuthorizationAttemptStore()
    entry = attempt()
    store.save(entry, now=START)
    with pytest.raises(AuthenticationFlowError):
        store.cancel("Z" * 43, now=START + 1)
    assert store.has_cancel_handle(entry.cancellation_handle or "", now=START + 1)
    store.cancel(entry.cancellation_handle or "", now=START + 1)
    assert_indexes_empty(store)


def test_repeated_expired_handle_cannot_be_consumed_or_cancelled() -> None:
    store = InMemoryAuthorizationAttemptStore()
    entry = attempt()
    store.save(entry, now=START)
    assert not store.has_cancel_handle(entry.cancellation_handle or "", now=START + TTL)
    with pytest.raises(AuthenticationFlowError):
        store.cancel(entry.cancellation_handle or "", now=START + TTL)
    with pytest.raises(AuthenticationFlowError):
        store.consume(entry.browser_binding, entry.state, now=START + TTL)
    assert_indexes_empty(store)


def test_expired_lookup_does_not_resurrect_handle_on_new_save() -> None:
    store = InMemoryAuthorizationAttemptStore()
    old = attempt(0)
    store.save(old, now=START)
    assert not store.has_cancel_handle(old.cancellation_handle or "", now=START + TTL)
    new = attempt(1, created_at=START + TTL, expires_at=START + TTL * 2)
    store.save(new, now=START + TTL)
    assert not store.has_cancel_handle(old.cancellation_handle or "", now=START + TTL)
    assert store.has_cancel_handle(new.cancellation_handle or "", now=START + TTL)
    store.cancel(new.cancellation_handle or "", now=START + TTL)
    assert_indexes_empty(store)


def test_native_repeated_begin_reaps_expired_refs_using_checked_clock() -> None:
    """Use a minimal isolated native exchange shell; no transport or CERN calls."""
    current = [START]
    store = InMemoryAuthorizationAttemptStore()
    config = OidcClientConfiguration(
        issuer="https://issuer.example.invalid/realm",
        authorization_endpoint="https://issuer.example.invalid/realm/auth",
        client_id="offline-only-client",
        redirect_uri="http://127.0.0.1:8080/oidc/callback",
    )
    service = OidcAuthorizationService(config, store, clock=lambda: current[0])
    native = object.__new__(CernOidcNativeCodeExchange)
    native._clock = lambda: current[0]
    native._service = service
    native._store = store
    native._cancel_lock = RLock()
    native._pending_cancel_handles = set()
    first: AuthorizationStart = native.begin()
    assert first.cancellation_handle is not None
    current[0] += TTL
    second = native.begin()
    assert second.cancellation_handle is not None
    assert native._pending_cancel_handles == {second.cancellation_handle}
    assert not store.has_cancel_handle(first.cancellation_handle, now=current[0])
    native.cancel_pending()
    assert_indexes_empty(store)


def test_native_invalid_clock_is_rejected_before_new_attempt_is_saved() -> None:
    class ForbiddenService:
        def begin(self) -> AuthorizationStart:
            raise AssertionError("Attempt must not be created with an invalid clock")

    native = object.__new__(CernOidcNativeCodeExchange)
    native._clock = lambda: math.nan
    native._service = ForbiddenService()  # type: ignore[assignment]
    native._cancel_lock = RLock()
    with pytest.raises(ValueError, match="OIDC authorization attempt was rejected"):
        native.begin()
