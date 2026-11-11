"""Adversarial time-bound OIDC store tests, with no CERN network traffic."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from asca.domain.identity import AuthenticationFlowError, PendingAuthorization
from asca.infrastructure.identity_memory import InMemoryAuthorizationAttemptStore

NOW = 1_800_000_000.0
HANDLE = "K" * 43


def pending() -> PendingAuthorization:
    return PendingAuthorization(
        browser_binding="bound-browser",
        state="bound-state",
        nonce="bound-nonce",
        code_verifier="bound-verifier",
        created_at=NOW,
        expires_at=NOW + 300,
        cancellation_handle=HANDLE,
    )


@pytest.mark.parametrize("offset", [-1.0, 0.0, 1.0])
def test_parallel_callback_and_cancellation_at_expiry(offset: float) -> None:
    store = InMemoryAuthorizationAttemptStore()
    attempt = pending()
    store.save(attempt, now=NOW)
    gate = Barrier(2)
    moment = NOW + 300 + offset

    def consume() -> str:
        gate.wait(timeout=5)
        try:
            store.consume(attempt.browser_binding, attempt.state, now=moment)
            return "consumed"
        except AuthenticationFlowError:
            return "rejected"

    def cancel() -> str:
        gate.wait(timeout=5)
        try:
            store.cancel(HANDLE, now=moment)
            return "cancelled"
        except AuthenticationFlowError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(consume)
        second = executor.submit(cancel)
        results = [first.result(timeout=5), second.result(timeout=5)]

    if offset < 0:
        assert results.count("rejected") == 1
        assert set(results) in ({"consumed", "rejected"}, {"cancelled", "rejected"})
    else:
        assert results == ["rejected", "rejected"]
    assert store._pending == store._cancellations == store._handles_by_binding == {}


def test_stale_cancel_does_not_remove_later_live_attempt() -> None:
    store = InMemoryAuthorizationAttemptStore()
    first = pending()
    store.save(first, now=NOW)
    second = PendingAuthorization(
        browser_binding="other-browser",
        state="other-state",
        nonce="other-nonce",
        code_verifier="other-verifier",
        created_at=NOW + 200,
        expires_at=NOW + 600,
        cancellation_handle="L" * 43,
    )
    store.save(second, now=NOW + 200)
    with pytest.raises(AuthenticationFlowError):
        store.cancel(HANDLE, now=NOW + 300)
    assert store.has_cancel_handle("L" * 43, now=NOW + 300)
    store.consume(second.browser_binding, second.state, now=NOW + 300)
    assert store._pending == store._cancellations == store._handles_by_binding == {}


def test_lookup_expiry_races_with_cancel_without_index_leak() -> None:
    store = InMemoryAuthorizationAttemptStore()
    store.save(pending(), now=NOW)
    gate = Barrier(2)

    def lookup() -> bool:
        gate.wait(timeout=5)
        return store.has_cancel_handle(HANDLE, now=NOW + 300)

    def cancel() -> bool:
        gate.wait(timeout=5)
        try:
            store.cancel(HANDLE, now=NOW + 299)
            return True
        except AuthenticationFlowError:
            return False

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(lookup)
        second = executor.submit(cancel)
        assert first.result(timeout=5) is False
        assert second.result(timeout=5) in {True, False}
    assert store._pending == store._cancellations == store._handles_by_binding == {}
