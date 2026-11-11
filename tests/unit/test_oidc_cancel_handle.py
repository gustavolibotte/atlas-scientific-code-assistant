"""Opaque authorization-attempt cancellation: deterministic offline unit tests."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from threading import Barrier
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest

from asca.application.identity import OidcAuthorizationService, OidcClientConfiguration
from asca.domain.identity import AuthenticationFlowError, PendingAuthorization
from asca.infrastructure.identity_memory import InMemoryAuthorizationAttemptStore

NOW = 1800000000.0


def make(*, max_pending: int = 256):
    store = InMemoryAuthorizationAttemptStore(max_pending=max_pending)
    config = OidcClientConfiguration(
        issuer="https://issuer.example.invalid/realm",
        authorization_endpoint="https://issuer.example.invalid/realm/auth",
        client_id="offline-only-client",
        redirect_uri="http://127.0.0.1:8080/oidc/callback",
    )
    return OidcAuthorizationService(config, store, clock=lambda: NOW), store


def state_of(url: str) -> str:
    return parse_qs(urlsplit(url).query)["state"][0]


def test_capability_is_random_and_never_embedded_in_url_or_repr() -> None:
    service, store = make()
    first, second = service.begin(), service.begin()
    assert type(first.cancellation_handle) is str
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", first.cancellation_handle)
    assert first.cancellation_handle != second.cancellation_handle
    assert first.cancellation_handle not in first.authorization_url
    assert first.cancellation_handle not in repr(first)
    assert first.cancellation_handle not in repr(next(iter(store._pending.values())))
    assert first.browser_binding not in first.authorization_url
    assert first.cancellation_handle != first.browser_binding
    assert first.cancellation_handle != state_of(first.authorization_url)


def test_cancellation_is_independent_of_state_and_binding() -> None:
    service, store = make()
    attempt = service.begin()
    assert attempt.cancellation_handle is not None
    store.cancel(attempt.cancellation_handle)
    assert store._pending == {}
    assert store._cancellations == {}
    assert store._handles_by_binding == {}
    with pytest.raises(AuthenticationFlowError):
        service.finish(
            browser_binding=attempt.browser_binding,
            state=state_of(attempt.authorization_url),
            code="synthetic-code",
        )


def test_consuming_a_success_invalidates_the_cancellation_handle() -> None:
    service, store = make()
    attempt = service.begin()
    service.finish(
        browser_binding=attempt.browser_binding,
        state=state_of(attempt.authorization_url),
        code="synthetic-code",
    )
    with pytest.raises(AuthenticationFlowError):
        store.cancel(attempt.cancellation_handle or "")
    assert store._pending == store._cancellations == store._handles_by_binding == {}


def test_consumed_denial_invalidates_the_cancellation_handle() -> None:
    service, store = make()
    attempt = service.begin()
    with pytest.raises(AuthenticationFlowError, match="not granted"):
        service.finish(
            browser_binding=attempt.browser_binding,
            state=state_of(attempt.authorization_url),
            error="access_denied",
        )
    with pytest.raises(AuthenticationFlowError):
        store.cancel(attempt.cancellation_handle or "")
    assert store._pending == {}


def test_wrong_state_does_not_consume_and_correct_handle_still_cancels() -> None:
    service, store = make()
    attempt = service.begin()
    with pytest.raises(AuthenticationFlowError):
        service.finish(browser_binding=attempt.browser_binding, state="wrong", code="code")
    assert len(store._pending) == 1
    store.cancel(attempt.cancellation_handle or "")
    assert not store._pending


def test_wrong_cancel_handle_cannot_cancel_another_attempt() -> None:
    service, store = make()
    first, second = service.begin(), service.begin()
    with pytest.raises(AuthenticationFlowError):
        store.cancel("A" * 43)
    store.cancel(first.cancellation_handle or "")
    service.finish(
        browser_binding=second.browser_binding,
        state=state_of(second.authorization_url),
        code="synthetic-code",
    )
    assert not store._pending


@pytest.mark.parametrize(
    "invalid",
    ["", "x", "A" * 42, "A" * 129, "!" * 43, "a" * 42 + "=", "a" * 42 + "/", None, 7, True],
)
def test_bad_cancel_capability_is_rejected_without_mutation(invalid: object) -> None:
    service, store = make()
    attempt = service.begin()
    with pytest.raises(AuthenticationFlowError):
        store.cancel(invalid)  # type: ignore[arg-type]
    assert len(store._pending) == 1
    store.cancel(attempt.cancellation_handle or "")
    assert not store._pending


def test_duplicate_cancel_cannot_revive_any_entry() -> None:
    service, store = make()
    attempt = service.begin()
    token = attempt.cancellation_handle or ""
    store.cancel(token)
    with pytest.raises(AuthenticationFlowError):
        store.cancel(token)
    assert not store._pending


def test_cancelling_a_second_attempt_does_not_cancel_the_first() -> None:
    service, store = make()
    first, second = service.begin(), service.begin()
    store.cancel(second.cancellation_handle or "")
    service.finish(
        browser_binding=first.browser_binding,
        state=state_of(first.authorization_url),
        code="synthetic-code",
    )
    assert not store._pending


def test_expiry_clears_both_indexes() -> None:
    service, store = make()
    first = service.begin()
    assert first.cancellation_handle is not None
    with pytest.raises(AuthenticationFlowError):
        store.consume(first.browser_binding, state_of(first.authorization_url), now=NOW + 1000)
    assert not store._pending and not store._cancellations
    with pytest.raises(AuthenticationFlowError):
        store.cancel(first.cancellation_handle)


def test_purge_expired_removes_cancel_handle() -> None:
    service, store = make()
    first = service.begin()
    new = PendingAuthorization("other-binding", "state", "nonce", "verifier", NOW + 500, NOW + 900)
    store.save(new, now=NOW + 500)
    assert len(store._pending) == 1
    with pytest.raises(AuthenticationFlowError):
        store.cancel(first.cancellation_handle or "")


def test_duplicate_cancel_handle_is_rejected_before_insertion() -> None:
    service, store = make()
    first = service.begin()
    duplicate = PendingAuthorization(
        "other-binding",
        "other-state",
        "nonce",
        "verifier",
        NOW,
        NOW + 300,
        first.cancellation_handle,
    )
    with pytest.raises(AuthenticationFlowError):
        store.save(duplicate, now=NOW)
    assert len(store._pending) == 1


def test_full_store_rejects_extra_attempt_without_leaking_cancel_index() -> None:
    service, store = make(max_pending=1)
    first = service.begin()
    with pytest.raises(AuthenticationFlowError):
        service.begin()
    assert len(store._pending) == len(store._cancellations) == 1
    store.cancel(first.cancellation_handle or "")
    assert not store._pending


def test_url_build_failure_revokes_newly_stored_attempt() -> None:
    service, store = make()
    with (
        patch.object(service, "_build_authorization_start", side_effect=RuntimeError("secret")),
        pytest.raises(RuntimeError, match="secret"),
    ):
        service.begin()
    assert store._pending == store._cancellations == store._handles_by_binding == {}


def test_attempt_fields_are_immutable_and_cancel_handle_not_repr() -> None:
    service, store = make()
    attempt = service.begin()
    item = next(iter(store._pending.values()))
    with pytest.raises(FrozenInstanceError):
        item.cancellation_handle = "changed"  # type: ignore[misc]
    assert attempt.cancellation_handle not in repr(item)


def test_collision_in_binding_key_does_not_create_orphaned_cancel_index() -> None:
    service, store = make()
    first = service.begin()
    existing = next(iter(store._pending.values()))
    with pytest.raises(AuthenticationFlowError):
        store.save(existing, now=NOW)
    assert len(store._pending) == len(store._cancellations) == 1
    store.cancel(first.cancellation_handle or "")
    assert not store._pending


def test_cancel_competes_atomically_with_callback_consumption() -> None:
    service, store = make()
    attempt = service.begin()
    gate = Barrier(2)

    def finish():
        gate.wait(timeout=3)
        try:
            service.finish(
                browser_binding=attempt.browser_binding,
                state=state_of(attempt.authorization_url),
                code="synthetic-code",
            )
            return "consumed"
        except AuthenticationFlowError:
            return "lost"

    def cancel():
        gate.wait(timeout=3)
        try:
            store.cancel(attempt.cancellation_handle or "")
            return "cancelled"
        except AuthenticationFlowError:
            return "lost"

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(finish)
        b = pool.submit(cancel)
        results = {a.result(timeout=3), b.result(timeout=3)}
    assert results in ({"consumed", "lost"}, {"cancelled", "lost"})
    assert store._pending == store._cancellations == store._handles_by_binding == {}
