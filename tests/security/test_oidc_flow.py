"""Adversarial offline callback, expiry, resource and replay tests."""

from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlsplit

import pytest

from asca.application.identity import OidcAuthorizationService, OidcClientConfiguration
from asca.domain.identity import AuthenticationFlowError, PendingAuthorization
from asca.infrastructure.identity_memory import InMemoryAuthorizationAttemptStore


@pytest.fixture
def flow() -> tuple[OidcAuthorizationService, InMemoryAuthorizationAttemptStore, list[float]]:
    now = [100.0]
    config = OidcClientConfiguration(
        issuer="https://auth.example.invalid/realms/test",
        authorization_endpoint="https://auth.example.invalid/authorize",
        client_id="mock-client",
        redirect_uri="http://127.0.0.1:8000/callback",
    )
    store = InMemoryAuthorizationAttemptStore()
    return OidcAuthorizationService(config, store, clock=lambda: now[0]), store, now


def _state(start_url: str) -> str:
    return parse_qs(urlsplit(start_url).query)["state"][0]


def test_wrong_browser_binding_cannot_consume_attempt(
    flow: tuple[OidcAuthorizationService, InMemoryAuthorizationAttemptStore, list[float]],
) -> None:
    service, _, _ = flow
    start = service.begin()
    with pytest.raises(AuthenticationFlowError, match="Invalid or expired"):
        service.finish(
            browser_binding="attacker", state=_state(start.authorization_url), code="code"
        )
    assert (
        service.finish(
            browser_binding=start.browser_binding,
            state=_state(start.authorization_url),
            code="code",
        ).code
        == "code"
    )


def test_modified_state_cannot_consume_attempt(
    flow: tuple[OidcAuthorizationService, InMemoryAuthorizationAttemptStore, list[float]],
) -> None:
    service, _, _ = flow
    start = service.begin()
    with pytest.raises(AuthenticationFlowError, match="state mismatch"):
        service.finish(browser_binding=start.browser_binding, state="tampered", code="code")
    assert (
        service.finish(
            browser_binding=start.browser_binding,
            state=_state(start.authorization_url),
            code="code",
        ).code
        == "code"
    )


def test_callback_cannot_be_replayed(
    flow: tuple[OidcAuthorizationService, InMemoryAuthorizationAttemptStore, list[float]],
) -> None:
    service, _, _ = flow
    start = service.begin()
    kwargs = {
        "browser_binding": start.browser_binding,
        "state": _state(start.authorization_url),
        "code": "code",
    }
    service.finish(**kwargs)
    with pytest.raises(AuthenticationFlowError, match="Invalid or expired"):
        service.finish(**kwargs)


def test_expired_callback_rejected_and_removed(
    flow: tuple[OidcAuthorizationService, InMemoryAuthorizationAttemptStore, list[float]],
) -> None:
    service, _, now = flow
    start = service.begin()
    now[0] += 300.0
    with pytest.raises(AuthenticationFlowError, match="Invalid or expired"):
        service.finish(
            browser_binding=start.browser_binding,
            state=_state(start.authorization_url),
            code="code",
        )
    with pytest.raises(AuthenticationFlowError, match="Invalid or expired"):
        service.finish(
            browser_binding=start.browser_binding,
            state=_state(start.authorization_url),
            code="code",
        )


def test_issuer_mismatch_rejected_and_can_retry(
    flow: tuple[OidcAuthorizationService, InMemoryAuthorizationAttemptStore, list[float]],
) -> None:
    service, _, _ = flow
    start = service.begin()
    with pytest.raises(AuthenticationFlowError, match="issuer"):
        service.finish(
            browser_binding=start.browser_binding,
            state=_state(start.authorization_url),
            code="code",
            response_issuer="https://imposter.example.invalid",
        )
    assert (
        service.finish(
            browser_binding=start.browser_binding,
            state=_state(start.authorization_url),
            code="code",
        ).code
        == "code"
    )


def test_provider_decline_consumes_attempt(
    flow: tuple[OidcAuthorizationService, InMemoryAuthorizationAttemptStore, list[float]],
) -> None:
    service, _, _ = flow
    start = service.begin()
    with pytest.raises(AuthenticationFlowError, match="not granted"):
        service.finish(
            browser_binding=start.browser_binding,
            state=_state(start.authorization_url),
            error="access_denied",
        )
    with pytest.raises(AuthenticationFlowError, match="Invalid or expired"):
        service.finish(
            browser_binding=start.browser_binding,
            state=_state(start.authorization_url),
            code="code",
        )


@pytest.mark.parametrize(
    "code,error", [(None, None), ("code", "access_denied"), ("", None), (None, "")]
)
def test_incomplete_or_ambiguous_callback_rejected(
    flow: tuple[OidcAuthorizationService, InMemoryAuthorizationAttemptStore, list[float]],
    code: str | None,
    error: str | None,
) -> None:
    service, _, _ = flow
    start = service.begin()
    with pytest.raises(AuthenticationFlowError, match="Invalid authorization callback"):
        service.finish(
            browser_binding=start.browser_binding,
            state=_state(start.authorization_url),
            code=code,
            error=error,
        )


def test_store_purges_expired_before_capacity_check() -> None:
    store = InMemoryAuthorizationAttemptStore(max_pending=1)
    first = PendingAuthorization("a", "s1", "n1", "v1", 0, 10)
    second = PendingAuthorization("b", "s2", "n2", "v2", 10, 20)
    store.save(first, now=0)
    with pytest.raises(AuthenticationFlowError, match="limit"):
        store.save(second, now=5)
    store.save(second, now=10)
    assert store.consume("b", "s2", now=11) == second


def test_store_rejects_duplicate_and_expired_entries() -> None:
    store = InMemoryAuthorizationAttemptStore()
    attempt = PendingAuthorization("a", "s1", "n1", "v1", 0, 10)
    store.save(attempt, now=1)
    with pytest.raises(AuthenticationFlowError, match="Duplicate"):
        store.save(attempt, now=2)
    with pytest.raises(AuthenticationFlowError, match="Invalid or expired"):
        store.save(PendingAuthorization("b", "s2", "n2", "v2", 0, 2), now=3)


def test_store_capacity_bounds() -> None:
    with pytest.raises(ValueError, match="max_pending"):
        InMemoryAuthorizationAttemptStore(max_pending=0)
    with pytest.raises(ValueError, match="max_pending"):
        InMemoryAuthorizationAttemptStore(max_pending=100_001)


def test_concurrent_replay_exactly_one_consumer_wins(
    flow: tuple[OidcAuthorizationService, InMemoryAuthorizationAttemptStore, list[float]],
) -> None:
    service, _, _ = flow
    start = service.begin()
    state = _state(start.authorization_url)

    def redeem(_: int) -> bool:
        try:
            service.finish(browser_binding=start.browser_binding, state=state, code="code")
        except AuthenticationFlowError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=12) as pool:
        assert sum(pool.map(redeem, range(60))) == 1


def test_sensitive_values_are_not_in_object_representations(
    flow: tuple[OidcAuthorizationService, InMemoryAuthorizationAttemptStore, list[float]],
) -> None:
    service, store, _ = flow
    start = service.begin()
    pending = store.consume(start.browser_binding, _state(start.authorization_url), now=101)
    assert pending.state not in repr(pending)
    assert pending.nonce not in repr(pending)
    assert pending.code_verifier not in repr(pending)
    assert pending.browser_binding not in repr(pending)
