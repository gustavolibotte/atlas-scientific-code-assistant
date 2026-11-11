"""Adversarial offline verification of independent native OIDC cancellation."""

from __future__ import annotations

import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest

from asca.application.identity import AuthorizationStart
from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.identity import AuthenticationFlowError
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_native_host import OidcNativeHostError
from asca.domain.oidc_native_lifecycle import NativeCallbackDenied
from asca.domain.oidc_token_http import UnverifiedOidcTokenHttpResponse
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken
from asca.infrastructure.oidc_native_host import CernNativeOidcHostTransaction
from asca.infrastructure.oidc_token_http import HttpsOidcTokenTransport
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

NOW = 1800000000.0


def provider() -> OidcProviderMetadata:
    return OidcProviderMetadata(
        issuer=CERN_OIDC_ISSUER,
        authorization_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        token_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        jwks_uri=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        approved_id_token_algorithms=("RS256", "PS256"),
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )


class OfflineTransport(HttpsOidcTokenTransport):
    def __init__(self) -> None:
        self.calls = 0
        self.on_exchange = None

    def exchange(self, prepared: object, client: object) -> UnverifiedOidcTokenHttpResponse:
        self.calls += 1
        if self.on_exchange is not None:
            self.on_exchange()
        return UnverifiedOidcTokenHttpResponse(
            body=json.dumps(
                {"access_token": "synthetic", "token_type": "Bearer", "id_token": "a.b.c"}
            ).encode("ascii")
        )


class OfflineVerifier(CernOidcVerificationPipeline):
    def __init__(self) -> None:
        self.calls = 0

    def check(
        self,
        tokens: object,
        metadata: object,
        *,
        expected_client_id: str,
        expected_nonce: str,
        now: int,
        **_kwargs: object,
    ) -> CheckedUntrustedCernOidcToken:
        assert tokens is not None and metadata is not None and expected_nonce
        self.calls += 1
        return CheckedUntrustedCernOidcToken(
            issuer=CERN_OIDC_ISSUER,
            subject="offline-identity-not-trusted",
            audiences=(expected_client_id,),
            expires_at=now + 300,
            algorithm="RS256",
            kid="synthetic",
            source_url=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        )


def build(**kwargs: object):
    transport = OfflineTransport()
    verifier = OfflineVerifier()
    now = [NOW]
    options: dict[str, object] = {
        "host": "127.0.0.1",
        "client_id": "offline-cancellation-test-client",
        "metadata": provider(),
        "transport": transport,
        "verifier": verifier,
        "clock": lambda: now[0],
        "timeout_seconds": 0.7,
        "per_connection_seconds": 0.1,
        "max_connections": 4,
    }
    options.update(kwargs)
    host = CernNativeOidcHostTransaction(**options)  # type: ignore[arg-type]
    return host, transport, verifier, now


def start(host: CernNativeOidcHostTransaction) -> str:
    return parse_qs(urlsplit(host.begin().authorization_url).query)["state"][0]


def send(host: CernNativeOidcHostTransaction, *, state: str, action: str) -> bytes:
    uri = urlsplit(host.binding.redirect_uri)
    data = (f"GET {uri.path}?state={state}&{action} HTTP/1.1\r\nHost: {uri.netloc}\r\n\r\n").encode(
        "ascii"
    )
    with socket.create_connection((host.binding.host, host.binding.port), timeout=0.5) as conn:
        conn.settimeout(1.0)
        conn.sendall(data)
        response = bytearray()
        while chunk := conn.recv(4096):
            response.extend(chunk)
        return bytes(response)


def assert_empty(host: CernNativeOidcHostTransaction) -> None:
    store = host._exchange._store
    assert store._pending == store._cancellations == store._handles_by_binding == {}
    assert host._exchange._pending_cancel_handles == set()


@pytest.mark.parametrize(
    "forgery",
    [
        "missing-state",
        "duplicate-state",
        "wrong-state",
        "no-url",
        "wrong-binding",
        "non-url",
        "fragment",
        "extra",
        "long",
        "bad-method",
    ],
)
def test_failed_start_cancels_even_when_url_cannot_supply_state(forgery: str) -> None:
    host, transport, verifier, _ = build()
    with host:
        original = host._lifecycle.begin

        def tamper() -> AuthorizationStart:
            began = original()
            url = began.authorization_url
            binding = began.browser_binding
            if forgery == "missing-state":
                url = url.replace("state=", "notstate=", 1)
            elif forgery == "duplicate-state":
                url += "&state=" + "X" * 43
            elif forgery == "wrong-state":
                url = url.replace("state=", "state=%2F", 1)
            elif forgery == "no-url":
                url = ""
            elif forgery == "wrong-binding":
                binding = "bad"
            elif forgery == "non-url":
                url = "https://evil.invalid/not-valid"
            elif forgery == "fragment":
                url += "#malformed"
            elif forgery == "extra":
                url += "&unsupported=1"
            elif forgery == "long":
                url += "A" * 9000
            elif forgery == "bad-method":
                url = url.replace("code_challenge_method=S256", "code_challenge_method=plain")
            # The original exchange already recorded its independent capability;
            # a forged upstream return value cannot overwrite that private index.
            return AuthorizationStart(url, binding)

        with patch.object(host._lifecycle, "begin", tamper), pytest.raises(OidcNativeHostError):
            host.begin()
        assert host.closed
        assert_empty(host)
        assert transport.calls == verifier.calls == 0


def test_cancel_succeeds_even_if_host_state_is_destroyed() -> None:
    host, transport, verifier, _ = build()
    with host:
        start(host)
        host._state = None
        host._browser_binding = None
        host.close()
        assert_empty(host)
    assert transport.calls == verifier.calls == 0


def test_cancellation_does_not_use_reject_callback_or_url_state() -> None:
    host, transport, _, _ = build()
    with host:
        start(host)
        with patch.object(host._exchange, "reject_callback", side_effect=AssertionError("bad")):
            host.close()
        assert_empty(host)
    assert transport.calls == 0


def test_host_multiple_closes_stay_terminal_and_leave_no_orphans() -> None:
    host, transport, verifier, _ = build()
    with host:
        start(host)
        for _ in range(5):
            host.close()
            assert_empty(host)
    assert transport.calls == verifier.calls == 0


def test_callback_success_discards_cancel_capability() -> None:
    host, transport, verifier, _ = build()
    with host:
        state = start(host)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(host.complete)
            assert send(host, state=state, action="code=synthetic-code").startswith(b"HTTP/1.1 202")
            result = future.result(timeout=2)
            assert result.subject == "offline-identity-not-trusted"
    assert_empty(host)
    assert transport.calls == verifier.calls == 1


def test_callback_denial_discards_cancel_capability() -> None:
    host, transport, verifier, _ = build()
    with host:
        state = start(host)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(host.complete)
            assert send(host, state=state, action="error=access_denied").startswith(b"HTTP/1.1 202")
            assert future.result(timeout=2) == NativeCallbackDenied()
    assert_empty(host)
    assert transport.calls == verifier.calls == 0


def test_wrong_state_fails_and_cancel_index_is_removed() -> None:
    host, transport, verifier, _ = build()
    with host:
        start(host)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(host.complete)
            assert send(host, state="X" * 43, action="code=synthetic").startswith(b"HTTP/1.1 202")
            with pytest.raises(OidcNativeHostError):
                future.result(timeout=2)
    assert_empty(host)
    assert transport.calls == verifier.calls == 0


def test_expired_callback_has_no_surviving_cancel_index() -> None:
    host, transport, verifier, clock = build()
    with host:
        state = start(host)
        clock[0] += 1000
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(host.complete)
            assert send(host, state=state, action="code=synthetic").startswith(b"HTTP/1.1 202")
            with pytest.raises(OidcNativeHostError):
                future.result(timeout=2)
    assert_empty(host)
    assert transport.calls == verifier.calls == 0


def test_parallel_close_and_complete_cannot_reuse_transaction() -> None:
    host, transport, verifier, _ = build(timeout_seconds=1.5)
    with host:
        start(host)
        with ThreadPoolExecutor(max_workers=2) as pool:
            waiting = pool.submit(host.complete)
            time.sleep(0.02)
            cancelled = pool.submit(host.close)
            cancelled.result(timeout=2)
            with pytest.raises(OidcNativeHostError):
                waiting.result(timeout=2)
        assert_empty(host)
    assert transport.calls == verifier.calls == 0


def test_concurrent_close_cannot_return_during_token_exchange() -> None:
    host, transport, verifier, _ = build()
    busy, release = threading.Event(), threading.Event()

    def block_exchange() -> None:
        busy.set()
        assert release.wait(timeout=2)

    transport.on_exchange = block_exchange
    with host:
        state = start(host)
        with ThreadPoolExecutor(max_workers=2) as pool:
            completed = pool.submit(host.complete)
            assert send(host, state=state, action="code=synthetic").startswith(b"HTTP/1.1 202")
            assert busy.wait(timeout=1)
            cancelled = pool.submit(host.close)
            time.sleep(0.03)
            assert not cancelled.done()
            release.set()
            assert completed.result(timeout=2).subject == "offline-identity-not-trusted"
            cancelled.result(timeout=2)
    assert_empty(host)
    assert transport.calls == verifier.calls == 1


def test_cancel_exchange_is_idempotent_even_without_host_start() -> None:
    host, transport, _, _ = build()
    with host:
        host._exchange.cancel_pending()
        host._exchange.cancel_pending()
        assert_empty(host)
    assert transport.calls == 0


def test_native_exchange_records_only_non_url_cancel_handles() -> None:
    host, _, _, _ = build()
    with host:
        state = start(host)
        handles = host._exchange._pending_cancel_handles
        assert len(handles) == 1
        handle = next(iter(handles))
        assert handle != state
        assert handle != host._browser_binding
        assert handle not in host._registration_snapshot.redirect_uri
        host.close()
        assert_empty(host)


def test_cancelled_attempt_cannot_be_replayed_through_lower_level_exchange() -> None:
    host, transport, verifier, _ = build()
    with host:
        state = start(host)
        binding = host._browser_binding
        host.close()
        with pytest.raises(ValueError):
            host._exchange.exchange_callback(
                browser_binding=binding,
                state=state,
                code="synthetic",
            )
    assert_empty(host)
    assert transport.calls == verifier.calls == 0


def test_cancel_cannot_consume_unrelated_store_pending() -> None:
    host, transport, _, _ = build()
    with host:
        state = start(host)
        secret = next(iter(host._exchange._pending_cancel_handles))
        with pytest.raises(AuthenticationFlowError):
            host._exchange._store.cancel("Z" * 43)
        assert len(host._exchange._store._pending) == 1
        assert state and secret
        host.close()
        assert_empty(host)
    assert transport.calls == 0


def test_repeated_native_attempts_do_not_accumulate_stale_cancel_handles() -> None:
    host, transport, verifier, _ = build()
    with host:
        exchange = host._exchange
        for _ in range(25):
            started = exchange.begin()
            state = parse_qs(urlsplit(started.authorization_url).query)["state"][0]
            assert started.cancellation_handle is not None
            assert exchange._store.has_cancel_handle(started.cancellation_handle)
            exchange.reject_callback(
                browser_binding=started.browser_binding,
                state=state,
                error="access_denied",
            )
            assert not exchange._store._pending
            assert len(exchange._pending_cancel_handles) <= 1
        exchange.cancel_pending()
        assert_empty(host)
    assert transport.calls == verifier.calls == 0
