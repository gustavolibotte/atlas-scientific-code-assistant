"""Adversarial lifecycle transitions without real CERN traffic or OS listeners."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier
from urllib.parse import parse_qs, urlsplit

import pytest

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_native_callback import NativeLoopbackHttpRequest
from asca.domain.oidc_native_exchange import OidcNativeExchangeError
from asca.domain.oidc_native_lifecycle import OidcNativeLifecycleError
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.domain.oidc_token_http import UnverifiedOidcTokenHttpResponse
from asca.domain.oidc_token_request import UnsentOidcTokenRequest
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken
from asca.infrastructure.oidc_native_exchange import CernOidcNativeCodeExchange
from asca.infrastructure.oidc_native_lifecycle import CernNativeCallbackLifecycle
from asca.infrastructure.oidc_token_http import HttpsOidcTokenTransport
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

NOW = 1_800_000_000.0
CLIENT = "offline-lifecycle-client"
DENIAL = "access_denied"


def registration(host: str = "127.0.0.1") -> OidcClientRegistration:
    authority = "[::1]" if host == "::1" else host
    return OidcClientRegistration(
        client_id=CLIENT,
        redirect_uri=f"http://{authority}:45921/oidc/callback",
        mode=OidcClientMode.NATIVE_LOOPBACK,
    )


def metadata() -> OidcProviderMetadata:
    return OidcProviderMetadata(
        issuer=CERN_OIDC_ISSUER,
        authorization_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        token_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        jwks_uri=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        approved_id_token_algorithms=("RS256", "PS256", "ES256"),
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )


class FakeTransport(HttpsOidcTokenTransport):
    def __init__(self) -> None:
        self.requests: list[UnsentOidcTokenRequest] = []
        self.fail = False

    def exchange(
        self, prepared: UnsentOidcTokenRequest, client: OidcClientRegistration
    ) -> UnverifiedOidcTokenHttpResponse:
        assert client.client_id == CLIENT
        self.requests.append(prepared)
        if self.fail:
            raise ValueError("sensitive-transport-failure")
        body = json.dumps(
            {"access_token": "synthetic-token", "token_type": "Bearer", "id_token": "a.b.c"}
        ).encode("utf-8")
        return UnverifiedOidcTokenHttpResponse(body=body)


class FakeVerifier(CernOidcVerificationPipeline):
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.fail = False

    def check(
        self,
        tokens: object,
        provider: object,
        *,
        expected_client_id: str,
        expected_nonce: str,
        now: int,
        **_kwargs: object,
    ) -> CheckedUntrustedCernOidcToken:
        assert provider == metadata()
        assert tokens is not None
        self.calls.append((expected_client_id, expected_nonce))
        if self.fail:
            raise ValueError("sensitive-verifier-failure")
        return CheckedUntrustedCernOidcToken(
            issuer=CERN_OIDC_ISSUER,
            subject="synthetic-subject",
            audiences=(expected_client_id,),
            expires_at=now + 200,
            algorithm="RS256",
            kid="synthetic-kid",
            source_url=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        )


def make(host: str = "127.0.0.1", *, ttl: int = 300):
    clock = [NOW]
    transport = FakeTransport()
    verifier = FakeVerifier()
    exchange = CernOidcNativeCodeExchange(
        registration(host),
        metadata(),
        transport=transport,
        verifier=verifier,
        clock=lambda: clock[0],
        ttl_seconds=ttl,
    )
    lifecycle = CernNativeCallbackLifecycle(exchange)
    return lifecycle, exchange, transport, verifier, clock


def start(lifecycle: CernNativeCallbackLifecycle) -> tuple[str, str]:
    started = lifecycle.begin()
    state = parse_qs(urlsplit(started.authorization_url).query)["state"][0]
    return started.browser_binding, state


def request(state: str, *, host: str = "127.0.0.1", **changes: object):
    authority = f"[{host}]:45921" if ":" in host else f"{host}:45921"
    values: dict[str, object] = {
        "method": "GET",
        "request_target": f"/oidc/callback?state={state}&error={DENIAL}",
        "http_version": "HTTP/1.1",
        "headers": (("Host", authority),),
        "peer_ip": host,
        "local_ip": host,
        "local_port": 45921,
        "body": b"",
    }
    values.update(changes)
    return NativeLoopbackHttpRequest(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "protected_binding",
    [
        "",
        "x",
        "a" * 42,
        "a" * 129,
        "with space" * 5,
        "x" * 43 + "=",
        None,
        1,
        True,
        {},
        [],
    ],
)
def test_untrusted_or_invalid_binding_is_rejected_without_consuming(
    protected_binding: object,
) -> None:
    lifecycle, _, transport, _, _ = make()
    binding, state = start(lifecycle)
    with pytest.raises(OidcNativeLifecycleError):
        lifecycle.complete(
            request=request(state),
            protected_binding=protected_binding,  # type: ignore[arg-type]
        )
    assert lifecycle.complete(request=request(state), protected_binding=binding).status
    assert transport.requests == []


@pytest.mark.parametrize(
    "suffix",
    [
        "&error=other",
        "&code=synthetic-code",
        "&state=Z",
        "&foo=1",
        "&error_description=secret",
        "&iss=https://evil.invalid",
        "&error=access_denied%0Ainjection",
        "&error=access+denied",
        "&error_uri=https://evil.invalid",
        "&error=",
        "&iss=",
        "&state=",
        "&error=x%ZZ",
        "&token=attack",
        "&code_verifier=attack",
        "&browser_binding=attack",
        "&redirect_uri=x",
    ],
)
def test_malicious_or_ambiguous_denial_query_does_not_consume(suffix: str) -> None:
    lifecycle, _, transport, _, _ = make()
    binding, state = start(lifecycle)
    altered = request(
        state,
        request_target=f"/oidc/callback?state={state}&error=access_denied{suffix}",
    )
    with pytest.raises(OidcNativeLifecycleError):
        lifecycle.complete(request=altered, protected_binding=binding)
    assert lifecycle.complete(request=request(state), protected_binding=binding).status
    assert transport.requests == []


@pytest.mark.parametrize(
    "change",
    [
        {"method": "POST"},
        {"method": "get"},
        {"body": b"abc"},
        {"peer_ip": "1.2.3.4"},
        {"local_ip": "8.8.8.8"},
        {"local_port": 8000},
        {"http_version": "HTTP/2"},
        {"headers": (("Host", "127.0.0.1:45921"), ("Host", "127.0.0.1:45921"))},
        {"headers": (("Host", "127.0.0.1:45921"), ("X-Forwarded-For", "127.0.0.1"))},
        {"headers": (("Host", "localhost:45921"),)},
        {"request_target": "/wrong?state=abc&error=x"},
        {"request_target": "http://localhost:45921/oidc/callback?state=abc&error=x"},
    ],
)
def test_malformed_http_envelope_is_rejected_without_consumption(change: dict[str, object]) -> None:
    lifecycle, _, transport, _, _ = make()
    binding, state = start(lifecycle)
    malicious = request(state, **change)
    with pytest.raises(OidcNativeLifecycleError):
        lifecycle.complete(request=malicious, protected_binding=binding)
    assert lifecycle.complete(request=request(state), protected_binding=binding).status
    assert transport.requests == []


def test_concurrent_repeated_denials_exactly_one_consumes() -> None:
    lifecycle, _, transport, verifier, _ = make()
    binding, state = start(lifecycle)
    barrier = Barrier(24)

    def worker(_index: int) -> bool:
        barrier.wait()
        try:
            lifecycle.complete(request=request(state), protected_binding=binding)
            return True
        except OidcNativeLifecycleError:
            return False

    with ThreadPoolExecutor(max_workers=24) as pool:
        results = list(pool.map(worker, range(24)))
    assert results.count(True) == 1
    assert transport.requests == [] and verifier.calls == []


def test_concurrent_success_and_denial_never_both_consume() -> None:
    lifecycle, _, transport, verifier, _ = make()
    binding, state = start(lifecycle)
    barrier = Barrier(2)

    def worker(deny: bool) -> str:
        incoming = request(
            state,
            request_target=(
                f"/oidc/callback?state={state}&"
                + ("error=access_denied" if deny else "code=synthetic-code")
            ),
        )
        barrier.wait()
        try:
            result = lifecycle.complete(request=incoming, protected_binding=binding)
            return "denied" if deny else "exchanged" if result.subject else "invalid"
        except OidcNativeLifecycleError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(worker, [True, False]))
    assert outcomes.count("rejected") == 1
    assert outcomes.count("denied") + outcomes.count("exchanged") == 1
    assert len(transport.requests) <= 1
    assert len(verifier.calls) <= 1
    assert not ("denied" in outcomes and "exchanged" in outcomes)


def test_mismatched_callback_uri_rejected_before_store_consumption() -> None:
    lifecycle, exchange, transport, _, _ = make()
    binding, state = start(lifecycle)
    changed = registration("::1")
    object.__setattr__(exchange, "_registration", changed)
    with pytest.raises(OidcNativeLifecycleError):
        lifecycle.complete(request=request(state), protected_binding=binding)
    assert transport.requests == []


def test_denial_uses_same_store_as_existing_success_service() -> None:
    lifecycle, exchange, transport, _, _ = make()
    binding, state = start(lifecycle)
    assert (
        exchange.reject_callback(browser_binding=binding, state=state, error="access_denied")
        is None
    )
    with pytest.raises(OidcNativeLifecycleError):
        lifecycle.complete(request=request(state), protected_binding=binding)
    assert transport.requests == []


def test_consumed_state_does_not_recover_after_http_transport_failure() -> None:
    lifecycle, _, transport, _, _ = make()
    binding, state = start(lifecycle)
    transport.fail = True
    incoming = request(state, request_target=f"/oidc/callback?state={state}&code=synthetic-code")
    with pytest.raises(OidcNativeLifecycleError):
        lifecycle.complete(request=incoming, protected_binding=binding)
    transport.fail = False
    with pytest.raises(OidcNativeLifecycleError):
        lifecycle.complete(request=request(state), protected_binding=binding)
    assert len(transport.requests) == 1


def test_prohibited_secret_information_absent_from_denial_error() -> None:
    lifecycle, _, _, _, _ = make()
    binding, state = start(lifecycle)
    with pytest.raises(OidcNativeLifecycleError) as captured:
        lifecycle.complete(
            request=request(
                state, request_target=f"/oidc/callback?state={state}&error=x&foo=secret"
            ),
            protected_binding=binding,
        )
    for secret in (binding, state, "secret", "x&foo"):
        assert secret not in str(captured.value)
        assert secret not in repr(captured.value)


def test_public_denial_api_rejects_invalid_issuer_without_consuming() -> None:
    lifecycle, exchange, transport, _, _ = make()
    binding, state = start(lifecycle)
    with pytest.raises(OidcNativeExchangeError) as captured:
        exchange.reject_callback(
            browser_binding=binding,
            state=state,
            error="access_denied",
            response_issuer=CERN_OIDC_ISSUER + "/other",
        )
    assert "other" not in str(captured.value)
    assert lifecycle.complete(request=request(state), protected_binding=binding).status
    assert transport.requests == []


@pytest.mark.parametrize("error", ["", "not allowed", "ä", "!", "a" * 129, None, 1, True])
def test_public_denial_api_rejects_invalid_error_without_consuming(error: object) -> None:
    lifecycle, exchange, transport, _, _ = make()
    binding, state = start(lifecycle)
    with pytest.raises(OidcNativeExchangeError):
        exchange.reject_callback(
            browser_binding=binding,
            state=state,
            error=error,  # type: ignore[arg-type]
        )
    assert lifecycle.complete(request=request(state), protected_binding=binding).status
    assert transport.requests == []


@pytest.mark.parametrize("state", ["", "nope", "Z" * 43, None, True, 4])
def test_public_denial_api_rejects_wrong_state_without_consuming(state: object) -> None:
    lifecycle, exchange, _, _, _ = make()
    binding, actual = start(lifecycle)
    with pytest.raises(OidcNativeExchangeError):
        exchange.reject_callback(
            browser_binding=binding,
            state=state,
            error="access_denied",  # type: ignore[arg-type]
        )
    assert lifecycle.complete(request=request(actual), protected_binding=binding).status


def test_public_denial_api_rejects_wrong_binding_and_replay() -> None:
    lifecycle, exchange, transport, _, _ = make()
    binding, state = start(lifecycle)
    with pytest.raises(OidcNativeExchangeError):
        exchange.reject_callback(browser_binding="X" * 43, state=state, error="access_denied")
    assert (
        exchange.reject_callback(browser_binding=binding, state=state, error="access_denied")
        is None
    )
    with pytest.raises(OidcNativeExchangeError):
        exchange.reject_callback(browser_binding=binding, state=state, error="access_denied")
    assert transport.requests == []


def test_no_sockets_are_opened_for_denial(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    def no_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Unexpected socket operation")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    lifecycle, _, transport, _, _ = make()
    binding, state = start(lifecycle)
    assert lifecycle.complete(request=request(state), protected_binding=binding).status
    assert transport.requests == []


def test_forged_request_can_never_confer_authentication() -> None:
    lifecycle, _, transport, _, _ = make()
    binding, state = start(lifecycle)
    forged = replace(request(state), headers=(("Host", "127.0.0.1:45921"),))
    denied = lifecycle.complete(request=forged, protected_binding=binding)
    assert denied.login == "not_implemented"
    assert not hasattr(denied, "verified_identity")
    assert not hasattr(denied, "access_token")
    assert transport.requests == []
