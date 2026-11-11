"""Isolated OS-loopback host transaction: offline unit and integration tests."""

from __future__ import annotations

import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from urllib.parse import parse_qs, urlsplit

import pytest

from asca.application.identity import pkce_s256_challenge
from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.identity import VerifiedIdentity
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_native_exchange import ExchangedUntrustedCernOidcToken
from asca.domain.oidc_native_host import NativeOidcHostStart, OidcNativeHostError
from asca.domain.oidc_native_lifecycle import NativeCallbackDenied
from asca.domain.oidc_token_http import UnverifiedOidcTokenHttpResponse
from asca.domain.oidc_token_request import UnsentOidcTokenRequest
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken
from asca.infrastructure.oidc_native_host import CernNativeOidcHostTransaction
from asca.infrastructure.oidc_token_http import HttpsOidcTokenTransport
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

NOW = 1_800_000_000.0
CLIENT = "synthetic-host-test-client"


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


class SyntheticTransport(HttpsOidcTokenTransport):
    def __init__(self) -> None:
        self.calls: list[tuple[UnsentOidcTokenRequest, object]] = []
        self.failure = False
        self.unexpected_failure = False

    def exchange(
        self, prepared: UnsentOidcTokenRequest, client: object
    ) -> UnverifiedOidcTokenHttpResponse:
        self.calls.append((prepared, client))
        if self.unexpected_failure:
            raise RuntimeError("private-transport-failure")
        if self.failure:
            raise ValueError("private-transport-failure")
        body = json.dumps(
            {"access_token": "dummy-private-token", "token_type": "Bearer", "id_token": "a.b.c"}
        ).encode("ascii")
        return UnverifiedOidcTokenHttpResponse(body=body)


class SyntheticVerifier(CernOidcVerificationPipeline):
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.failure = False

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
        assert tokens is not None and provider == metadata()
        self.calls.append((expected_client_id, expected_nonce))
        if self.failure:
            raise ValueError("private-verifier-failure")
        return CheckedUntrustedCernOidcToken(
            issuer=CERN_OIDC_ISSUER,
            subject="synthetic-subject",
            audiences=(expected_client_id,),
            expires_at=now + 250,
            algorithm="RS256",
            kid="synthetic-key",
            source_url=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        )


def make(*, host: str = "127.0.0.1", **changes: object):
    transport = SyntheticTransport()
    verifier = SyntheticVerifier()
    clock = [NOW]
    opts: dict[str, object] = {
        "host": host,
        "client_id": CLIENT,
        "metadata": metadata(),
        "transport": transport,
        "verifier": verifier,
        "clock": lambda: clock[0],
        "timeout_seconds": 0.6,
        "per_connection_seconds": 0.15,
        "max_connections": 4,
    }
    opts.update(changes)
    flow = CernNativeOidcHostTransaction(**opts)  # type: ignore[arg-type]
    return flow, transport, verifier, clock


def start(flow: CernNativeOidcHostTransaction):
    begun = flow.begin()
    query = parse_qs(urlsplit(begun.authorization_url).query)
    return begun, query["state"][0], query


def wire(
    flow: CernNativeOidcHostTransaction,
    *,
    state: str,
    action: str = "error=access_denied",
    extra: str = "",
) -> bytes:
    uri = urlsplit(flow.binding.redirect_uri)
    data = (
        f"GET {uri.path}?state={state}&{action} HTTP/1.1\r\nHost: {uri.netloc}\r\n{extra}\r\n"
    ).encode("ascii")
    with socket.create_connection((flow.binding.host, flow.binding.port), timeout=0.6) as conn:
        conn.settimeout(1.5)
        conn.sendall(data)
        output = bytearray()
        while True:
            piece = conn.recv(4096)
            if not piece:
                return bytes(output)
            output.extend(piece)


def roundtrip(flow: CernNativeOidcHostTransaction, state: str, action: str):
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(flow.complete)
        response = wire(flow, state=state, action=action)
        return future.result(timeout=2), response


def test_host_constructs_listener_first_and_binds_ephemeral_port() -> None:
    with make()[0] as flow:
        assert flow.binding.port > 0
        assert flow._exchange.callback_registration.redirect_uri == flow.binding.redirect_uri
        assert flow._exchange.callback_registration == flow._listener.registration
        assert not flow.closed
    assert flow.closed


def test_begin_exposes_url_not_private_binding_or_verifier() -> None:
    with make()[0] as flow:
        begun, state, query = start(flow)
        assert type(begun) is NativeOidcHostStart
        assert begun.login == "not_implemented"
        assert begun.redirect_uri == flow.binding.redirect_uri
        assert query["redirect_uri"] == [flow.binding.redirect_uri]
        assert query["response_type"] == ["code"]
        assert query["code_challenge_method"] == ["S256"]
        assert len(query["code_challenge"][0]) == 43
        assert len(state) == 43
        assert len(query["nonce"][0]) == 43
        assert "code_verifier" not in query and "browser_binding" not in query
        assert flow._browser_binding not in begun.authorization_url
        assert flow._browser_binding not in repr(begun)
        assert "authorization_url" not in repr(begun)
        with pytest.raises(FrozenInstanceError):
            begun.redirect_uri = "http://evil.invalid"  # type: ignore[misc]


def test_correlated_denial_is_terminal_without_token_network() -> None:
    with make()[0] as flow:
        _, state, _ = start(flow)
        result, response = roundtrip(flow, state, "error=access_denied")
        assert result == NativeCallbackDenied()
        assert result.login == "not_implemented"
        assert response.startswith(b"HTTP/1.1 202")
        assert flow.closed and flow._listener.closed
        assert flow._browser_binding is None and flow._state is None
        with pytest.raises(OidcNativeHostError):
            flow.complete()


def test_code_exchange_is_offline_untrusted_and_pkce_bound() -> None:
    flow, transport, verifier, _ = make()
    with flow:
        begun, state, query = start(flow)
        result, response = roundtrip(flow, state, "code=test-code")
        assert isinstance(result, ExchangedUntrustedCernOidcToken)
        assert not isinstance(result, VerifiedIdentity)
        assert result.subject == "synthetic-subject"
        assert response.startswith(b"HTTP/1.1 202")
        assert len(transport.calls) == len(verifier.calls) == 1
        req, client = transport.calls[0]
        data = parse_qs(req.form_body.decode("ascii"))
        assert data["code"] == ["test-code"]
        assert data["redirect_uri"] == [begun.redirect_uri]
        assert data["client_id"] == [CLIENT]
        assert pkce_s256_challenge(data["code_verifier"][0]) == query["code_challenge"][0]
        assert verifier.calls[0] == (CLIENT, query["nonce"][0])
        assert client == flow._listener.registration
        assert flow.closed and flow._listener.closed
        assert "dummy-private-token" not in repr(result)
        assert flow._browser_binding is None and flow._state is None


def test_wrong_state_callback_fails_and_revokes_original_attempt() -> None:
    flow, transport, _, _ = make()
    with flow:
        _, _state, _ = start(flow)
        binding = flow._browser_binding
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(flow.complete)
            assert wire(flow, state="Z" * 43, action="code=test-code").startswith(b"HTTP/1.1 202")
            with pytest.raises(OidcNativeHostError):
                future.result(timeout=2)
        assert flow.closed and not transport.calls
        assert binding not in flow._exchange._store._pending
        assert flow._exchange._store._pending == {}


def test_valid_issuer_on_denial_consumes_once() -> None:
    flow, transport, _, _ = make()
    with flow:
        _, state, _ = start(flow)
        result, _ = roundtrip(flow, state, f"error=access_denied&iss={CERN_OIDC_ISSUER}")
        assert result == NativeCallbackDenied()
        assert transport.calls == []


def test_cancel_without_callback_revokes_attempt_and_closes_port() -> None:
    flow, transport, verifier, _ = make()
    begun, state, _ = start(flow)
    assert begun.redirect_uri == flow.binding.redirect_uri
    assert flow._exchange._store._pending
    flow.close()
    flow.close()
    assert flow._exchange._store._pending == {}
    assert flow.closed and flow._listener.closed
    assert not transport.calls and not verifier.calls
    with pytest.raises(OidcNativeHostError):
        flow.begin()
    with pytest.raises(OidcNativeHostError):
        flow.complete()
    assert state not in repr(flow)


def test_close_before_begin_is_terminal_and_does_not_save_attempt() -> None:
    flow, transport, _, _ = make()
    flow.close()
    assert flow.closed
    assert flow._exchange._store._pending == {}
    with pytest.raises(OidcNativeHostError):
        flow.begin()
    assert transport.calls == []


def test_complete_before_begin_fails_closed() -> None:
    flow, _, _, _ = make()
    with pytest.raises(OidcNativeHostError):
        flow.complete()
    assert flow.closed


def test_duplicate_begin_fails_closed_and_revokes_pending() -> None:
    flow, _, _, _ = make()
    start(flow)
    with pytest.raises(OidcNativeHostError):
        flow.begin()
    assert flow.closed and flow._exchange._store._pending == {}


def test_context_without_begin_closes_listener() -> None:
    flow, _, _, _ = make()
    with flow:
        assert not flow.closed
    assert flow.closed and flow._listener.closed
    with pytest.raises(OidcNativeHostError), flow:
        pass


def test_timeout_revokes_pending_authorization() -> None:
    flow, transport, _, _ = make(timeout_seconds=0.05)
    with flow:
        start(flow)
        with pytest.raises(OidcNativeHostError):
            flow.complete()
    assert flow._exchange._store._pending == {}
    assert transport.calls == []


def test_transport_failure_is_sanitized_and_attempt_is_not_restored() -> None:
    flow, transport, _, _ = make()
    transport.failure = True
    with flow:
        _, state, _ = start(flow)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(flow.complete)
            assert wire(flow, state=state, action="code=test-code").startswith(b"HTTP/1.1 202")
            with pytest.raises(
                OidcNativeHostError, match="Native host transaction was rejected"
            ) as error:
                future.result(timeout=2)
        assert "private-transport-failure" not in str(error.value)
    assert flow._exchange._store._pending == {}
    assert flow.closed


def test_unexpected_transport_exception_is_sanitized() -> None:
    flow, transport, _, _ = make()
    transport.unexpected_failure = True
    with flow:
        _, state, _ = start(flow)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(flow.complete)
            assert wire(flow, state=state, action="code=abc").startswith(b"HTTP/1.1 202")
            with pytest.raises(
                OidcNativeHostError, match="Native host transaction was rejected"
            ) as error:
                future.result(timeout=2)
        assert "private-transport-failure" not in str(error.value)
    assert flow._exchange._store._pending == {}


def test_verifier_failure_sanitized_without_identity() -> None:
    flow, transport, verifier, _ = make()
    verifier.failure = True
    with flow:
        _, state, _ = start(flow)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(flow.complete)
            assert wire(flow, state=state, action="code=abc").startswith(b"HTTP/1.1 202")
            with pytest.raises(OidcNativeHostError):
                future.result(timeout=2)
    assert len(transport.calls) == len(verifier.calls) == 1
    assert flow._exchange._store._pending == {}


def test_ipv6_loopback_composition_when_available() -> None:
    try:
        flow, transport, _, _ = make(host="::1")
    except OidcNativeHostError:
        pytest.skip("IPv6 loopback is unavailable")
    with flow:
        _, state, query = start(flow)
        assert query["redirect_uri"][0].startswith("http://[::1]:")
        result, response = roundtrip(flow, state, "error=access_denied")
        assert result == NativeCallbackDenied()
        assert response.startswith(b"HTTP/1.1 202")
        assert transport.calls == []


def test_cancel_interrupts_receive_from_other_thread() -> None:
    flow, transport, _, _ = make(timeout_seconds=2)
    with flow:
        start(flow)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(flow.complete)
            time.sleep(0.03)
            flow.close()
            with pytest.raises(OidcNativeHostError):
                future.result(timeout=2)
    assert flow.closed and flow._exchange._store._pending == {}
    assert transport.calls == []


def test_closed_socket_refuses_future_connection() -> None:
    flow, _, _, _ = make()
    address = (flow.binding.host, flow.binding.port)
    flow.close()
    with pytest.raises(OSError):
        socket.create_connection(address, timeout=0.2)


def test_mutated_exchange_registration_is_rejected_before_begin() -> None:
    flow, transport, _, _ = make()
    with flow:
        original = flow._exchange._registration
        from asca.domain.oidc_registration import OidcClientRegistration

        flow._exchange._registration = OidcClientRegistration(
            client_id=original.client_id,
            redirect_uri=original.redirect_uri.replace("/oidc/callback", "/wrong/callback"),
            mode=original.mode,
            scopes=original.scopes,
        )
        with pytest.raises(OidcNativeHostError):
            flow.begin()
        assert flow.closed
        assert not transport.calls


def test_host_closes_socket_when_exchange_constructor_rejects_metadata() -> None:
    import asca.infrastructure.oidc_native_host as module

    class BrokenExchange:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise ValueError("private-exchange-error")

    from unittest.mock import patch

    captured: list[object] = []
    original = module.CernNativeLoopbackListener

    def create_listener(**kwargs: object):
        listener = original(**kwargs)  # type: ignore[arg-type]
        captured.append(listener)
        return listener

    with (
        patch.object(module, "CernNativeLoopbackListener", create_listener),
        patch.object(module, "CernOidcNativeCodeExchange", BrokenExchange),
        pytest.raises(OidcNativeHostError, match="Invalid native host configuration"),
    ):
        make()
    assert captured and captured[0].closed  # type: ignore[attr-defined]


@pytest.mark.parametrize("invalid", [None, "oops", 2, object()])
def test_invalid_synthetic_metadata_is_rejected_before_socket(invalid: object) -> None:
    with pytest.raises(OidcNativeHostError):
        make(metadata=invalid)


@pytest.mark.parametrize("invalid", [None, "oops", 3, object(), HttpsOidcTokenTransport()])
def test_missing_or_default_transport_not_allowed(invalid: object) -> None:
    with pytest.raises(OidcNativeHostError):
        make(transport=invalid)


@pytest.mark.parametrize("invalid", [None, 3, object(), CernOidcVerificationPipeline()])
def test_missing_or_default_verifier_not_allowed(invalid: object) -> None:
    with pytest.raises(OidcNativeHostError):
        make(verifier=invalid)
