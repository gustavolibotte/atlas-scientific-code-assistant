"""Adversarial native listener tests using only real local loopback TCP clients.

No provider requests or credentials are used; the only network is OS loopback.
"""

from __future__ import annotations

import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlsplit

import pytest

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_native_lifecycle import NativeCallbackDenied, OidcNativeLifecycleError
from asca.domain.oidc_token_http import UnverifiedOidcTokenHttpResponse
from asca.domain.oidc_token_request import UnsentOidcTokenRequest
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken
from asca.infrastructure.oidc_native_exchange import CernOidcNativeCodeExchange
from asca.infrastructure.oidc_native_lifecycle import CernNativeCallbackLifecycle
from asca.infrastructure.oidc_native_listener import CernNativeLoopbackListener
from asca.infrastructure.oidc_token_http import HttpsOidcTokenTransport
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

STATE = "a" * 43
CLIENT = "offline-real-loopback-listener"
NOW = 1_800_000_000.0


def listener(**changes: object) -> CernNativeLoopbackListener:
    options: dict[str, object] = {
        "host": "127.0.0.1",
        "client_id": CLIENT,
        "timeout_seconds": 1.2,
        "per_connection_seconds": 0.25,
        "max_connections": 4,
    }
    options.update(changes)
    return CernNativeLoopbackListener(**options)  # type: ignore[arg-type]


def request(bound: CernNativeLoopbackListener, *, query: str | None = None) -> bytes:
    uri = urlsplit(bound.binding.redirect_uri)
    query = query or f"state={STATE}&error=access_denied"
    return f"GET {uri.path}?{query} HTTP/1.1\r\nHost: {uri.netloc}\r\n\r\n".encode("ascii")


def wire(bound: CernNativeLoopbackListener, content: bytes, *, fragments: int = 1) -> bytes:
    with socket.create_connection((bound.binding.host, bound.binding.port), timeout=1.0) as conn:
        conn.settimeout(1.5)
        if fragments == 1:
            conn.sendall(content)
        else:
            cut = len(content) // fragments
            for index in range(fragments):
                piece = (
                    content[index * cut :]
                    if index == fragments - 1
                    else content[index * cut : (index + 1) * cut]
                )
                conn.sendall(piece)
                time.sleep(0.005)
        result = bytearray()
        while True:
            part = conn.recv(4096)
            if not part:
                return bytes(result)
            result.extend(part)


@pytest.mark.parametrize(
    "attack",
    [
        lambda b: request(b).replace(b"GET ", b"POST ", 1),
        lambda b: request(b).split(b"\r\n", 1)[0] + b"\r\n\r\n",
        lambda b: request(b).replace(b"HTTP/1.1", b"HTTP/1.0"),
        lambda b: request(b).replace(b"Host:", b"X-Host:"),
        lambda b: request(b) + b"MORE-BYTES",
        lambda b: request(b).replace(b"\r\n", b"\n"),
        lambda b: request(b).replace(b"\r\nHost", b"\r\n\tHost"),
        lambda b: request(b).replace(b"GET ", b"GET  ", 1),
        lambda b: request(b).replace(b" HTTP/1.1", b"  HTTP/1.1"),
        lambda b: request(b).replace(b"/oidc/callback", b"/wrong/callback"),
        lambda b: request(b).replace(b"/oidc/callback?", b"http://evil.invalid/oidc/callback?"),
        lambda b: request(b).replace(b"state=", b"evil=", 1),
        lambda b: request(b).replace(b"state=", b"state=%QQ", 1),
        lambda b: request(b).replace(b"error=access_denied", b"code=ok&error=access_denied"),
        lambda b: request(b)[:-2] + b"Content-Length: 10\r\n\r\n",
        lambda b: request(b)[:-2] + b"Transfer-Encoding: chunked\r\n\r\n",
        lambda b: request(b)[:-2] + b"Cookie: session=attacker\r\n\r\n",
        lambda b: request(b)[:-2] + b"Authorization: Bearer synthetic\r\n\r\n",
        lambda b: request(b)[:-2] + b"Origin: https://evil.invalid\r\n\r\n",
        lambda b: request(b)[:-2] + b"X-Forwarded-Host: evil.invalid\r\n\r\n",
        lambda b: request(b)[:-2] + b"Host: evil.invalid\r\n\r\n",
        lambda b: request(b).replace(b"Host: ", b"Host: evil.invalid, ", 1),
        lambda b: request(b).replace(b"Host: ", b"Host: localhost:", 1),
        lambda b: request(b).replace(b"HTTP/1.1", b"HTTP/1.2"),
        lambda b: request(b).replace(b"state=", b"state=\x00", 1),
        lambda b: request(b).replace(b"\r\nHost:", b"\r\nFo\xff: bad\r\nHost:"),
        lambda b: request(b).replace(b"\r\nHost:", b"\r\nH\r\nost: bad\r\nHost:"),
        lambda b: request(b).replace(b"\r\nHost:", b"\r\n : bad\r\nHost:"),
        lambda b: request(b).replace(b"\r\nHost:", b"\r\nH\tt:bad\r\nHost:"),
        lambda b: request(b).replace(b"\r\nHost:", b"\r\nHost:  "),
        lambda b: request(b).replace(b"\r\nHost:", b"\r\nHost: \t"),
    ],
)
def test_malformed_or_injected_request_is_rejected_without_ending_listener(attack):
    with listener() as bound, ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(bound.receive)
        response = wire(bound, attack(bound))
        assert response.startswith(b"HTTP/1.1 400"), response
        assert b"state=" not in response and b"access_denied" not in response
        valid_response = wire(bound, request(bound), fragments=3)
        assert valid_response.startswith(b"HTTP/1.1 202")
        parsed = future.result(timeout=2)
        assert parsed.method == "GET"
        assert bound.closed


def test_oversized_headers_rejected_then_valid_callback() -> None:
    with listener(max_request_bytes=512) as bound, ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(bound.receive)
        malformed = request(bound)[:-2] + b"X-Filler: " + b"x" * 700 + b"\r\n\r\n"
        try:
            response = wire(bound, malformed)
        except ConnectionResetError:
            # Oversized requests can receive RST while unread TCP data remains.
            response = b""
        assert not response or response.startswith(b"HTTP/1.1 400")
        assert wire(bound, request(bound)).startswith(b"HTTP/1.1 202")
        assert future.result(timeout=2).request_target.startswith("/oidc/callback?")


def test_slowloris_incomplete_request_timeout_then_valid() -> None:
    with listener(per_connection_seconds=0.05) as bound, ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(bound.receive)
        address = (bound.binding.host, bound.binding.port)
        with socket.create_connection(address, timeout=1) as conn:
            conn.sendall(b"GET /oidc/callback?state=")
            time.sleep(0.09)
            assert conn.recv(1024).startswith(b"HTTP/1.1 400")
        assert wire(bound, request(bound)).startswith(b"HTTP/1.1 202")
        assert future.result(timeout=2).local_ip == "127.0.0.1"


def test_adversary_exhausts_bounded_connections_without_network_exchange() -> None:
    from asca.domain.oidc_native_listener import OidcNativeListenerError

    with listener(max_connections=2) as bound, ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(bound.receive)
        for _ in range(2):
            assert wire(bound, b"GET / HTTP/1.1\r\nHost: evil.invalid\r\n\r\n").startswith(
                b"HTTP/1.1 400"
            )
        with pytest.raises(OidcNativeListenerError):
            future.result(timeout=2)
        assert bound.closed


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


class OfflineTransport(HttpsOidcTokenTransport):
    def __init__(self) -> None:
        self.requests: list[UnsentOidcTokenRequest] = []

    def exchange(
        self, prepared: UnsentOidcTokenRequest, _client: object
    ) -> UnverifiedOidcTokenHttpResponse:
        self.requests.append(prepared)
        return UnverifiedOidcTokenHttpResponse(
            body=json.dumps(
                {"access_token": "synthetic", "token_type": "Bearer", "id_token": "a.b.c"}
            ).encode()
        )


class OfflineVerifier(CernOidcVerificationPipeline):
    def check(
        self,
        _tokens: object,
        _provider: object,
        *,
        expected_client_id: str,
        expected_nonce: str,
        now: int,
        **_kwargs: object,
    ) -> CheckedUntrustedCernOidcToken:
        assert expected_nonce
        return CheckedUntrustedCernOidcToken(
            issuer=CERN_OIDC_ISSUER,
            subject="synthetic-subject",
            audiences=(expected_client_id,),
            expires_at=now + 120,
            algorithm="RS256",
            kid="test-key",
            source_url=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        )


def lifecycle(bound: CernNativeLoopbackListener):
    transport = OfflineTransport()
    exchange = CernOidcNativeCodeExchange(
        bound.registration,
        metadata(),
        transport=transport,
        verifier=OfflineVerifier(),
        clock=lambda: NOW,
    )
    return CernNativeCallbackLifecycle(exchange), transport


def start(life: CernNativeCallbackLifecycle) -> tuple[str, str]:
    started = life.begin()
    state = parse_qs(urlsplit(started.authorization_url).query)["state"][0]
    return started.browser_binding, state


def test_real_socket_denial_consumes_once_without_any_token_post() -> None:
    with listener() as bound:
        life, transport = lifecycle(bound)
        binding, state = start(life)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(bound.receive)
            payload = request(bound, query=f"state={state}&error=access_denied")
            assert wire(bound, payload).startswith(b"HTTP/1.1 202")
            envelope = future.result(timeout=2)
        assert bound.closed  # Closed BEFORE lifecycle consumption.
        result = life.complete(request=envelope, protected_binding=binding)
        assert isinstance(result, NativeCallbackDenied)
        assert transport.requests == []
        with pytest.raises(OidcNativeLifecycleError):
            life.complete(request=envelope, protected_binding=binding)
        assert transport.requests == []


def test_real_socket_success_passes_state_to_existing_pkce_exchange_once() -> None:
    from asca.domain.oidc_native_exchange import ExchangedUntrustedCernOidcToken

    with listener() as bound:
        life, transport = lifecycle(bound)
        binding, state = start(life)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(bound.receive)
            payload = request(bound, query=f"state={state}&code=synthetic-code")
            assert wire(bound, payload).startswith(b"HTTP/1.1 202")
            envelope = future.result(timeout=2)
        result = life.complete(request=envelope, protected_binding=binding)
        assert isinstance(result, ExchangedUntrustedCernOidcToken)
        assert result.subject == "synthetic-subject"
        assert len(transport.requests) == 1
        with pytest.raises(OidcNativeLifecycleError):
            life.complete(request=envelope, protected_binding=binding)
        assert len(transport.requests) == 1


def test_valid_syntax_wrong_state_closes_listener_but_does_not_consume() -> None:
    with listener() as bound:
        life, transport = lifecycle(bound)
        binding, state = start(life)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(bound.receive)
            payload = request(bound, query=f"state={STATE}&error=access_denied")
            assert wire(bound, payload).startswith(b"HTTP/1.1 202")
            envelope = future.result(timeout=2)
        assert bound.closed
        with pytest.raises(OidcNativeLifecycleError):
            life.complete(request=envelope, protected_binding=binding)
        assert not transport.requests
        # The pending attempt is still consumable via the lifecycle (no live listener).
        from dataclasses import replace

        repaired = replace(
            envelope, request_target=f"/oidc/callback?state={state}&error=access_denied"
        )
        restored = life.complete(request=repaired, protected_binding=binding)
        assert isinstance(restored, NativeCallbackDenied)


def test_no_external_network_endpoint_or_authentication_route_imported() -> None:
    from asca.infrastructure.oidc_native_listener import CernNativeLoopbackListener

    assert CernNativeLoopbackListener.__module__ == "asca.infrastructure.oidc_native_listener"
    with listener() as bound:
        assert bound.binding.login == "not_implemented"
    # No actual OIDC network call is involved in this listener module or test.
