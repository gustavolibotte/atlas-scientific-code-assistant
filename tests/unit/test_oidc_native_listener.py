"""Real, local-only native loopback TCP listener unit/contract tests."""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from urllib.parse import urlsplit

import pytest

from asca.domain.oidc_native_listener import (
    NativeLoopbackListenerBinding,
    OidcNativeListenerError,
)
from asca.domain.oidc_registration import OidcClientMode
from asca.infrastructure.oidc_native_listener import CernNativeLoopbackListener

STATE = "s" * 43
CODE = "synthetic-code"


def listener(*, host: str = "127.0.0.1", **changes: object) -> CernNativeLoopbackListener:
    options: dict[str, object] = {
        "host": host,
        "client_id": "synthetic-native-listener-client",
        "timeout_seconds": 1.0,
        "per_connection_seconds": 0.35,
        "max_connections": 4,
    }
    options.update(changes)
    return CernNativeLoopbackListener(**options)  # type: ignore[arg-type]


def request(
    bound: CernNativeLoopbackListener,
    *,
    target: str | None = None,
    headers: str = "",
    method: str = "GET",
    version: str = "HTTP/1.1",
) -> bytes:
    uri = urlsplit(bound.binding.redirect_uri)
    authority = uri.netloc
    callback = target or f"{uri.path}?state={STATE}&code={CODE}"
    return f"{method} {callback} {version}\r\nHost: {authority}\r\n{headers}\r\n".encode("ascii")


def send(bound: CernNativeLoopbackListener, content: bytes) -> bytes:
    with socket.create_connection((bound.binding.host, bound.binding.port), timeout=1.0) as conn:
        conn.settimeout(1.5)
        conn.sendall(content)
        chunks = []
        while True:
            data = conn.recv(4096)
            if not data:
                return b"".join(chunks)
            chunks.append(data)


def roundtrip(bound: CernNativeLoopbackListener, content: bytes):
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(bound.receive)
        response = send(bound, content)
        envelope = future.result(timeout=2)
        return envelope, response


def test_listener_observes_kernel_chosen_port_and_does_not_authenticate() -> None:
    with listener() as bound:
        registration = bound.registration
        assert type(bound.binding) is NativeLoopbackListenerBinding
        assert registration.mode is OidcClientMode.NATIVE_LOOPBACK
        assert registration.redirect_uri == bound.binding.redirect_uri
        assert registration.client_id == "synthetic-native-listener-client"
        assert bound.binding.host == "127.0.0.1"
        assert 1 <= bound.binding.port <= 65535
        assert bound.binding.login == "not_implemented"
        with pytest.raises(FrozenInstanceError):
            bound.binding.port = 0  # type: ignore[misc]
        assert not bound.closed
    assert bound.closed


def test_listener_accepts_one_actual_ipv4_callback_then_closes() -> None:
    with listener() as bound:
        envelope, response = roundtrip(bound, request(bound))
        assert response.startswith(b"HTTP/1.1 202 Accepted\r\n")
        assert b"Cache-Control: no-store" in response
        assert b"Content-Length: 0" in response
        assert b"synthetic-code" not in response
        assert envelope.local_ip == envelope.peer_ip == "127.0.0.1"
        assert envelope.local_port == bound.binding.port
        assert envelope.request_target.endswith(f"state={STATE}&code={CODE}")
        assert envelope.headers == (("Host", urlsplit(bound.binding.redirect_uri).netloc),)
        assert bound.closed
        with pytest.raises(OidcNativeListenerError):
            bound.receive()
        with pytest.raises(OSError):
            socket.create_connection((bound.binding.host, bound.binding.port), timeout=0.2)


def test_listener_accepts_one_ipv6_callback_if_supported() -> None:
    try:
        bound = listener(host="::1")
    except OidcNativeListenerError:
        pytest.skip("IPv6 loopback binding is not available in this environment")
    with bound:
        assert bound.binding.redirect_uri.startswith("http://[::1]:")
        envelope, response = roundtrip(bound, request(bound))
        assert response.startswith(b"HTTP/1.1 202")
        assert envelope.local_ip == envelope.peer_ip == "::1"
        assert envelope.local_port == bound.binding.port
        assert bound.closed


@pytest.mark.parametrize(
    "changes",
    [
        {"host": "0.0.0.0"},
        {"host": "::"},
        {"host": "localhost"},
        {"host": "127.0.0.2"},
        {"host": "::ffff:127.0.0.1"},
        {"host": "[::1]"},
        {"host": None},
        {"host": 123},
        {"host": "127.0.0.1\x00"},
        {"client_id": ""},
        {"client_id": "invalid client"},
        {"client_id": None},
        {"scopes": ("openid", "admin")},
        {"scopes": "openid"},
        {"callback_path": ""},
        {"callback_path": "/"},
        {"callback_path": "//oidc/callback"},
        {"callback_path": "/oidc//callback"},
        {"callback_path": "/oidc/../callback"},
        {"callback_path": "/oidc%2Fcallback"},
        {"callback_path": "/oidc?callback"},
        {"callback_path": "/oidc#callback"},
        {"callback_path": "/oidc\\callback"},
        {"callback_path": "/" + "x" * 129},
        {"timeout_seconds": 0},
        {"timeout_seconds": 121},
        {"timeout_seconds": float("nan")},
        {"timeout_seconds": True},
        {"per_connection_seconds": 0},
        {"per_connection_seconds": 11},
        {"per_connection_seconds": float("inf")},
        {"max_connections": 0},
        {"max_connections": 17},
        {"max_connections": True},
        {"max_request_bytes": 255},
        {"max_request_bytes": 16385},
        {"max_request_bytes": True},
    ],
)
def test_reject_invalid_binding_and_limits_before_serving(changes: dict[str, object]) -> None:
    with pytest.raises(OidcNativeListenerError):
        listener(**changes)


def test_custom_valid_path_and_scopes() -> None:
    with listener(callback_path="/native/callback_1", scopes=("openid", "profile")) as bound:
        assert bound.registration.scopes == ("openid", "profile")
        assert bound.binding.redirect_uri.endswith("/native/callback_1")
        envelope, response = roundtrip(bound, request(bound))
        assert envelope.request_target.startswith("/native/callback_1?")
        assert response.startswith(b"HTTP/1.1 202")


def test_context_close_is_idempotent_and_rejects_reuse() -> None:
    bound = listener()
    bound.close()
    bound.close()
    assert bound.closed
    with pytest.raises(OidcNativeListenerError):
        bound.receive()
    with pytest.raises(OidcNativeListenerError), bound:
        pass


def test_expiry_without_any_connection_closes_listener() -> None:
    with listener(timeout_seconds=0.05) as bound:
        started = time.monotonic()
        with pytest.raises(OidcNativeListenerError):
            bound.receive()
        elapsed = time.monotonic() - started
        assert 0.02 <= elapsed < 1.0
        assert bound.closed


def test_close_from_another_thread_interrupts_waiting_receiver() -> None:
    with listener(timeout_seconds=2.0) as bound:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(bound.receive)
            time.sleep(0.03)
            bound.close()
            with pytest.raises(OidcNativeListenerError):
                future.result(timeout=1.0)
        assert bound.closed


def test_only_one_thread_may_enter_receive() -> None:
    with listener(timeout_seconds=0.3) as bound, ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(bound.receive)
        deadline = time.monotonic() + 1.0
        while not bound._started and time.monotonic() < deadline:
            time.sleep(0.005)
        assert bound._started
        with pytest.raises(OidcNativeListenerError):
            bound.receive()
        response = send(bound, request(bound))
        envelope = first.result(timeout=1)
        assert envelope.method == "GET"
        assert response.startswith(b"HTTP/1.1 202")


def test_connection_limit_exhaustion_fails_closed() -> None:
    with listener(max_connections=1) as bound:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(bound.receive)
            response = send(bound, request(bound, method="POST"))
            assert response.startswith(b"HTTP/1.1 400")
            with pytest.raises(OidcNativeListenerError):
                future.result(timeout=1.0)
        assert bound.closed


def test_incomplete_request_eof_rejected_before_second_valid_request() -> None:
    with listener() as bound, ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(bound.receive)
        address = (bound.binding.host, bound.binding.port)
        with socket.create_connection(address, timeout=1) as conn:
            conn.sendall(b"GET /oidc/callback?state=")
            conn.shutdown(socket.SHUT_WR)
            assert conn.recv(1024).startswith(b"HTTP/1.1 400")
        assert send(bound, request(bound)).startswith(b"HTTP/1.1 202")
        assert future.result(timeout=2).method == "GET"


def test_explicit_cancel_closes_active_connection() -> None:
    with (
        listener(timeout_seconds=1.0, per_connection_seconds=0.5) as bound,
        ThreadPoolExecutor(max_workers=1) as pool,
    ):
        future = pool.submit(bound.receive)
        address = (bound.binding.host, bound.binding.port)
        with socket.create_connection(address, timeout=1) as conn:
            conn.sendall(b"GET /oidc/callback?state=")
            deadline = time.monotonic() + 1.0
            while bound._active_connection is None and time.monotonic() < deadline:
                time.sleep(0.005)
            assert bound._active_connection is not None
            bound.close()
            with pytest.raises(OidcNativeListenerError):
                future.result(timeout=2)
            assert bound.closed


def test_reject_expired_read_deadline_using_synthetic_socket() -> None:
    from asca.infrastructure.oidc_native_listener import _read_http_request

    class FakeSocket:
        def settimeout(self, _timeout: float) -> None:
            raise AssertionError("Read should not begin after timeout")

    with pytest.raises(OidcNativeListenerError):
        _read_http_request(
            FakeSocket(),  # type: ignore[arg-type]
            deadline=time.monotonic() - 1,
            max_bytes=1024,
            peer_ip="127.0.0.1",
            local_ip="127.0.0.1",
            local_port=30000,
        )


def test_synthetic_socket_binding_failure_is_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    from asca.infrastructure import oidc_native_listener as module

    class BrokenSocket:
        closed = False

        def bind(self, _address: object) -> None:
            raise OSError("sensitive-address")

        def close(self) -> None:
            self.closed = True

    fake = BrokenSocket()
    monkeypatch.setattr(module.socket, "socket", lambda *_args: fake)
    with pytest.raises(OidcNativeListenerError, match="socket binding was rejected") as raised:
        listener()
    assert "sensitive-address" not in str(raised.value)
    assert fake.closed


def test_fake_socket_reporting_wrong_bound_host_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from asca.infrastructure import oidc_native_listener as module

    class WrongHostSocket:
        closed = False

        def bind(self, _address: object) -> None:
            pass

        def listen(self, _backlog: int) -> None:
            pass

        def getsockname(self) -> tuple[str, int]:
            return "0.0.0.0", 22222

        def close(self) -> None:
            self.closed = True

    fake = WrongHostSocket()
    monkeypatch.setattr(module.socket, "socket", lambda *_args: fake)
    with pytest.raises(OidcNativeListenerError):
        listener()
    assert fake.closed


def test_neutral_response_swallow_socket_io_errors() -> None:
    class BrokenConnection:
        def settimeout(self, _seconds: float) -> None:
            raise OSError("do-not-disclose")

    CernNativeLoopbackListener._respond(BrokenConnection(), accepted=True)  # type: ignore[arg-type]


def test_close_between_accept_and_connection_registration() -> None:
    with listener(timeout_seconds=1) as bound:
        real_socket = bound._socket

        class ClosingSocket:
            def settimeout(self, timeout: float) -> None:
                real_socket.settimeout(timeout)

            def accept(self):
                conn, address = real_socket.accept()
                bound.close()
                return conn, address

            def close(self) -> None:
                real_socket.close()

        bound._socket = ClosingSocket()  # type: ignore[assignment]
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(bound.receive)
            with (
                socket.create_connection((bound.binding.host, bound.binding.port), timeout=1),
                pytest.raises(OidcNativeListenerError),
            ):
                future.result(timeout=2)
        assert bound.closed


def test_socket_creation_failure_sanitized_without_partial_resource(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from asca.infrastructure import oidc_native_listener as module

    def cannot_create(*_args: object) -> None:
        raise OSError("sensitive-create-failure")

    monkeypatch.setattr(module.socket, "socket", cannot_create)
    with pytest.raises(OidcNativeListenerError, match="socket binding was rejected") as raised:
        listener()
    assert "sensitive-create-failure" not in str(raised.value)


def test_accept_operating_system_failure_is_sanitized_and_closes_socket() -> None:
    with listener(timeout_seconds=0.2) as bound:
        original_socket = bound._socket

        class FailedAcceptSocket:
            def settimeout(self, _seconds: float) -> None:
                pass

            def accept(self) -> None:
                raise OSError("sensitive-listener-accept-failure")

            def close(self) -> None:
                original_socket.close()

        bound._socket = FailedAcceptSocket()  # type: ignore[assignment]
        with pytest.raises(OidcNativeListenerError, match="Native listener was rejected") as error:
            bound.receive()
        assert "sensitive-listener-accept-failure" not in str(error.value)
        assert bound.closed
