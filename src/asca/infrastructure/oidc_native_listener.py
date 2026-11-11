"""Bounded, single-response native loopback HTTP listener (unmounted).

An actual OS socket is bound to 127.0.0.1 or ::1 with a kernel-selected port.
The listener sends only neutral HTTP responses, closes its listening socket
before returning a syntactically accepted callback, and never authenticates.

The caller MUST retain the native authorization binding in protected host state
and dispatch the returned callback through CernNativeCallbackLifecycle.complete.
A local process can still race, forge an HTTP callback or deny service; state,
PKCE and the official client registration are separate trust requirements.
"""

from __future__ import annotations

import re
import socket
import threading
import time
from contextlib import suppress
from typing import Literal, Self

from asca.domain.oidc_native_callback import NativeLoopbackHttpRequest
from asca.domain.oidc_native_listener import (
    NativeLoopbackListenerBinding,
    OidcNativeListenerError,
)
from asca.domain.oidc_registration import OidcClientMode, OidcClientRegistration
from asca.infrastructure.oidc_native_callback import CernNativeLoopbackCallbackPolicy

_PATH = re.compile(r"/[A-Za-z0-9/_-]{1,127}\Z", re.ASCII)
_RESPONSE_ACCEPTED = (
    b"HTTP/1.1 202 Accepted\r\n"
    b"Content-Length: 0\r\n"
    b"Cache-Control: no-store\r\n"
    b"Connection: close\r\n\r\n"
)
_RESPONSE_REJECTED = (
    b"HTTP/1.1 400 Bad Request\r\n"
    b"Content-Length: 0\r\n"
    b"Cache-Control: no-store\r\n"
    b"Connection: close\r\n\r\n"
)


def _bounded_seconds(value: object, *, maximum: float) -> float:
    if (
        not isinstance(value, (int, float))
        or type(value) not in (int, float)
        or not 0.05 <= value <= maximum
    ):
        raise OidcNativeListenerError("Invalid native listener limits")
    return float(value)


def _read_http_request(
    connection: socket.socket,
    *,
    deadline: float,
    max_bytes: int,
    peer_ip: str,
    local_ip: str,
    local_port: int,
) -> NativeLoopbackHttpRequest:
    """Read one complete HTTP/1.1 header; never normalize duplicate fields."""
    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OidcNativeListenerError("Invalid native listener request")
        connection.settimeout(min(0.2, remaining))
        piece = connection.recv(min(1024, max_bytes + 1 - len(buffer)))
        if not piece:
            raise OidcNativeListenerError("Invalid native listener request")
        buffer.extend(piece)
        if len(buffer) > max_bytes:
            raise OidcNativeListenerError("Invalid native listener request")
    raw_headers, _, extra = bytes(buffer).partition(b"\r\n\r\n")
    if extra or b"\n" in raw_headers.replace(b"\r\n", b""):
        raise OidcNativeListenerError("Invalid native listener request")
    try:
        lines = raw_headers.decode("ascii").split("\r\n")
    except UnicodeError:
        raise OidcNativeListenerError("Invalid native listener request") from None
    if len(lines) < 2 or len(lines) > 33:
        raise OidcNativeListenerError("Invalid native listener request")
    parts = lines[0].split(" ")
    if len(parts) != 3 or any(not part for part in parts):
        raise OidcNativeListenerError("Invalid native listener request")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line or line[0].isspace() or ":" not in line:
            raise OidcNativeListenerError("Invalid native listener request")
        name, value = line.split(":", 1)
        if value.startswith(" "):
            value = value[1:]
        if value.startswith(" ") or value.endswith(" ") or "\t" in value:
            raise OidcNativeListenerError("Invalid native listener request")
        headers.append((name, value))
    return NativeLoopbackHttpRequest(
        method=parts[0],
        request_target=parts[1],
        http_version=parts[2],
        headers=tuple(headers),
        peer_ip=peer_ip,
        local_ip=local_ip,
        local_port=local_port,
        body=b"",
    )


class CernNativeLoopbackListener:
    """Own a loopback socket for one strict, untrusted OAuth callback response.

    Use a context manager. receive() is single-invocation; it closes the socket
    on accepted callback, timeout, connection budget exhaustion, or error.
    An HTTP 202 acknowledges syntax only, not state consumption or login.
    """

    def __init__(
        self,
        *,
        host: str,
        client_id: str,
        callback_path: str = "/oidc/callback",
        scopes: tuple[str, ...] = ("openid",),
        timeout_seconds: float = 30.0,
        per_connection_seconds: float = 2.0,
        max_connections: int = 8,
        max_request_bytes: int = 8192,
    ) -> None:
        if (
            type(host) is not str
            or host not in ("127.0.0.1", "::1")
            or type(callback_path) is not str
            or _PATH.fullmatch(callback_path) is None
            or "//" in callback_path
            or type(max_connections) is not int
            or not 1 <= max_connections <= 16
            or type(max_request_bytes) is not int
            or not 256 <= max_request_bytes <= 16384
        ):
            raise OidcNativeListenerError("Invalid native listener configuration")
        total = _bounded_seconds(timeout_seconds, maximum=120.0)
        per_connection = _bounded_seconds(per_connection_seconds, maximum=10.0)
        authority = f"[{host}]" if host == "::1" else host
        try:
            # Validate the operator declaration before opening a listening socket.
            OidcClientRegistration(
                client_id=client_id,
                redirect_uri=f"http://{authority}:1{callback_path}",
                mode=OidcClientMode.NATIVE_LOOPBACK,
                scopes=scopes,
            )
        except (TypeError, ValueError, AttributeError):
            raise OidcNativeListenerError("Invalid native listener configuration") from None

        family = socket.AF_INET6 if host == "::1" else socket.AF_INET
        listener: socket.socket | None = None
        try:
            listener = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            if family == socket.AF_INET6:
                # Prevent an IPv4-mapped listener on IPv6 sockets.
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind((host, 0))
            listener.listen(1)
            actual_host = listener.getsockname()[0]
            actual_port = listener.getsockname()[1]
            if actual_host != host or not 1 <= actual_port <= 65535:
                raise OidcNativeListenerError("Native listener socket binding was rejected")
            registration = OidcClientRegistration(
                client_id=client_id,
                redirect_uri=f"http://{authority}:{actual_port}{callback_path}",
                mode=OidcClientMode.NATIVE_LOOPBACK,
                scopes=scopes,
            )
            policy = CernNativeLoopbackCallbackPolicy(registration)
        except (OSError, TypeError, ValueError, AttributeError):
            if listener is not None:
                listener.close()
            raise OidcNativeListenerError("Native listener socket binding was rejected") from None
        self._socket = listener
        self._registration = registration
        self._policy = policy
        literal_host: Literal["127.0.0.1", "::1"] = "::1" if host == "::1" else "127.0.0.1"
        self._binding = NativeLoopbackListenerBinding(
            host=literal_host, port=actual_port, redirect_uri=registration.redirect_uri
        )
        self._timeout = total
        self._connection_timeout = per_connection
        self._max_connections = max_connections
        self._max_request_bytes = max_request_bytes
        self._lock = threading.Lock()
        self._started = False
        self._closed = False
        self._active_connection: socket.socket | None = None

    @property
    def registration(self) -> OidcClientRegistration:
        """Operator-declared native client with actual ephemeral redirect port."""
        return self._registration

    @property
    def binding(self) -> NativeLoopbackListenerBinding:
        """Descriptive OS socket binding, not evidence of browser or user identity."""
        return self._binding

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def close(self) -> None:
        """Idempotently close listening and active sockets, including on cancellation."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._socket.close()
            if self._active_connection is not None:
                self._active_connection.close()

    def __enter__(self) -> Self:
        if self.closed:
            raise OidcNativeListenerError("Native listener was closed")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @staticmethod
    def _respond(connection: socket.socket, *, accepted: bool) -> None:
        """Send a bounded, secret-free response; never imply authentication."""
        with suppress(OSError, TimeoutError):
            connection.settimeout(0.2)
            connection.sendall(_RESPONSE_ACCEPTED if accepted else _RESPONSE_REJECTED)

    def receive(self) -> NativeLoopbackHttpRequest:
        """Return one syntax-accepted callback, closing before any token exchange.

        Reject malformed connections without consuming an authorization attempt.
        The whole operation has a monotonic deadline and a connection budget.
        No method here creates a principal or connects to CERN.
        """
        with self._lock:
            if self._closed or self._started:
                raise OidcNativeListenerError("Native listener was closed or already used")
            self._started = True
        deadline = time.monotonic() + self._timeout
        try:
            for _ in range(self._max_connections):
                while True:
                    if self.closed or time.monotonic() >= deadline:
                        raise OidcNativeListenerError("Native listener expired or was closed")
                    try:
                        self._socket.settimeout(min(0.2, max(0.001, deadline - time.monotonic())))
                        connection, _ = self._socket.accept()
                        break
                    except TimeoutError:
                        continue
                with connection:
                    with self._lock:
                        if self._closed:
                            raise OidcNativeListenerError("Native listener was closed")
                        self._active_connection = connection
                    try:
                        peer_ip = connection.getpeername()[0]
                        local = connection.getsockname()
                        local_ip = local[0]
                        local_port = local[1]
                        request = _read_http_request(
                            connection,
                            deadline=min(
                                deadline,
                                time.monotonic() + self._connection_timeout,
                            ),
                            max_bytes=self._max_request_bytes,
                            peer_ip=peer_ip,
                            local_ip=local_ip,
                            local_port=local_port,
                        )
                        self._policy.parse(request)
                    except (OSError, ValueError, TypeError, UnicodeError, AttributeError):
                        self._respond(connection, accepted=False)
                    else:
                        self._respond(connection, accepted=True)
                        return request
                    finally:
                        with self._lock:
                            self._active_connection = None
            raise OidcNativeListenerError("Native listener connection limit reached")
        except OidcNativeListenerError:
            raise
        except OSError:
            raise OidcNativeListenerError("Native listener was rejected") from None
        finally:
            self.close()
