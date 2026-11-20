"""Process-wide network kill switch for the test suite.

Unless ``ASCA_LIVE == "1"``, every non-loopback internet connection and every name lookup
other than ``localhost`` raises ``RuntimeError("network disabled in tests")``. AF_UNIX and
loopback (``127.0.0.0/8``, ``::1``) stay allowed, so in-process loopback servers work.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Mapping
from typing import Any

import pytest

MESSAGE = "network disabled in tests"
_INET = (socket.AF_INET, socket.AF_INET6)
_originals: dict[str, Any] = {}


def live_enabled(environ: Mapping[str, str]) -> bool:
    return environ.get("ASCA_LIVE") == "1"


def check_live_environment(environ: Mapping[str, str]) -> None:
    """Refuse live tests in CI."""
    if environ.get("CI") and environ.get("ASCA_LIVE"):
        raise pytest.UsageError("ASCA_LIVE must never be set in CI")


def is_allowed_host(host: object) -> bool:
    if host is None:
        return True
    if isinstance(host, bytes):
        host = host.decode("ascii", errors="replace")
    if not isinstance(host, str):
        return False
    if host.lower() == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    return address.is_loopback


def check_address(family: int, address: object) -> None:
    if family not in _INET:
        return
    host = address[0] if isinstance(address, tuple) and address else address
    if not is_allowed_host(host):
        raise RuntimeError(MESSAGE)


def _guarded_getaddrinfo(original: Callable[..., Any]) -> Callable[..., Any]:
    def getaddrinfo(host: object, *args: Any, **kwargs: Any) -> Any:
        if not is_allowed_host(host):
            raise RuntimeError(MESSAGE)
        return original(host, *args, **kwargs)

    return getaddrinfo


def _guarded_create_connection(original: Callable[..., Any]) -> Callable[..., Any]:
    def create_connection(address: Any, *args: Any, **kwargs: Any) -> Any:
        check_address(socket.AF_INET, address)
        return original(address, *args, **kwargs)

    return create_connection


def _guarded_connect(original: Callable[..., Any]) -> Callable[..., Any]:
    def connect(self: socket.socket, address: Any) -> Any:
        check_address(self.family, address)
        return original(self, address)

    return connect


def install() -> None:
    """Install the guard once; later calls are no-ops."""
    if _originals:
        return
    _originals["getaddrinfo"] = socket.getaddrinfo
    _originals["create_connection"] = socket.create_connection
    _originals["connect"] = socket.socket.connect
    _originals["connect_ex"] = socket.socket.connect_ex
    socket.getaddrinfo = _guarded_getaddrinfo(_originals["getaddrinfo"])
    socket.create_connection = _guarded_create_connection(_originals["create_connection"])
    socket.socket.connect = _guarded_connect(_originals["connect"])  # type: ignore[method-assign]
    socket.socket.connect_ex = _guarded_connect(_originals["connect_ex"])  # type: ignore[method-assign]


def installed() -> bool:
    return bool(_originals)
