"""The test-suite network kill switch and the live-test gating."""

import os
import socket

import conftest
import network_guard
import pytest

pytestmark = pytest.mark.security

needs_guard = pytest.mark.skipif(
    network_guard.live_enabled(os.environ), reason="the kill switch is off for live runs"
)


@needs_guard
def test_kill_switch_is_installed() -> None:
    assert network_guard.installed()


@needs_guard
def test_kill_switch_blocks_internet_connections_and_lookups() -> None:
    with pytest.raises(RuntimeError, match="network disabled in tests"):
        socket.create_connection(("inspirehep.net", 443), timeout=1)
    with pytest.raises(RuntimeError, match="network disabled in tests"):
        socket.getaddrinfo("example.org", 443)
    with pytest.raises(RuntimeError, match="network disabled in tests"):
        socket.getaddrinfo(b"example.org", 443)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(RuntimeError, match="network disabled in tests"):
            sock.connect(("188.184.21.108", 443))
        with pytest.raises(RuntimeError, match="network disabled in tests"):
            sock.connect_ex(("8.8.8.8", 53))
    with pytest.raises(RuntimeError, match="network disabled in tests"):
        network_guard.check_address(socket.AF_INET6, ("2001:4860:4860::8888", 53, 0, 0))
    network_guard.check_address(socket.AF_INET6, ("::1", 53, 0, 0))
    network_guard.check_address(socket.AF_UNIX, "/tmp/any.sock")


@needs_guard
def test_kill_switch_allows_loopback_and_unix_sockets() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            accepted, _ = server.accept()
            accepted.close()
            assert client.getpeername()[1] == port
        with socket.create_connection(("localhost", port), timeout=2):
            server.accept()[0].close()
    assert socket.getaddrinfo("127.0.0.1", 80)
    assert socket.getaddrinfo(None, 80)
    left, right = socket.socketpair()
    left.close()
    right.close()


def test_guard_host_rules() -> None:
    assert network_guard.is_allowed_host("127.0.0.2")
    assert network_guard.is_allowed_host("::1")
    assert network_guard.is_allowed_host("LOCALHOST")
    assert network_guard.is_allowed_host(None)
    assert not network_guard.is_allowed_host("10.0.0.1")
    assert not network_guard.is_allowed_host("localhost.example")
    assert not network_guard.is_allowed_host(42)
    network_guard.install()


def test_ci_together_with_asca_live_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("ASCA_LIVE", "1")
    with pytest.raises(pytest.UsageError):
        conftest.pytest_configure(None)  # type: ignore[arg-type]
    with pytest.raises(pytest.UsageError):
        network_guard.check_live_environment({"CI": "1", "ASCA_LIVE": "0"})
    network_guard.check_live_environment({"CI": "1"})
    network_guard.check_live_environment({"ASCA_LIVE": "1"})
    assert network_guard.live_enabled({"ASCA_LIVE": "1"})
    assert not network_guard.live_enabled({"ASCA_LIVE": "true"})


def test_live_items_are_skipped_without_asca_live(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASCA_LIVE", raising=False)

    class Item:
        def __init__(self, live: bool) -> None:
            self.keywords = {"live": True} if live else {}
            self.markers: list[pytest.MarkDecorator] = []

        def add_marker(self, marker: pytest.MarkDecorator) -> None:
            self.markers.append(marker)

    live, plain = Item(True), Item(False)
    conftest.pytest_collection_modifyitems(None, [live, plain])  # type: ignore[arg-type, list-item]
    assert [m.name for m in live.markers] == ["skip"]
    assert plain.markers == []
    monkeypatch.setenv("ASCA_LIVE", "1")
    again = Item(True)
    conftest.pytest_collection_modifyitems(None, [again])  # type: ignore[arg-type, list-item]
    assert again.markers == []
