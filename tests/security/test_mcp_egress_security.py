"""MCP endpoint egress: a loopback endpoint is never proxied, and a name that resolves to an
internal address is refused unless the private-network flag is set."""

import asyncio
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress

import httpx2
import pytest
from mcp_testing import (
    INTERNAL_QUERY,
    NO_PROXY,
    TOKEN,
    TOKEN_ENV,
    FixedClock,
    http_settings,
)

from asca.application.knowledge.models import ProviderError, ProviderErrorKind
from asca.infrastructure.knowledge import url_guard
from asca.infrastructure.knowledge.http import ClientSpec, build_client, select_proxy
from asca.infrastructure.knowledge.mcp_client import McpKnowledgeProvider
from asca.infrastructure.knowledge.settings import NetworkSettings, ProxyMode

pytestmark = pytest.mark.security

ENV_PROXY_VARIABLES = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY")


@contextmanager
def _fake_proxy() -> Iterator[tuple[int, list[bytes]]]:
    """A loopback listener that records whatever a client sends it."""
    received: list[bytes] = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(0.1)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(0.5)
                with suppress(OSError):
                    received.append(conn.recv(65536))

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1], received
    finally:
        stop.set()
        thread.join(2.0)
        listener.close()


def _unused_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "LOCALHOST", "::1", "[::1]"])
def test_loopback_hosts_are_never_proxied(host: str, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (*ENV_PROXY_VARIABLES, "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    explicit = NetworkSettings(ProxyMode.EXPLICIT, "http://proxy.example:3128")
    assert select_proxy(host, NetworkSettings()) is None
    assert select_proxy(host, explicit) is None
    assert select_proxy("chatlas.example", explicit) == "http://proxy.example:3128"


@pytest.mark.parametrize("mode", ["explicit", "env"])
def test_no_request_or_token_reaches_a_proxy_for_an_http_loopback_endpoint(
    mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in (*ENV_PROXY_VARIABLES, "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    with _fake_proxy() as (proxy_port, received):
        proxy_url = f"http://127.0.0.1:{proxy_port}"
        if mode == "explicit":
            network = NetworkSettings(ProxyMode.EXPLICIT, proxy_url)
        else:
            monkeypatch.setenv("HTTPS_PROXY", proxy_url)
            network = NetworkSettings(ProxyMode.ENV)
        url = f"http://127.0.0.1:{_unused_port()}/mcp"
        provider = McpKnowledgeProvider(
            http_settings(url, timeout_s=3.0),
            network=network,
            clock=FixedClock(),
            environ={TOKEN_ENV: TOKEN},
        )
        outcome = asyncio.run(provider.search(INTERNAL_QUERY))
    assert received == []
    assert TOKEN not in repr(outcome)


def _answer(address: str) -> object:
    async def resolver(host: str, port: int) -> list[tuple[object, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]

    return resolver


def _provider_over_a_stub_server(*, allow_private_network: bool) -> McpKnowledgeProvider:
    """Reaches a stub that answers 401, so a refusal and a connection are distinguishable."""

    def factory(spec: ClientSpec, network: NetworkSettings) -> httpx2.AsyncClient:
        return build_client(
            spec, network, httpx2.MockTransport(lambda request: httpx2.Response(401))
        )

    return McpKnowledgeProvider(
        http_settings(
            "https://chatlas.example/mcp",
            allow_insecure_loopback=False,
            allow_private_network=allow_private_network,
        ),
        network=NO_PROXY,
        clock=FixedClock(),
        environ={TOKEN_ENV: TOKEN},
        client_factory=factory,
    )


UNSAFE_URL = ProviderError(ProviderErrorKind.NOT_CONFIGURED, "unsafe_url")
PRIVATE_ADDRESSES = ["10.1.2.3", "192.168.0.5", "172.16.9.9", "100.100.1.1", "fc00::1"]


@pytest.mark.parametrize("address", [*PRIVATE_ADDRESSES, "169.254.169.254", "127.0.0.1"])
def test_a_name_resolving_to_an_internal_address_is_refused_by_default(
    address: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(url_guard, "_default_resolver", _answer(address))
    provider = _provider_over_a_stub_server(allow_private_network=False)
    assert asyncio.run(provider.search(INTERNAL_QUERY)) == UNSAFE_URL


@pytest.mark.parametrize("address", PRIVATE_ADDRESSES)
def test_the_private_network_flag_allows_private_ranges_only(
    address: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(url_guard, "_default_resolver", _answer(address))
    allowed = _provider_over_a_stub_server(allow_private_network=True)
    outcome = asyncio.run(allowed.search(INTERNAL_QUERY))
    assert outcome == ProviderError(ProviderErrorKind.AUTH_REQUIRED, "http_401", 401)


@pytest.mark.parametrize("address", ["169.254.169.254", "127.0.0.1", "0.0.0.0"])
def test_the_private_network_flag_never_allows_metadata_loopback_or_unspecified(
    address: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(url_guard, "_default_resolver", _answer(address))
    provider = _provider_over_a_stub_server(allow_private_network=True)
    assert asyncio.run(provider.search(INTERNAL_QUERY)) == UNSAFE_URL
