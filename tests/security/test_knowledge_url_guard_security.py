"""Endpoint URL and resolved-address refusals (configured MCP URLs, M3b probe target)."""

import asyncio
import ipaddress
import socket
from collections.abc import Sequence
from typing import Any

import pytest

from asca.infrastructure.knowledge.url_guard import (
    UnsafeUrl,
    check_address,
    check_resolved_addresses,
    validate_endpoint_url,
)

pytestmark = pytest.mark.security


def refusal(url: str, *, loopback: bool = False) -> str:
    with pytest.raises(UnsafeUrl) as caught:
        validate_endpoint_url(url, allow_insecure_loopback=loopback)
    assert url not in str(caught.value)
    assert "secret" not in str(caught.value)
    return caught.value.code


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("http://chatlas.example/mcp", "scheme"),
        ("ftp://chatlas.example/mcp", "scheme"),
        ("https://user:secret@chatlas.example/mcp", "userinfo"),
        ("https://chatlas.example/mcp?token=secret", "query"),
        ("https://chatlas.example/mcp?", "query"),
        ("https://chatlas.example/mcp#secret", "fragment"),
        ("https://chatlas.example:0/mcp", "port"),
        ("https://chatlas.example:99999/mcp", "port"),
        ("https://chatlas.example:/mcp", "port"),
        ("https:///mcp", "host"),
        ("https://exa mple.org/mcp", "host"),
        ("https://bücher.example/mcp", "host"),
        ("https://-bad-.example/mcp", "host"),
        ("https://chatlas.example/\x1b[31m", "host"),
        ("https://chatlas.example/" + "x" * 2000, "host"),
    ],
)
def test_unsafe_endpoint_urls_are_refused(url: str, code: str) -> None:
    assert refusal(url) == code


def test_http_is_allowed_only_for_loopback_with_the_flag() -> None:
    assert refusal("http://127.0.0.1:8080/mcp") == "scheme"
    assert refusal("http://10.0.0.1:8080/mcp", loopback=True) == "scheme"
    for url in ("http://127.0.0.1:8080/mcp", "http://[::1]:8080/mcp", "http://localhost/mcp"):
        assert validate_endpoint_url(url, allow_insecure_loopback=True) == url


def test_good_endpoint_urls_are_returned_unchanged() -> None:
    for url in (
        "https://chatlas.example/mcp",
        "https://chatlas.example:8443/mcp/",
        "https://[2001:db8::1]/mcp",
        "https://xn--bcher-kva.example/mcp",
        "https://chatlas.example./mcp",
    ):
        assert validate_endpoint_url(url, allow_insecure_loopback=False) == url
    with pytest.raises(UnsafeUrl):
        validate_endpoint_url(None, allow_insecure_loopback=False)  # type: ignore[arg-type]


def ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    return ipaddress.ip_address(text)


def test_loopback_needs_the_loopback_flag() -> None:
    assert not check_address(ip("127.0.0.1"), allow_private_network=False, allow_loopback=False)
    assert check_address(ip("127.0.0.1"), allow_private_network=False, allow_loopback=True)
    assert not check_address(
        ip("::ffff:127.0.0.1"), allow_private_network=True, allow_loopback=False
    )
    assert check_address(ip("::1"), allow_private_network=False, allow_loopback=True)


@pytest.mark.parametrize(
    "address",
    ["169.254.169.254", "fe80::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "240.0.0.1"],
)
def test_link_local_multicast_unspecified_and_reserved_are_always_refused(address: str) -> None:
    assert not check_address(ip(address), allow_private_network=True, allow_loopback=True)


@pytest.mark.parametrize(
    "address", ["10.0.0.1", "172.16.0.1", "192.168.0.1", "100.64.0.1", "fc00::1"]
)
def test_private_ranges_need_the_private_flag(address: str) -> None:
    assert not check_address(ip(address), allow_private_network=False, allow_loopback=True)
    assert check_address(ip(address), allow_private_network=True, allow_loopback=False)


def test_public_addresses_pass_and_other_special_ranges_fail() -> None:
    assert check_address(ip("188.184.21.108"), allow_private_network=False, allow_loopback=False)
    assert check_address(ip("2001:1458:d00::1"), allow_private_network=False, allow_loopback=False)
    assert not check_address(ip("192.0.2.1"), allow_private_network=True, allow_loopback=True)


def resolver(*addresses: str):  # type: ignore[no-untyped-def]
    async def resolve(host: str, port: int) -> Sequence[tuple[Any, ...]]:
        return [
            (socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port))
            for a in addresses
        ]

    return resolve


def check(
    *addresses: str, private: bool = False, loopback: bool = False, proxied: bool = False
) -> None:
    asyncio.run(
        check_resolved_addresses(
            "chatlas.example",
            443,
            allow_private_network=private,
            allow_loopback=loopback,
            proxied=proxied,
            resolver=resolver(*addresses),
        )
    )


def test_mixed_dns_answer_is_refused() -> None:
    with pytest.raises(UnsafeUrl) as caught:
        check("188.184.21.108", "10.0.0.5")
    assert caught.value.code == "address"
    check("188.184.21.108", "2001:1458:d00::1")
    check("10.0.0.5", private=True)


def test_empty_or_unparsable_answers_are_refused() -> None:
    with pytest.raises(UnsafeUrl):
        check()
    with pytest.raises(UnsafeUrl):
        check("not-an-address")
    with pytest.raises(UnsafeUrl):
        check("fe80::1%eth0", private=True, loopback=True)


def test_proxied_connections_skip_the_dns_check() -> None:
    check("10.0.0.5", proxied=True)


def test_default_resolver_uses_getaddrinfo_and_loopback_literals() -> None:
    asyncio.run(
        check_resolved_addresses(
            "127.0.0.1", 8080, allow_private_network=False, allow_loopback=True, proxied=False
        )
    )
    with pytest.raises(UnsafeUrl):
        asyncio.run(
            check_resolved_addresses(
                "127.0.0.1", 8080, allow_private_network=False, allow_loopback=False, proxied=False
            )
        )
