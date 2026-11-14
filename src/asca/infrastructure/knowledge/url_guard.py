"""Endpoint URL and resolved-address checks for configured MCP URLs and the M3b probe target.

Provider base URLs are fixed constants and never pass through here. Error messages never
contain the URL. The DNS check runs before a session; the rebinding (TOCTOU) gap between
the check and the connection is documented and accepted in ADR 0040.
"""

import asyncio
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Final
from urllib.parse import urlsplit

URL_MAX: Final = 2000
LOOPBACK_HOSTS: Final = frozenset({"127.0.0.1", "::1", "localhost"})
_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_PRIVATE_NETWORKS: Final = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fc00::/7"),
)

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Awaitable[Sequence[tuple[Any, ...]]]]


class UnsafeUrl(ValueError):  # noqa: N818 - name fixed by the M3 spec
    """An endpoint URL or its resolved address was refused; ``code`` names the reason."""

    code: str

    def __init__(self, code: str) -> None:
        super().__init__(f"unsafe endpoint URL ({code})")
        self.code = code


def _ip_literal(host: str) -> IpAddress | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _is_dns_name(host: str) -> bool:
    if not host.isascii() or len(host) > 253:
        return False
    labels = host.removesuffix(".").split(".")
    return all(_LABEL.fullmatch(label) is not None for label in labels)


def validate_endpoint_url(url: str, *, allow_insecure_loopback: bool) -> str:
    """Return ``url`` unchanged when it is an acceptable endpoint; raise ``UnsafeUrl``."""
    if not isinstance(url, str) or not 1 <= len(url) <= URL_MAX:
        raise UnsafeUrl("host")
    if any(char.isspace() or not char.isprintable() for char in url):
        raise UnsafeUrl("host")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in ("https", "http"):
        raise UnsafeUrl("scheme")
    if "@" in parts.netloc:
        raise UnsafeUrl("userinfo")
    if "?" in url:
        raise UnsafeUrl("query")
    if "#" in url:
        raise UnsafeUrl("fragment")
    if not host or (_ip_literal(host) is None and not _is_dns_name(host)):
        raise UnsafeUrl("host")
    if scheme == "http" and not (allow_insecure_loopback and host in LOOPBACK_HOSTS):
        raise UnsafeUrl("scheme")
    try:
        port = parts.port
    except ValueError:
        raise UnsafeUrl("port") from None
    if port is not None and not 1 <= port <= 65535:
        raise UnsafeUrl("port")
    if parts.netloc.endswith(":"):
        raise UnsafeUrl("port")
    return url


def check_address(ip: IpAddress, *, allow_private_network: bool, allow_loopback: bool) -> bool:
    """True when a connection to ``ip`` is acceptable."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return False
    if ip.is_loopback:
        return allow_loopback
    if ip.is_reserved:
        return False
    if any(ip in network for network in _PRIVATE_NETWORKS):
        return allow_private_network
    return ip.is_global


async def _default_resolver(host: str, port: int) -> Sequence[tuple[Any, ...]]:
    loop = asyncio.get_running_loop()
    return await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)


async def check_resolved_addresses(
    host: str,
    port: int,
    *,
    allow_private_network: bool,
    allow_loopback: bool,
    proxied: bool,
    resolver: Resolver | None = None,
) -> None:
    """Refuse when any resolved address is refused. Skipped when a proxy resolves names.

    Resolution errors (``socket.gaierror``) propagate to the caller.
    """
    if proxied:
        return
    answers = await (resolver or _default_resolver)(host, port)
    if not answers:
        raise UnsafeUrl("address")
    for answer in answers:
        literal = _ip_literal(str(answer[4][0]).split("%", 1)[0])
        if literal is None or not check_address(
            literal, allow_private_network=allow_private_network, allow_loopback=allow_loopback
        ):
            raise UnsafeUrl("address")
