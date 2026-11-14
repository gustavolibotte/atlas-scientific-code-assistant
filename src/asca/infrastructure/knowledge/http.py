"""Outbound HTTP policy shared by every knowledge adapter (httpx2 only).

One client per operation; TLS always verified (no setting can disable it); no redirects;
``Accept-Encoding: identity``; byte caps enforced by ``BoundedTransport`` before and while
reading; a generic User-Agent with no personal data; no retries. Exception text is never
used: failures map to fixed ``ProviderError`` codes.
"""

import asyncio
import json
import socket
import ssl
import urllib.request
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Final, NoReturn

import httpx2

import asca
from asca.application.knowledge.models import ProviderError, ProviderErrorKind
from asca.infrastructure.knowledge.settings import NetworkSettings, ProxyMode

USER_AGENT: Final = f"asca-knowledge/{asca.__version__}"
JSON_DEPTH_MAX: Final = 64
RETRY_AFTER_MAX: Final = 3600
KEPT_HEADERS: Final = ("content-type", "retry-after", "cf-mitigated", "www-authenticate")
# Not declared in typeshed, but part of urllib.request on every supported Python version.
_proxy_bypass_environment: Callable[[str], bool] = urllib.request.proxy_bypass_environment  # type: ignore[attr-defined]


@dataclass(frozen=True, slots=True)
class ClientSpec:
    host: str
    """Target host (for proxy selection)."""
    timeout_s: float
    max_response_bytes: int
    max_connections: int = 2
    accept: str = "application/json"
    extra_headers: tuple[tuple[str, str], ...] = ()
    """MCP bearer only; never logged."""

    def __repr__(self) -> str:
        return (
            f"ClientSpec(host={self.host!r}, timeout_s={self.timeout_s!r}, "
            f"max_response_bytes={self.max_response_bytes!r}, "
            f"max_connections={self.max_connections!r}, accept={self.accept!r}, "
            f"extra_headers=<{len(self.extra_headers)} redacted>)"
        )


ClientFactory = Callable[[ClientSpec, NetworkSettings], httpx2.AsyncClient]


class ResponseTooLarge(Exception):  # noqa: N818 - name fixed by the M3 spec
    """The response exceeded its byte cap."""


class UnsupportedEncoding(Exception):  # noqa: N818 - name fixed by the M3 spec
    """The response used a content encoding other than identity."""


def select_proxy(host: str, network: NetworkSettings) -> str | None:
    """The HTTPS proxy for ``host``; an explicit transport disables httpx2's env handling."""
    if network.proxy_mode is ProxyMode.NONE:
        return None
    if network.proxy_mode is ProxyMode.EXPLICIT:
        return network.proxy_url
    if _proxy_bypass_environment(host):
        return None
    return urllib.request.getproxies_environment().get("https")


class _BoundedStream(httpx2.AsyncByteStream):
    def __init__(self, inner: httpx2.AsyncByteStream, max_bytes: int) -> None:
        self._inner = inner
        self._max_bytes = max_bytes

    async def __aiter__(self) -> AsyncIterator[bytes]:
        total = 0
        async for chunk in self._inner:
            total += len(chunk)
            if total > self._max_bytes:
                raise ResponseTooLarge
            yield chunk

    async def aclose(self) -> None:
        await self._inner.aclose()


class BoundedTransport(httpx2.AsyncBaseTransport):
    """Forces ``Accept-Encoding: identity`` and enforces the response byte cap."""

    def __init__(self, inner: httpx2.AsyncBaseTransport, *, max_response_bytes: int) -> None:
        self._inner = inner
        self._max_bytes = max_response_bytes

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        request.headers["Accept-Encoding"] = "identity"
        response = await self._inner.handle_async_request(request)
        encoding = response.headers.get("content-encoding", "").strip().lower()
        if encoding not in ("", "identity"):
            await response.aclose()
            raise UnsupportedEncoding
        length = response.headers.get("content-length")
        if length is not None and (not length.strip().isdigit() or int(length) > self._max_bytes):
            await response.aclose()
            raise ResponseTooLarge
        stream = response.stream
        if not isinstance(stream, httpx2.AsyncByteStream):  # pragma: no cover - httpx2 invariant
            raise TypeError("an async transport must return an async stream")
        return httpx2.Response(
            response.status_code,
            headers=response.headers,
            stream=_BoundedStream(stream, self._max_bytes),
            extensions=response.extensions,
            request=request,
        )

    async def aclose(self) -> None:
        await self._inner.aclose()


def build_client(
    spec: ClientSpec, network: NetworkSettings, transport: httpx2.AsyncBaseTransport
) -> httpx2.AsyncClient:
    """Build a client around ``transport`` (wrapped in ``BoundedTransport``).

    ``network`` is accepted so replay and default clients share one signature; the proxy
    is wired into the inner transport by ``default_client_factory``.
    """
    del network
    t = spec.timeout_s
    return httpx2.AsyncClient(
        transport=BoundedTransport(transport, max_response_bytes=spec.max_response_bytes),
        follow_redirects=False,
        trust_env=True,
        timeout=httpx2.Timeout(connect=min(5.0, t), read=t, write=min(5.0, t), pool=min(5.0, t)),
        headers={
            "User-Agent": USER_AGENT,
            "Accept": spec.accept,
            "Accept-Encoding": "identity",
            **dict(spec.extra_headers),
        },
    )


def default_client_factory(spec: ClientSpec, network: NetworkSettings) -> httpx2.AsyncClient:
    """The production client: TLS verification is never disabled (``verify`` not passed)."""
    inner = httpx2.AsyncHTTPTransport(
        retries=0,
        trust_env=True,
        http2=False,
        limits=httpx2.Limits(
            max_connections=spec.max_connections,
            max_keepalive_connections=spec.max_connections,
        ),
        proxy=select_proxy(spec.host, network),
    )
    return build_client(spec, network, inner)


@dataclass(frozen=True, slots=True)
class RawResponse:
    status: int
    content_type: str
    body: bytes
    url: str
    headers: tuple[tuple[str, str], ...]


def parse_retry_after(value: str | None) -> int | None:
    """Integer seconds only, clamped to 0..3600; anything else is ``None``."""
    if value is None:
        return None
    text = value.strip()
    if not text.isdigit() or not text.isascii():
        return None
    return min(int(text), RETRY_AFTER_MAX)


def map_status(status: int, headers: httpx2.Headers) -> ProviderError:
    """Map a non-200 status to a ``ProviderError``; redirects are never followed."""
    challenge = headers.get("cf-mitigated", "").strip().lower() == "challenge"
    retry = parse_retry_after(headers.get("retry-after"))
    if 300 <= status < 400:
        return ProviderError(ProviderErrorKind.UNEXPECTED_REDIRECT, "redirect_refused", status)
    if status == 401:
        return ProviderError(ProviderErrorKind.AUTH_REQUIRED, "http_401", status)
    if status in (403, 503) and challenge:
        return ProviderError(ProviderErrorKind.BLOCKED, "bot_challenge", status)
    if status == 403:
        return ProviderError(ProviderErrorKind.AUTH_REQUIRED, "http_403", status)
    if status == 404:
        return ProviderError(ProviderErrorKind.NOT_FOUND, "not_found", status)
    if status == 429:
        return ProviderError(ProviderErrorKind.RATE_LIMITED, "http_429", status, retry)
    if 500 <= status <= 599:
        return ProviderError(ProviderErrorKind.HTTP_STATUS, f"http_{status}", status, retry)
    return ProviderError(ProviderErrorKind.HTTP_STATUS, f"http_{status}", status)


async def bounded_get(
    client: httpx2.AsyncClient, url: str, params: Sequence[tuple[str, str]]
) -> RawResponse | ProviderError:
    """Send one GET and map the outcome; the body is read only for a 200."""
    try:
        async with client.stream("GET", url, params=list(params)) as response:
            if response.status_code != 200:
                return map_status(response.status_code, response.headers)
            body = await response.aread()
            kept = tuple(
                (name, response.headers[name]) for name in KEPT_HEADERS if name in response.headers
            )
            return RawResponse(
                status=200,
                content_type=response.headers.get("content-type", ""),
                body=body,
                url=str(response.url),
                headers=kept,
            )
    except (httpx2.HTTPError, ResponseTooLarge, UnsupportedEncoding) as exc:
        return map_transport_error(exc)


def _chain(exc: BaseException) -> list[BaseException]:
    seen: list[BaseException] = []
    pending: list[BaseException | None] = [exc]
    while pending:
        item = pending.pop()
        if item is None or any(item is known for known in seen):
            continue
        seen.append(item)
        pending.extend((item.__cause__, item.__context__))
    return seen


def map_transport_error(exc: BaseException) -> ProviderError:
    """Map an HTTP failure to a fixed code; exception text is never used."""
    chain = _chain(exc)
    if isinstance(exc, httpx2.TimeoutException | TimeoutError):
        return ProviderError(ProviderErrorKind.TIMEOUT, "provider_timeout")
    if isinstance(exc, ResponseTooLarge):
        return ProviderError(ProviderErrorKind.RESPONSE_TOO_LARGE, "too_large")
    if isinstance(exc, UnsupportedEncoding):
        return ProviderError(ProviderErrorKind.UNSUPPORTED_ENCODING, "content_encoding")
    if isinstance(exc, httpx2.ConnectError) and any(
        isinstance(item, socket.gaierror) for item in chain
    ):
        return ProviderError(ProviderErrorKind.DNS_FAILED, "dns_failed")
    if any(isinstance(item, ssl.SSLError) for item in chain):
        return ProviderError(ProviderErrorKind.TLS_FAILED, "tls_failed")
    if isinstance(exc, httpx2.ConnectError):
        return ProviderError(ProviderErrorKind.CONNECT_FAILED, "connect_failed")
    if isinstance(exc, httpx2.HTTPError):
        return ProviderError(ProviderErrorKind.MALFORMED_RESPONSE, "unexpected_payload")
    return ProviderError(ProviderErrorKind.INTERNAL_ERROR, "unexpected_exception")


def _reject_constant(value: str) -> NoReturn:
    raise ValueError("non-finite JSON number")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _depth_ok(value: object) -> bool:
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict | list):
            if depth > JSON_DEPTH_MAX:
                return False
            children = item.values() if isinstance(item, dict) else item
            stack.extend((child, depth + 1) for child in children)
    return True


def strict_json(body: bytes) -> object | ProviderError:
    """Strict UTF-8, no duplicate keys, no NaN/Infinity, nesting depth at most 64."""
    invalid = ProviderError(ProviderErrorKind.MALFORMED_RESPONSE, "invalid_json")
    try:
        value: object = json.loads(
            body.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (RecursionError, ValueError, UnicodeDecodeError):
        return invalid
    return value if _depth_ok(value) else invalid


class MinIntervalGate:
    """Spaces requests at least ``min_interval_s`` apart, inside the caller's budget."""

    def __init__(
        self,
        min_interval_s: float,
        *,
        monotonic: Callable[[], float],
        sleep: Callable[[float], Awaitable[None]],
    ) -> None:
        self._interval = min_interval_s
        self._monotonic = monotonic
        self._sleep = sleep
        self._last: float | None = None
        self._lock: asyncio.Lock | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    def _current_lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._lock is None or self._loop is not loop:
            self._lock = asyncio.Lock()
            self._loop = loop
        return self._lock

    async def wait(self, budget_remaining_s: float) -> ProviderError | None:
        """Sleep until the next request may go, or refuse without sleeping when over budget.

        The release time is recorded as the time of the request, which the caller sends
        immediately after this returns.
        """
        async with self._current_lock():
            earliest = self._monotonic() if self._last is None else self._last + self._interval
            delay = earliest - self._monotonic()
            if delay > 0:
                if delay > budget_remaining_s:
                    return ProviderError(ProviderErrorKind.RATE_LIMITED, "local_gate")
                await self._sleep(delay)
            self._last = max(self._monotonic(), earliest)
            return None
