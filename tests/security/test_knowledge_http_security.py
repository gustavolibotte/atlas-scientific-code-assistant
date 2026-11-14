"""Outbound HTTP policy: byte caps, encodings, redirects, cookies, netrc, proxies, TLS, JSON."""

import asyncio
import json
import socket
import ssl
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import httpx2
import pytest
from http_replay import (
    ReplayTransport,
    UnexpectedRequest,
    fixture_from_mapping,
    load_fixture,
    make_fixture_document,
    replay_factory,
)

from asca.application.knowledge.models import ProviderError, ProviderErrorKind
from asca.infrastructure.knowledge.http import (
    USER_AGENT,
    BoundedTransport,
    ClientSpec,
    MinIntervalGate,
    RawResponse,
    ResponseTooLarge,
    UnsupportedEncoding,
    bounded_get,
    build_client,
    default_client_factory,
    map_transport_error,
    parse_retry_after,
    select_proxy,
    strict_json,
)
from asca.infrastructure.knowledge.settings import NetworkSettings, ProxyMode

pytestmark = pytest.mark.security

URL = "https://example.org/api"
SPEC = ClientSpec(host="example.org", timeout_s=5.0, max_response_bytes=1024)
NETWORK = NetworkSettings(proxy_mode=ProxyMode.NONE)
Handler = Callable[[httpx2.Request], httpx2.Response]


class Recorder(httpx2.MockTransport):
    def __init__(self, handler: Handler) -> None:
        super().__init__(self._record)
        self._handler = handler
        self.requests: list[httpx2.Request] = []

    def _record(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        return self._handler(request)


def get(
    transport: httpx2.AsyncBaseTransport, spec: ClientSpec = SPEC
) -> RawResponse | ProviderError:
    async def run() -> RawResponse | ProviderError:
        async with build_client(spec, NETWORK, transport) as client:
            return await bounded_get(client, URL, [("q", "x")])

    return asyncio.run(run())


class ExplodingStream(httpx2.AsyncByteStream):
    """A body that must never be read."""

    async def __aiter__(self) -> AsyncIterator[bytes]:
        raise AssertionError("the body was read")
        yield b""  # pragma: no cover


class ChunkedStream(httpx2.AsyncByteStream):
    def __init__(self, chunks: int, size: int) -> None:
        self.chunks = chunks
        self.size = size
        self.sent = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for _ in range(self.chunks):
            self.sent += 1
            yield b"x" * self.size


# ---------------------------------------------------------------------- byte caps and encoding


def test_over_cap_content_length_is_refused_before_reading() -> None:
    transport = Recorder(
        lambda request: httpx2.Response(
            200, headers={"content-length": "4096"}, stream=ExplodingStream()
        )
    )
    assert get(transport) == ProviderError(ProviderErrorKind.RESPONSE_TOO_LARGE, "too_large")


def test_malformed_content_length_is_refused() -> None:
    transport = Recorder(
        lambda request: httpx2.Response(
            200, headers={"content-length": "x"}, stream=ExplodingStream()
        )
    )
    assert get(transport) == ProviderError(ProviderErrorKind.RESPONSE_TOO_LARGE, "too_large")


def test_chunked_over_cap_body_is_aborted() -> None:
    stream = ChunkedStream(chunks=100, size=300)
    transport = Recorder(lambda request: httpx2.Response(200, stream=stream))
    assert get(transport) == ProviderError(ProviderErrorKind.RESPONSE_TOO_LARGE, "too_large")
    assert stream.sent == 4


def test_body_within_cap_is_returned_with_kept_headers_only() -> None:
    transport = Recorder(
        lambda request: httpx2.Response(
            200,
            headers={"content-type": "application/json", "set-cookie": "a=b", "x-other": "1"},
            content=b'{"ok": true}',
        )
    )
    raw = get(transport)
    assert isinstance(raw, RawResponse)
    assert raw.body == b'{"ok": true}'
    assert raw.content_type == "application/json"
    assert raw.headers == (("content-type", "application/json"),)
    assert raw.url == "https://example.org/api?q=x"


@pytest.mark.parametrize("encoding", ["gzip", "br", "deflate, gzip"])
def test_compressed_responses_are_refused(encoding: str) -> None:
    transport = Recorder(
        lambda request: httpx2.Response(
            200, headers={"content-encoding": encoding}, stream=ExplodingStream()
        )
    )
    assert get(transport) == ProviderError(
        ProviderErrorKind.UNSUPPORTED_ENCODING, "content_encoding"
    )


def test_identity_encoding_is_always_requested() -> None:
    transport = Recorder(lambda request: httpx2.Response(200, content=b"{}"))
    spec = ClientSpec(
        host="example.org",
        timeout_s=5.0,
        max_response_bytes=1024,
        extra_headers=(("Accept-Encoding", "gzip"),),
    )
    get(transport, spec)
    assert transport.requests[0].headers["accept-encoding"] == "identity"
    assert transport.requests[0].headers["user-agent"] == USER_AGENT
    assert USER_AGENT == "asca-knowledge/0.1.0"


def test_bounded_transport_forces_identity_on_any_client() -> None:
    inner = Recorder(lambda request: httpx2.Response(200, content=b"ok"))

    async def run() -> None:
        transport = BoundedTransport(inner, max_response_bytes=10)
        async with httpx2.AsyncClient(transport=transport, headers={"Accept-Encoding": "br"}) as c:
            response = await c.get(URL)
            assert response.content == b"ok"

    asyncio.run(run())
    assert inner.requests[0].headers["accept-encoding"] == "identity"


# ---------------------------------------------------------------------- redirects and cookies


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirects_are_refused_and_location_is_never_requested(status: int) -> None:
    transport = Recorder(
        lambda request: httpx2.Response(status, headers={"location": "https://evil.example/x"})
    )
    assert get(transport) == ProviderError(
        ProviderErrorKind.UNEXPECTED_REDIRECT, "redirect_refused", status
    )
    assert [str(r.url.host) for r in transport.requests] == ["example.org"]


def test_set_cookie_is_never_replayed_across_operations() -> None:
    transport = Recorder(
        lambda request: httpx2.Response(
            200, headers={"set-cookie": "session=abc; Path=/"}, content=b"{}"
        )
    )
    get(transport)
    get(transport)
    assert len(transport.requests) == 2
    assert "cookie" not in transport.requests[1].headers


def test_netrc_never_produces_an_authorization_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    netrc = tmp_path / ".netrc"
    netrc.write_text("machine example.org login user password hunter2-secret\n", encoding="utf-8")
    netrc.chmod(0o600)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("NETRC", str(netrc))
    transport = Recorder(lambda request: httpx2.Response(200, content=b"{}"))
    get(transport)
    assert "authorization" not in transport.requests[0].headers


def test_client_spec_repr_never_shows_extra_headers() -> None:
    spec = ClientSpec(
        "example.org", 5.0, 10, extra_headers=(("Authorization", "Bearer canary-token-1234567"),)
    )
    assert "canary" not in repr(spec)
    assert "1 redacted" in repr(spec)


# ---------------------------------------------------------------------- status mapping


@pytest.mark.parametrize(
    ("status", "headers", "expected"),
    [
        (401, {}, ProviderError(ProviderErrorKind.AUTH_REQUIRED, "http_401", 401)),
        (
            403,
            {"cf-mitigated": "challenge"},
            ProviderError(ProviderErrorKind.BLOCKED, "bot_challenge", 403),
        ),
        (
            503,
            {"cf-mitigated": "challenge"},
            ProviderError(ProviderErrorKind.BLOCKED, "bot_challenge", 503),
        ),
        (403, {}, ProviderError(ProviderErrorKind.AUTH_REQUIRED, "http_403", 403)),
        (404, {}, ProviderError(ProviderErrorKind.NOT_FOUND, "not_found", 404)),
        (
            429,
            {"retry-after": "99999"},
            ProviderError(ProviderErrorKind.RATE_LIMITED, "http_429", 429, 3600),
        ),
        (429, {}, ProviderError(ProviderErrorKind.RATE_LIMITED, "http_429", 429)),
        (
            503,
            {"retry-after": "10"},
            ProviderError(ProviderErrorKind.HTTP_STATUS, "http_503", 503, 10),
        ),
        (
            500,
            {"retry-after": "Wed, 21 Oct 2015 07:28:00 GMT"},
            ProviderError(ProviderErrorKind.HTTP_STATUS, "http_500", 500),
        ),
        (418, {"retry-after": "5"}, ProviderError(ProviderErrorKind.HTTP_STATUS, "http_418", 418)),
        (204, {}, ProviderError(ProviderErrorKind.HTTP_STATUS, "http_204", 204)),
    ],
)
def test_status_mapping(status: int, headers: dict[str, str], expected: ProviderError) -> None:
    transport = Recorder(
        lambda request: httpx2.Response(status, headers=headers, stream=ExplodingStream())
    )
    assert get(transport) == expected


def test_retry_after_parsing() -> None:
    assert parse_retry_after(None) is None
    assert parse_retry_after(" 7 ") == 7
    assert parse_retry_after("-1") is None
    assert parse_retry_after("1.5") is None
    assert parse_retry_after("١٢") is None


# ---------------------------------------------------------------------- transport errors


def _caused(exc: BaseException, cause: BaseException) -> BaseException:
    exc.__cause__ = cause
    return exc


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (httpx2.ReadTimeout("t"), "provider_timeout"),
        (httpx2.ConnectTimeout("t"), "provider_timeout"),
        (TimeoutError(), "provider_timeout"),
        (_caused(httpx2.ConnectError("c"), socket.gaierror(-2, "Name unknown")), "dns_failed"),
        (_caused(httpx2.ConnectError("c"), ssl.SSLCertVerificationError("bad cert")), "tls_failed"),
        (httpx2.ConnectError("refused"), "connect_failed"),
        (ResponseTooLarge(), "too_large"),
        (UnsupportedEncoding(), "content_encoding"),
        (httpx2.RemoteProtocolError("bad"), "unexpected_payload"),
        (httpx2.ReadError("reset"), "unexpected_payload"),
        (ValueError("secret-canary"), "unexpected_exception"),
    ],
)
def test_transport_error_mapping_never_uses_exception_text(exc: BaseException, code: str) -> None:
    error = map_transport_error(exc)
    assert error.code == code
    assert "canary" not in repr(error)


def test_error_context_chain_is_walked_without_loops() -> None:
    outer = httpx2.ConnectError("outer")
    inner = OSError("inner")
    inner.__context__ = outer
    outer.__context__ = inner
    assert map_transport_error(outer).code == "connect_failed"


def test_transport_exceptions_become_values_in_bounded_get() -> None:
    def fail(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("refused", request=request)

    assert get(Recorder(fail)) == ProviderError(ProviderErrorKind.CONNECT_FAILED, "connect_failed")


# ---------------------------------------------------------------------- proxies and TLS


def test_select_proxy_honours_environment_and_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    assert select_proxy("inspirehep.net", NetworkSettings()) == "http://proxy.example:3128"
    monkeypatch.setenv("NO_PROXY", "inspirehep.net,.arxiv.org")
    assert select_proxy("inspirehep.net", NetworkSettings()) is None
    assert select_proxy("export.arxiv.org", NetworkSettings()) is None
    assert select_proxy("www.hepdata.net", NetworkSettings()) == "http://proxy.example:3128"
    assert select_proxy("www.hepdata.net", NetworkSettings(ProxyMode.NONE)) is None
    explicit = NetworkSettings(ProxyMode.EXPLICIT, "https://corp.example:8443")
    assert select_proxy("inspirehep.net", explicit) == "https://corp.example:8443"
    monkeypatch.delenv("HTTPS_PROXY")
    monkeypatch.delenv("NO_PROXY")
    assert select_proxy("inspirehep.net", NetworkSettings()) is None


def _inner_pool(client: httpx2.AsyncClient) -> object:
    transport = client._transport
    assert isinstance(transport, BoundedTransport)
    inner = transport._inner
    assert isinstance(inner, httpx2.AsyncHTTPTransport)
    return inner._pool


@pytest.mark.parametrize(
    "network",
    [
        NetworkSettings(ProxyMode.NONE),
        NetworkSettings(ProxyMode.EXPLICIT, "http://proxy.example:3128"),
    ],
)
def test_default_factory_never_disables_tls_verification(network: NetworkSettings) -> None:
    async def run() -> None:
        async with default_client_factory(SPEC, network) as client:
            pool = _inner_pool(client)
            context = pool._ssl_context  # type: ignore[attr-defined]
            assert context.verify_mode is ssl.CERT_REQUIRED
            assert context.check_hostname is True
            assert client.follow_redirects is False
            assert client.headers["accept-encoding"] == "identity"

    asyncio.run(run())


def test_default_factory_uses_the_selected_proxy() -> None:
    explicit = NetworkSettings(ProxyMode.EXPLICIT, "http://proxy.example:3128")

    async def run() -> None:
        async with default_client_factory(SPEC, explicit) as client:
            pool = _inner_pool(client)
            assert type(pool).__name__ == "AsyncHTTPProxy"
        async with default_client_factory(SPEC, NETWORK) as client:
            assert type(_inner_pool(client)).__name__ == "AsyncConnectionPool"

    asyncio.run(run())


# ---------------------------------------------------------------------- strict JSON


def test_strict_json_accepts_plain_documents() -> None:
    assert strict_json(b'{"a": [1, 2.5, "x", null, true]}') == {"a": [1, 2.5, "x", None, True]}
    assert strict_json(json.dumps([[0]] * 3).encode()) == [[0]] * 3


@pytest.mark.parametrize(
    "body",
    [
        b'{"a": NaN}',
        b'{"a": Infinity}',
        b'{"a": -Infinity}',
        b'{"a": 1, "a": 2}',
        b"[" * 100 + b"]" * 100,
        b'{"a": "\xff"}',
        b"[" * 100_000,
        b"not json",
    ],
)
def test_strict_json_rejects_unsafe_documents(body: bytes) -> None:
    assert strict_json(body) == ProviderError(ProviderErrorKind.MALFORMED_RESPONSE, "invalid_json")


def test_strict_json_depth_limit_is_64() -> None:
    assert not isinstance(strict_json(b"[" * 64 + b"]" * 64), ProviderError)
    assert isinstance(strict_json(b"[" * 65 + b"]" * 65), ProviderError)


# ---------------------------------------------------------------------- gate


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def test_min_interval_gate_spaces_requests_within_budget() -> None:
    clock = FakeClock()
    gate = MinIntervalGate(3.0, monotonic=clock.monotonic, sleep=clock.sleep)
    assert asyncio.run(gate.wait(10.0)) is None
    clock.now += 1.0
    assert asyncio.run(gate.wait(10.0)) is None
    assert clock.sleeps == [2.0]
    clock.now += 0.5
    assert asyncio.run(gate.wait(1.0)) == ProviderError(
        ProviderErrorKind.RATE_LIMITED, "local_gate"
    )
    assert clock.sleeps == [2.0]
    clock.now += 10.0
    assert asyncio.run(gate.wait(0.0)) is None


def test_min_interval_gate_serialises_concurrent_callers() -> None:
    clock = FakeClock()
    gate = MinIntervalGate(1.0, monotonic=clock.monotonic, sleep=clock.sleep)

    async def run() -> list[ProviderError | None]:
        return list(await asyncio.gather(*(gate.wait(10.0) for _ in range(3))))

    assert asyncio.run(run()) == [None, None, None]
    assert clock.sleeps == [1.0, 1.0]


# ---------------------------------------------------------------------- replay support


def _fixture(**kwargs: object) -> dict[str, object]:
    base: dict[str, object] = {
        "provider": "inspire",
        "scenario": "synthetic_search",
        "url": "https://inspirehep.net/api/literature",
        "params": [("size", "1"), ("q", "x")],
        "headers": {"content-type": "application/json"},
        "body_text": '{"hits": {"total": 0, "hits": []}}',
    }
    base.update(kwargs)
    return make_fixture_document(**base)  # type: ignore[arg-type]


def test_replay_matches_on_sorted_query_and_records_requests(tmp_path: Path) -> None:
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(_fixture()), encoding="utf-8")
    fixture = load_fixture(path)
    transport = ReplayTransport([fixture])
    factory = replay_factory(transport)
    spec = ClientSpec("inspirehep.net", 5.0, 1024)

    async def run() -> RawResponse | ProviderError:
        async with factory(spec, NETWORK) as client:
            return await bounded_get(
                client, "https://inspirehep.net/api/literature", [("q", "x"), ("size", "1")]
            )

    raw = asyncio.run(run())
    assert isinstance(raw, RawResponse) and raw.status == 200
    transport.assert_all_used()
    request = transport.requests[0]
    assert request.headers["user-agent"] == USER_AGENT
    assert request.headers["accept-encoding"] == "identity"
    assert "cookie" not in request.headers and "authorization" not in request.headers


def test_replay_refuses_unknown_requests_and_reports_unused_fixtures() -> None:
    transport = ReplayTransport(
        [fixture_from_mapping(_fixture())], delays={"inspirehep.net": 0.001}
    )

    async def run() -> None:
        async with replay_factory(transport)(ClientSpec("inspirehep.net", 5.0, 1024), NETWORK) as c:
            await c.get("https://inspirehep.net/api/other", params={"secret": "query"})

    with pytest.raises(UnexpectedRequest, match="/api/other") as caught:
        asyncio.run(run())
    assert "secret" not in str(caught.value)
    with pytest.raises(AssertionError, match="unexpected requests"):
        transport.assert_all_used()
    unused = ReplayTransport([fixture_from_mapping(_fixture())])
    with pytest.raises(AssertionError, match="unused fixtures"):
        unused.assert_all_used()


def test_replay_fixture_validation() -> None:
    with pytest.raises(ValueError):
        fixture_from_mapping({**_fixture(), "format": "other"})
    tampered = _fixture()
    tampered["response"] = {**tampered["response"], "body_sha256": "0" * 64}  # type: ignore[dict-item]
    with pytest.raises(ValueError):
        fixture_from_mapping(tampered)
    with pytest.raises(ValueError):
        fixture_from_mapping(_fixture(headers={"set-cookie": "a=b"}))
    duplicate = fixture_from_mapping(_fixture())
    with pytest.raises(ValueError):
        ReplayTransport([duplicate, duplicate])
