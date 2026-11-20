"""Replay of recorded HTTP exchanges (format ``asca-http-fixture/1``); never the network.

An unknown request raises ``UnexpectedRequest`` naming only the path, and is also recorded
in ``unexpected`` so a test fails even when an adapter or the federation turns the
exception into an error value.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl

import httpx2

from asca.infrastructure.knowledge.http import ClientFactory, ClientSpec, build_client
from asca.infrastructure.knowledge.settings import NetworkSettings

FIXTURE_FORMAT = "asca-http-fixture/1"
ALLOWED_RESPONSE_HEADERS = frozenset(
    {"content-type", "retry-after", "cf-mitigated", "www-authenticate", "location"}
)

MatchKey = tuple[str, str, tuple[tuple[str, str], ...]]


class UnexpectedRequest(AssertionError):  # noqa: N818 - name fixed by the M3 spec
    """A request that no fixture matches."""


@dataclass(frozen=True, slots=True)
class Fixture:
    provider: str
    scenario: str
    synthetic: bool
    method: str
    url: str
    params: tuple[tuple[str, str], ...]
    status: int
    headers: tuple[tuple[str, str], ...]
    body_text: str

    @property
    def key(self) -> MatchKey:
        return (self.method.upper(), self.url, tuple(sorted(self.params)))


def fixture_from_mapping(data: Mapping[str, object]) -> Fixture:
    if data.get("format") != FIXTURE_FORMAT:
        raise ValueError("not an asca-http-fixture/1 document")
    request = data["request"]
    response = data["response"]
    assert isinstance(request, dict) and isinstance(response, dict)
    body_text = response["body_text"]
    assert isinstance(body_text, str)
    if hashlib.sha256(body_text.encode("utf-8")).hexdigest() != response["body_sha256"]:
        raise ValueError("fixture body_sha256 does not match body_text")
    headers = response.get("headers", {})
    assert isinstance(headers, dict)
    if not set(headers) <= ALLOWED_RESPONSE_HEADERS:
        raise ValueError("fixture has a response header outside the allowlist")
    synthetic = data["synthetic"]
    assert isinstance(synthetic, bool)
    return Fixture(
        provider=str(data["provider"]),
        scenario=str(data["scenario"]),
        synthetic=synthetic,
        method=str(request["method"]),
        url=str(request["url"]),
        params=tuple((str(k), str(v)) for k, v in request.get("params", [])),
        status=int(response["status"]),
        headers=tuple((str(k), str(v)) for k, v in headers.items()),
        body_text=body_text,
    )


def load_fixture(path: Path) -> Fixture:
    return fixture_from_mapping(json.loads(path.read_text(encoding="utf-8")))


def make_fixture_document(
    *,
    provider: str,
    scenario: str,
    url: str,
    params: Iterable[tuple[str, str]] = (),
    status: int = 200,
    headers: Mapping[str, str] | None = None,
    body_text: str = "",
    synthetic: bool = True,
) -> dict[str, object]:
    """A synthetic fixture document, for tests that do not need a committed file."""
    return {
        "format": FIXTURE_FORMAT,
        "provider": provider,
        "scenario": scenario,
        "synthetic": synthetic,
        "request": {"method": "GET", "url": url, "params": sorted(params)},
        "response": {
            "status": status,
            "headers": dict(headers or {}),
            "body_text": body_text,
            "body_sha256": hashlib.sha256(body_text.encode("utf-8")).hexdigest(),
        },
    }


def _key(request: httpx2.Request) -> MatchKey:
    url = request.url
    base = f"{url.scheme}://{url.host}{url.path}"
    query = parse_qsl(url.query.decode("ascii"), keep_blank_values=True)
    return (request.method.upper(), base, tuple(sorted(query)))


class ReplayTransport(httpx2.MockTransport):
    def __init__(
        self, fixtures: Iterable[Fixture], *, delays: Mapping[str, float] | None = None
    ) -> None:
        super().__init__(self._handle)
        self._fixtures: dict[MatchKey, Fixture] = {}
        for fixture in fixtures:
            if fixture.key in self._fixtures:
                raise ValueError("two fixtures share one request")
            self._fixtures[fixture.key] = fixture
        self._delays = dict(delays or {})
        self._used: set[MatchKey] = set()
        self.requests: list[httpx2.Request] = []
        self.unexpected: list[str] = []

    async def _handle(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        delay = self._delays.get(request.url.host, 0.0)
        if delay:
            await asyncio.sleep(delay)
        key = _key(request)
        fixture = self._fixtures.get(key)
        if fixture is None:
            self.unexpected.append(request.url.path)
            raise UnexpectedRequest(f"unexpected request to path {request.url.path}")
        self._used.add(key)
        return httpx2.Response(
            fixture.status,
            headers=list(fixture.headers),
            content=fixture.body_text.encode("utf-8"),
            request=request,
        )

    def assert_all_used(self) -> None:
        assert not self.unexpected, f"unexpected requests: {self.unexpected}"
        unused = sorted(
            f"{fixture.provider}/{fixture.scenario}"
            for key, fixture in self._fixtures.items()
            if key not in self._used
        )
        assert not unused, f"unused fixtures: {unused}"


def replay_factory(transport: httpx2.AsyncBaseTransport) -> ClientFactory:
    """A ``ClientFactory`` that builds clients exactly like the default one, over replay."""

    def factory(spec: ClientSpec, network: NetworkSettings) -> httpx2.AsyncClient:
        return build_client(spec, network, transport)

    return factory
