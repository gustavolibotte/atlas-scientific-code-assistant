"""Builders for the public HTTP adapters over replayed fixtures, with fake time.

No test using these helpers can reach the network: every request goes through a
``ReplayTransport``, which raises on any request without a fixture.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx2
from http_replay import Fixture, ReplayTransport, fixture_from_mapping, load_fixture, replay_factory

from asca.application.demo import FixedClock
from asca.infrastructure.knowledge.arxiv import ArxivProvider
from asca.infrastructure.knowledge.hepdata import HepdataProvider
from asca.infrastructure.knowledge.http import USER_AGENT
from asca.infrastructure.knowledge.inspire import InspireProvider
from asca.infrastructure.knowledge.settings import (
    ArxivSettings,
    HepdataSettings,
    InspireSettings,
    NetworkSettings,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "knowledge"
NOW = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)
CLOCK = FixedClock(NOW)
NETWORK = NetworkSettings()
EXIT_QUERY = "energy reconstruction liquid argon calorimeter neural network"


def fixture(name: str) -> Fixture:
    return load_fixture(FIXTURES / name)


@dataclass
class FakeTime:
    """A monotonic clock advanced only by ``sleep``; records every sleep."""

    now: float = 1000.0
    sleeps: list[float] = field(default_factory=list)

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def transport(*fixtures: Fixture | Mapping[str, object] | str) -> ReplayTransport:
    loaded: list[Fixture] = []
    for item in fixtures:
        if isinstance(item, str):
            loaded.append(fixture(item))
        elif isinstance(item, Fixture):
            loaded.append(item)
        else:
            loaded.append(fixture_from_mapping(item))
    return ReplayTransport(loaded)


def _common(replay: httpx2.AsyncBaseTransport, time: FakeTime | None) -> dict[str, Any]:
    clock_time = time or FakeTime()
    return {
        "network": NETWORK,
        "clock": CLOCK,
        "client_factory": replay_factory(replay),
        "monotonic": clock_time.monotonic,
        "sleep": clock_time.sleep,
    }


def inspire(
    replay: httpx2.AsyncBaseTransport, *, time: FakeTime | None = None, timeout_s: float = 10.0
) -> InspireProvider:
    return InspireProvider(InspireSettings(timeout_s=timeout_s), **_common(replay, time))


def arxiv(
    replay: httpx2.AsyncBaseTransport,
    *,
    time: FakeTime | None = None,
    timeout_s: float = 15.0,
    min_interval_s: float = 3.0,
) -> ArxivProvider:
    settings = ArxivSettings(timeout_s=timeout_s, min_interval_s=min_interval_s)
    return ArxivProvider(settings, **_common(replay, time))


def hepdata(
    replay: httpx2.AsyncBaseTransport, *, time: FakeTime | None = None, timeout_s: float = 10.0
) -> HepdataProvider:
    return HepdataProvider(HepdataSettings(timeout_s=timeout_s), **_common(replay, time))


def assert_polite_requests(replay: ReplayTransport, hosts: Iterable[str]) -> None:
    """Generic User-Agent, identity encoding, no cookies or credentials, known hosts only."""
    allowed = set(hosts)
    assert replay.requests, "no request was sent"
    for request in replay.requests:
        assert request.url.host in allowed
        assert request.url.scheme == "https"
        assert request.headers["User-Agent"] == USER_AGENT
        assert request.headers["Accept-Encoding"] == "identity"
        assert "cookie" not in request.headers
        assert "authorization" not in request.headers
