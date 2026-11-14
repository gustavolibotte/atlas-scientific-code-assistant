"""Opt-in live checks against the real public providers (structure only).

Skipped unless ``ASCA_LIVE=1``; ``tests/conftest.py`` refuses ``ASCA_LIVE`` together with
``CI``, and the CI workflow policy test forbids enabling it in a workflow. Each test sends
at most a handful of requests with the generic User-Agent and the providers' spacing.
"""

from __future__ import annotations

import asyncio
import time

import httpx2
import pytest
from knowledge_exit import exit_query

from asca.application.knowledge.federation import ProviderStatus
from asca.application.knowledge.models import (
    CandidateRef,
    FetchResult,
    KnowledgeQuery,
    ProviderError,
    ProviderErrorKind,
    SearchResult,
)
from asca.application.knowledge.pids import pid_text
from asca.infrastructure.knowledge.arxiv import ArxivProvider
from asca.infrastructure.knowledge.factory import build_federation
from asca.infrastructure.knowledge.hepdata import HepdataProvider
from asca.infrastructure.knowledge.http import ClientSpec, default_client_factory
from asca.infrastructure.knowledge.inspire import InspireProvider
from asca.infrastructure.knowledge.settings import (
    DEFAULT_SETTINGS,
    ArxivSettings,
    HepdataSettings,
    InspireSettings,
    NetworkSettings,
)
from asca.infrastructure.system import SystemClock

pytestmark = [pytest.mark.live, pytest.mark.contract]

DOI = "doi:10.1140/epjc/s10052-010-1354-y"
NETWORK = DEFAULT_SETTINGS.network


def identity_pids(result: FetchResult | SearchResult, index: int = 0) -> set[str]:
    candidate = result.candidate if isinstance(result, FetchResult) else result.candidates[index]
    return {pid_text(pid) for pid in candidate.identity_pids}


def test_live_inspire_search_by_arxiv_id() -> None:
    provider = InspireProvider(InspireSettings(), network=NETWORK, clock=SystemClock())
    outcome = asyncio.run(provider.search(KnowledgeQuery("arxiv:0912.2642", 1)))
    assert isinstance(outcome, SearchResult), outcome
    assert outcome.candidates[0].ref.native_id == "840027"
    assert DOI in identity_pids(outcome)


def test_live_arxiv_fetch_and_spacing() -> None:
    sent: list[float] = []

    async def stamp(request: httpx2.Request) -> None:
        sent.append(time.monotonic())

    def factory(spec: ClientSpec, network: NetworkSettings) -> httpx2.AsyncClient:
        client = default_client_factory(spec, network)
        client.event_hooks["request"].append(stamp)
        return client

    provider = ArxivProvider(
        ArxivSettings(), network=NETWORK, clock=SystemClock(), client_factory=factory
    )

    async def run() -> tuple[object, object]:
        fetched = await provider.fetch(CandidateRef("arxiv", "0912.2642"))
        searched = await provider.search(KnowledgeQuery("observation higgs boson", 1))
        return fetched, searched

    fetched, searched = asyncio.run(run())
    assert isinstance(fetched, FetchResult), fetched
    assert fetched.candidate.version.label == "arXiv:0912.2642v4"
    assert DOI in identity_pids(fetched)
    assert isinstance(searched, SearchResult), searched
    assert len(sent) == 2
    assert sent[1] - sent[0] >= 3.0


def test_live_hepdata_search_is_ok_or_blocked() -> None:
    provider = HepdataProvider(HepdataSettings(), network=NETWORK, clock=SystemClock())
    outcome = asyncio.run(provider.search(exit_query()))
    if isinstance(outcome, ProviderError):
        assert outcome.kind is ProviderErrorKind.BLOCKED
    else:
        assert isinstance(outcome, SearchResult)


def test_live_federated_search_groups_members_from_two_providers() -> None:
    federation = build_federation(DEFAULT_SETTINGS, live=True, clock=SystemClock(), environ={})
    result = asyncio.run(federation.search(exit_query(), only=frozenset({"inspire", "arxiv"})))
    assert [report.status for report in result.reports] == [ProviderStatus.OK] * 2
    assert any(
        len({item.candidate.ref.provider_id for item in group.members}) >= 2
        for group in result.groups
    )
