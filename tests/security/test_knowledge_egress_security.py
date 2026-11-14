"""Egress rules: public adapters never receive sensitive queries; the recorder records only
fixed public scenarios (recorder and HTTP adapter part)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from knowledge_adapters import arxiv, hepdata, inspire, transport

from asca.application.knowledge.models import KnowledgeQuery, ProviderError, ProviderErrorKind
from asca.domain.provenance import AccessClass
from asca.infrastructure.knowledge import recording
from asca.infrastructure.knowledge.arxiv import ARXIV_API
from asca.infrastructure.knowledge.hepdata import HEPDATA_SEARCH
from asca.infrastructure.knowledge.inspire import INSPIRE_API
from asca.infrastructure.knowledge.recording import (
    PUBLIC_PROVIDERS,
    SCENARIOS,
    RecordingRefused,
    Scenario,
)

pytestmark = pytest.mark.security

REFUSED = ProviderError(ProviderErrorKind.NOT_CONSULTED, "query_access_class")


def run(coro: Any) -> Any:
    return asyncio.run(coro)


@pytest.mark.parametrize("access", [AccessClass.INTERNAL, AccessClass.RESTRICTED])
@pytest.mark.parametrize("build", [inspire, arxiv, hepdata], ids=["inspire", "arxiv", "hepdata"])
def test_sensitive_queries_send_zero_requests_to_public_adapters(
    build: Any, access: AccessClass
) -> None:
    replay = transport()
    query = KnowledgeQuery("Synthetic internal note on liquid argon calibration", 5, access)
    assert run(build(replay).search(query)) == REFUSED
    assert replay.requests == []


@pytest.mark.parametrize("provider", ["local", "mcp:chatlas", "mcp", "cds", "Inspire"])
def test_the_recorder_refuses_non_public_providers(provider: str) -> None:
    with pytest.raises(RecordingRefused, match="public providers only"):
        Scenario(provider, "x", INSPIRE_API, ())


@pytest.mark.parametrize(
    ("provider", "url"),
    [
        ("inspire", "https://inspirehep.net/api/literature/1920956"),
        ("arxiv", "https://evil.example/api/query"),
        ("hepdata", "http://www.hepdata.net/search/"),
    ],
)
def test_the_recorder_refuses_urls_other_than_the_fixed_base(provider: str, url: str) -> None:
    with pytest.raises(RecordingRefused, match="fixed base URL"):
        Scenario(provider, "x", url, ())


def test_the_scenario_table_is_fixed_public_and_free_of_urls() -> None:
    assert {scenario.provider for scenario in SCENARIOS} == set(PUBLIC_PROVIDERS)
    assert {scenario.url for scenario in SCENARIOS} == {INSPIRE_API, ARXIV_API, HEPDATA_SEARCH}
    for scenario in SCENARIOS:
        for _, value in scenario.params:
            assert "://" not in value


def test_the_recorder_refuses_unknown_scenarios_and_non_public_fixtures() -> None:
    with pytest.raises(RecordingRefused):
        recording.select(["local/manifest"])
    with pytest.raises(RecordingRefused):
        recording.select(["mcp:chatlas/search"])
    with pytest.raises(RecordingRefused):
        recording.fixture_document(
            provider="mcp:chatlas",
            scenario="x",
            url="https://chatlas.example/mcp",
            params=(),
            status=200,
            headers=(),
            body_text="",
            sanitized=(),
            recorded_at=recording._UtcClock().now(),
            synthetic=False,
        )
