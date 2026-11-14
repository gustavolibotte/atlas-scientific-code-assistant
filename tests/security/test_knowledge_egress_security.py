"""Egress rules: public adapters never receive sensitive queries or internal documents; the
recorder records only fixed public scenarios (recorder, HTTP adapter and federation parts)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

import pytest
from http_replay import replay_factory
from knowledge_adapters import CLOCK, arxiv, hepdata, inspire, transport
from knowledge_exit import LOCAL_TITLE, exit_query, exit_settings, exit_transport, make_library

from asca.application.knowledge.models import KnowledgeQuery, ProviderError, ProviderErrorKind
from asca.domain.provenance import AccessClass
from asca.infrastructure.knowledge import recording
from asca.infrastructure.knowledge.arxiv import ARXIV_API
from asca.infrastructure.knowledge.factory import build_federation
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


# ---------------------------------------------------------------------- federation part


def _sent_text(request: Any) -> str:
    """Everything a request carries, URL-decoded: URL, headers and body."""
    url = unquote_plus(str(request.url))
    headers = " ".join(f"{name}: {value}" for name, value in request.headers.items())
    return f"{url}\n{headers}\n{request.content.decode('utf-8', 'replace')}"


def test_internal_local_document_never_appears_in_any_outbound_request(tmp_path: Path) -> None:
    library = make_library(tmp_path)
    note = (library / "notes" / "optimal-filtering.md").read_text(encoding="utf-8")
    replay = exit_transport()
    federation = build_federation(
        exit_settings(library),
        live=True,
        clock=CLOCK,
        client_factory=replay_factory(replay),
        environ={},
    )
    result = run(federation.search(exit_query()))
    local = [
        item
        for group in result.groups
        for item in group.members
        if item.candidate.ref.provider_id == "local"
    ]
    assert len(local) == 1 and local[0].candidate.access_class is AccessClass.INTERNAL
    assert len(replay.requests) == 3
    secret_lines = [line.strip() for line in note.splitlines() if line.strip()]
    for request in replay.requests:
        sent = _sent_text(request)
        assert LOCAL_TITLE not in sent
        assert "Synthetic internal test material" not in sent
        for line in secret_lines:
            assert line not in sent


def test_internal_query_through_the_federation_sends_zero_requests(tmp_path: Path) -> None:
    library = make_library(tmp_path)
    replay = exit_transport()
    federation = build_federation(
        exit_settings(library),
        live=True,
        clock=CLOCK,
        client_factory=replay_factory(replay),
        environ={},
    )
    query = KnowledgeQuery(LOCAL_TITLE, 5, AccessClass.INTERNAL)
    result = run(federation.search(query))
    assert replay.requests == []
    skipped = {r.provider_id: r.error for r in result.reports if r.provider_id != "local"}
    assert skipped == dict.fromkeys(("inspire", "arxiv", "hepdata"), REFUSED)
    assert result.reports[-1].returned == 1
