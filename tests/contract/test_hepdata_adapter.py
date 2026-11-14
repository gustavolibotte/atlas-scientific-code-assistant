"""HEPData adapter: the real recorded challenge and the synthetic provisional search."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from http_replay import make_fixture_document
from knowledge_adapters import (
    EXIT_QUERY,
    FakeTime,
    assert_polite_requests,
    fixture,
    hepdata,
    transport,
)
from knowledge_contract import assert_provider_contract

from asca.application.knowledge.models import (
    CandidateRef,
    ContentAvailability,
    HealthState,
    KnowledgeQuery,
    PidOrigin,
    PidRole,
    ProviderError,
    ProviderErrorKind,
    SearchResult,
    VersionKind,
)
from asca.application.knowledge.policy import AuthorityRule, suggest_authority
from asca.domain.provenance import AccessClass, PidScheme, SourceAuthority
from asca.infrastructure.knowledge.hepdata import HEPDATA_SEARCH, search_params

pytestmark = pytest.mark.contract

EXIT = KnowledgeQuery(EXIT_QUERY, 5)
QUERY = KnowledgeQuery("synthetic query", 5)
BLOCKED = ProviderError(ProviderErrorKind.BLOCKED, "bot_challenge", 403)


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def doc(
    body: str,
    *,
    text: str = "synthetic query",
    limit: int = 5,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> dict[str, object]:
    return make_fixture_document(
        provider="hepdata",
        scenario="synthetic",
        url=HEPDATA_SEARCH,
        params=search_params(text, limit),
        status=status,
        headers=headers if headers is not None else {"content-type": "application/json"},
        body_text=body,
    )


def test_recorded_challenge_is_blocked_and_never_retried() -> None:
    assert fixture("hepdata/lar_nn_search_blocked.json").synthetic is False
    replay = transport("hepdata/lar_nn_search_blocked.json")
    outcome = run(hepdata(replay).search(EXIT))
    assert outcome == BLOCKED
    assert len(replay.requests) == 1
    replay.assert_all_used()
    assert_polite_requests(replay, {"www.hepdata.net"})
    assert list(replay.requests[0].url.params.multi_items()) == [
        ("q", EXIT_QUERY),
        ("format", "json"),
        ("size", "5"),
        ("page", "1"),
    ]


def test_challenge_on_503_is_blocked_too() -> None:
    body = "<html>challenge</html>"
    headers = {"content-type": "text/html", "cf-mitigated": "challenge"}
    outcome = run(hepdata(transport(doc(body, status=503, headers=headers))).search(QUERY))
    assert outcome == ProviderError(ProviderErrorKind.BLOCKED, "bot_challenge", 503)


def test_synthetic_search_maps_concept_doi_identity_and_related_links() -> None:
    assert fixture("hepdata/synthetic_search.json").synthetic is True
    replay = transport("hepdata/synthetic_search.json")
    outcome = run(hepdata(replay).search(EXIT))
    assert isinstance(outcome, SearchResult)
    assert (outcome.total_reported, outcome.dropped_items) == (4, 2)
    first, second = outcome.candidates
    assert first.ref == CandidateRef("hepdata", "ins9999901")
    identity = [item for item in first.pids if item.role is PidRole.IDENTITY]
    assert [(i.pid.scheme, i.pid.value, i.origin) for i in identity] == [
        (PidScheme.DOI, "10.17182/hepdata.99901", PidOrigin.NATIVE)
    ]
    related = {
        (item.pid.scheme, item.pid.value, item.origin)
        for item in first.pids
        if item.role is PidRole.RELATED
    }
    assert related == {
        (PidScheme.INSPIRE, "9999901", PidOrigin.CURATED_LINK),
        (PidScheme.DOI, "10.5555/asca-test.901", PidOrigin.CURATED_LINK),
        (PidScheme.ARXIV, "2511.99901", PidOrigin.CURATED_LINK),
    }
    assert (first.version.kind, first.version.label) == (
        VersionKind.DATASET_VERSION,
        "doi:10.17182/hepdata.99901.v2",
    )
    assert first.facts.refereed is None and first.facts.document_types == ("dataset",)
    assert first.facts.collaborations == ("Synthetic Collaboration",)
    assert first.content is ContentAvailability.METADATA_ONLY
    assert first.landing_url == "https://www.hepdata.net/record/ins9999901"
    assert first.snippet is None and first.authors == ()
    assert second.ref.native_id == "ins9999902"
    assert second.version.label == "doi:10.17182/hepdata.99902.v1"
    suggestion = suggest_authority(first)
    assert suggestion.authority is SourceAuthority.WORKING_MATERIAL
    assert suggestion.rule is AuthorityRule.HEPDATA_DATASET


def test_items_without_title_inspire_id_or_versioned_doi_are_dropped() -> None:
    results: list[object] = [
        {"title": "No ids"},
        {"inspire_id": 9999901, "hepdata_doi": "10.17182/hepdata.1.v1"},
        {"inspire_id": "x", "title": "Bad id", "hepdata_doi": "10.17182/hepdata.1.v1"},
        {"inspire_id": 9999902, "title": "Bad DOI", "hepdata_doi": "nonsense"},
        {"inspire_id": 9999903, "title": " ", "hepdata_doi": "10.17182/hepdata.3.v1"},
        {"inspire_id": True, "title": "Bool id", "hepdata_doi": "10.17182/hepdata.4.v1"},
        "not an object",
        {
            "inspire_id": 9999905,
            "title": "Kept, with a HEPData DOI as publication DOI and a bad arXiv id",
            "hepdata_doi": "10.17182/hepdata.5.v3/t1",
            "doi": "10.17182/hepdata.5",
            "arxiv_id": "arXiv:nonsense",
        },
    ]
    query = KnowledgeQuery("synthetic query", 10)
    replay = transport(doc(json.dumps({"results": results}), limit=10))
    outcome = run(hepdata(replay).search(query))
    assert isinstance(outcome, SearchResult)
    assert outcome.dropped_items == 7 and outcome.total_reported is None
    (kept,) = outcome.candidates
    assert kept.version.label == "doi:10.17182/hepdata.5.v3"
    assert {(p.pid.scheme, p.role) for p in kept.pids} == {
        (PidScheme.DOI, PidRole.IDENTITY),
        (PidScheme.INSPIRE, PidRole.RELATED),
    }


@pytest.mark.parametrize(
    ("body", "content_type", "code"),
    [
        ("<html>login</html>", "text/html", "unexpected_content_type"),
        ("{", "application/json", "invalid_json"),
        ('{"hits": []}', "application/json", "unexpected_payload"),
        ('{"results": [], "total": -3}', "application/json", "unexpected_payload"),
    ],
)
def test_malformed_responses(body: str, content_type: str, code: str) -> None:
    replay = transport(doc(body, headers={"content-type": content_type}))
    outcome = run(hepdata(replay).search(QUERY))
    assert outcome == ProviderError(ProviderErrorKind.MALFORMED_RESPONSE, code)


def test_results_beyond_the_limit_are_ignored() -> None:
    results = [
        {
            "inspire_id": 9999900 + n,
            "title": f"Record {n}",
            "hepdata_doi": f"10.17182/hepdata.{n}.v1",
        }
        for n in range(1, 6)
    ]
    query = KnowledgeQuery("synthetic query", 2)
    replay = transport(doc(json.dumps({"results": results, "total": 5}), limit=2))
    outcome = run(hepdata(replay).search(query))
    assert isinstance(outcome, SearchResult)
    assert len(outcome.candidates) == 2 and outcome.dropped_items == 0


def test_fetch_is_unsupported_without_a_request() -> None:
    replay = transport()
    provider = hepdata(replay)
    assert run(provider.fetch(CandidateRef("hepdata", "ins9999901"))) == ProviderError(
        ProviderErrorKind.UNSUPPORTED, "fetch_unsupported"
    )
    assert run(provider.fetch(CandidateRef("inspire", "1"))) == ProviderError(
        ProviderErrorKind.UNSUPPORTED, "invalid_native_id"
    )
    assert replay.requests == []


def test_health_search_and_challenge() -> None:
    ok = transport(doc('{"results": [], "total": 0}', text="higgs", limit=1))
    assert run(hepdata(ok).health()).state is HealthState.AVAILABLE
    challenge = transport(
        doc(
            "<html/>",
            text="higgs",
            limit=1,
            status=403,
            headers={"content-type": "text/html", "cf-mitigated": "challenge"},
        )
    )
    health = run(hepdata(challenge).health(deep=True))
    assert health.state is HealthState.UNAVAILABLE and health.error == BLOCKED
    html = transport(doc("<html/>", text="higgs", limit=1, headers={"content-type": "text/html"}))
    health = run(hepdata(html).health())
    assert health.error == ProviderError(
        ProviderErrorKind.MALFORMED_RESPONSE, "unexpected_content_type"
    )


def test_gate_spacing_is_one_second() -> None:
    time = FakeTime()
    replay = transport(doc('{"results": []}'))
    provider = hepdata(replay, time=time)
    run(provider.search(QUERY))
    run(provider.search(QUERY))
    assert time.sleeps == [pytest.approx(1.0)]


def test_descriptor_and_contract() -> None:
    health = doc('{"results": [], "total": 0}', text="higgs", limit=1)
    replay = transport("hepdata/synthetic_search.json", health)
    provider = hepdata(replay)
    descriptor = provider.descriptor
    assert (descriptor.id, descriptor.label, descriptor.adapter_version) == (
        "hepdata",
        "HEPData",
        "hepdata/1",
    )
    assert descriptor.supports_fetch is False
    assert descriptor.access_class is AccessClass.PUBLIC
    assert_provider_contract(provider, EXIT)
    replay.assert_all_used()
