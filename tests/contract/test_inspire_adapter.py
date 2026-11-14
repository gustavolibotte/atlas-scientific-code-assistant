"""INSPIRE adapter over recorded and synthetic fixtures (never the network)."""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

import httpx2
import pytest
from http_replay import ReplayTransport, make_fixture_document
from knowledge_adapters import (
    EXIT_QUERY,
    NOW,
    FakeTime,
    assert_polite_requests,
    fixture,
    inspire,
    transport,
)
from knowledge_contract import assert_provider_contract

from asca.application.knowledge.models import (
    CandidateRef,
    ContentAvailability,
    DocumentKind,
    FetchResult,
    HealthState,
    KnowledgeQuery,
    LicenseInfo,
    LicenseScope,
    PartialDate,
    PidOrigin,
    PidRole,
    ProviderError,
    ProviderErrorKind,
    ProviderKind,
    SearchResult,
    VersionKind,
)
from asca.application.knowledge.policy import AuthorityRule, suggest_authority
from asca.domain.provenance import AccessClass, PidScheme, SourceAuthority
from asca.infrastructure.knowledge.inspire import (
    HEALTH_PARAMS,
    INSPIRE_API,
    INSPIRE_FIELDS,
    fetch_params,
    search_params,
)

pytestmark = pytest.mark.contract

EXIT = KnowledgeQuery(EXIT_QUERY, 5)
QUERY = KnowledgeQuery("synthetic query", 5)
SENTENCE = "Optimal filtering minimises the noise variance of the amplitude estimate."


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def search_doc(
    hits: list[dict[str, object]],
    *,
    total: int | None = None,
    query: KnowledgeQuery = QUERY,
    status: int = 200,
    headers: dict[str, str] | None = None,
    body: str | None = None,
) -> dict[str, object]:
    text = (
        body
        if body is not None
        else json.dumps({"hits": {"total": total or len(hits), "hits": hits}})
    )
    return make_fixture_document(
        provider="inspire",
        scenario="synthetic",
        url=INSPIRE_API,
        params=search_params(query),
        status=status,
        headers=headers if headers is not None else {"content-type": "application/json"},
        body_text=text,
    )


def fetch_doc(
    native_id: str, hits: list[dict[str, object]], total: int | None = None
) -> dict[str, object]:
    body = json.dumps({"hits": {"total": len(hits) if total is None else total, "hits": hits}})
    return make_fixture_document(
        provider="inspire",
        scenario="synthetic_fetch",
        url=INSPIRE_API,
        params=fetch_params(native_id),
        headers={"content-type": "application/json"},
        body_text=body,
    )


def health_doc(status: int = 200) -> dict[str, object]:
    return make_fixture_document(
        provider="inspire",
        scenario="health",
        url=INSPIRE_API,
        params=HEALTH_PARAMS,
        status=status,
        headers={"content-type": "application/json"},
        body_text='{"hits":{"total":1,"hits":[]}}',
    )


def hit(recid: int = 9999901, **metadata: object) -> dict[str, object]:
    base: dict[str, object] = {
        "control_number": recid,
        "titles": [{"title": "Synthetic INSPIRE record"}],
    }
    base.update(metadata)
    return {"updated": "2026-11-01T08:00:00+00:00", "metadata": base}


def pid_texts(candidate: Any, role: PidRole | None = None) -> set[str]:
    return {
        f"{item.pid.scheme.value}:{item.pid.value}"
        for item in candidate.pids
        if role is None or item.role is role
    }


# ---------------------------------------------------------------------- recorded exit fixture


def exit_search() -> tuple[SearchResult, ReplayTransport]:
    replay = transport("inspire/lar_nn_search.json")
    outcome = run(inspire(replay).search(EXIT))
    assert isinstance(outcome, SearchResult)
    return outcome, replay


def test_exit_fixture_maps_five_candidates_in_provider_order() -> None:
    outcome, replay = exit_search()
    assert [c.ref.native_id for c in outcome.candidates] == [
        "458161",
        "1920956",
        "1969369",
        "2744105",
        "2013724",
    ]
    assert [c.rank for c in outcome.candidates] == [0, 1, 2, 3, 4]
    assert (outcome.total_reported, outcome.dropped_items) == (17, 0)
    assert all(c.kind is ProviderKind.INSPIRE for c in outcome.candidates)
    assert all(c.access_class is AccessClass.PUBLIC for c in outcome.candidates)
    assert all(c.retrieved_at == NOW for c in outcome.candidates)
    replay.assert_all_used()
    assert_polite_requests(replay, {"inspirehep.net"})


def test_exit_fixture_record_1920956_is_refereed_with_a_curated_doi() -> None:
    outcome, _ = exit_search()
    record = outcome.candidates[1]
    assert pid_texts(record, PidRole.IDENTITY) == {
        "inspire:1920956",
        "doi:10.1088/1748-0221/17/01/p01002",
        "arxiv:2109.05124",
    }
    dois = [item for item in record.pids if item.pid.scheme is PidScheme.DOI]
    assert len(dois) == 1, "the duplicated upper-case DOI entries collapse into one pid"
    assert dois[0].origin is PidOrigin.CURATED_LINK
    natives = [item for item in record.pids if item.origin is PidOrigin.NATIVE]
    assert [item.pid.scheme for item in natives] == [PidScheme.INSPIRE]
    assert record.version.kind is VersionKind.JOURNAL_PUBLICATION
    assert record.version.label == "doi:10.1088/1748-0221/17/01/p01002"
    assert record.facts.refereed is True
    assert record.facts.document_types == ("article",)
    assert record.facts.journal_ref == "JINST 17 (2022) P01002"
    assert record.issued == PartialDate(2022, 1, 4)
    assert record.authors == ("Polson, L.",) and record.author_count == 3
    assert record.landing_url == "https://inspirehep.net/literature/1920956"
    assert record.content is ContentAvailability.ABSTRACT
    assert record.snippet is not None and SENTENCE in record.snippet
    assert record.licenses == (
        LicenseInfo("CC0-1.0", None, LicenseScope.METADATA),
        LicenseInfo(
            "CC-BY-4.0", "http://creativecommons.org/licenses/by/4.0/", LicenseScope.CONTENT
        ),
    )
    suggestion = suggest_authority(record)
    assert suggestion.authority is SourceAuthority.PUBLISHED
    assert suggestion.rule is AuthorityRule.INSPIRE_REFEREED


def test_exit_fixture_unrefereed_records_are_working_material() -> None:
    outcome, _ = exit_search()
    by_id = {c.ref.native_id: c for c in outcome.candidates}
    assert by_id["1969369"].facts.refereed is None
    assert by_id["2013724"].facts.refereed is False
    for native_id in ("1969369", "2744105", "2013724"):
        suggestion = suggest_authority(by_id[native_id])
        assert suggestion.authority is SourceAuthority.WORKING_MATERIAL
        assert suggestion.rule is AuthorityRule.INSPIRE_OTHER
    assert "cds_record:2806560" in pid_texts(by_id["1969369"], PidRole.RELATED)


def test_exit_fixture_thesis_versions_by_its_cern_report_number() -> None:
    outcome, _ = exit_search()
    thesis = outcome.candidates[3]
    assert thesis.facts.document_types == ("thesis",)
    assert thesis.facts.journal_ref is None, "a bare year is not a journal reference"
    assert "cds_report:CERN-THESIS-2023-294" in pid_texts(thesis, PidRole.IDENTITY)
    assert thesis.version.kind is VersionKind.REPORT_NUMBER
    assert thesis.version.label == "report:CERN-THESIS-2023-294"


def test_search_sends_the_documented_parameters_in_order() -> None:
    _, replay = exit_search()
    request = replay.requests[0]
    assert str(request.url).startswith(INSPIRE_API + "?")
    assert list(request.url.params.multi_items()) == [
        ("q", EXIT_QUERY),
        ("size", "5"),
        ("page", "1"),
        ("sort", "bestmatch"),
        ("fields", INSPIRE_FIELDS),
    ]
    assert request.headers["Accept"] == "application/json"


# ---------------------------------------------------------------------- fetch


def test_fetch_uses_a_control_number_query_and_returns_abstract_text() -> None:
    replay = transport("inspire/fetch_1920956.json")
    outcome = run(inspire(replay).fetch(CandidateRef("inspire", "1920956")))
    assert isinstance(outcome, FetchResult)
    document = outcome.document
    assert document.kind is DocumentKind.ABSTRACT_TEXT
    assert document.text.startswith(
        "Energy reconstruction in a liquid argon calorimeter cell using convolutional "
        "neural networks\n\n"
    )
    assert SENTENCE in document.text and document.text.endswith("\n")
    body = fixture("inspire/fetch_1920956.json").body_text.encode("utf-8")
    assert document.raw_sha256 == hashlib.sha256(body).hexdigest()
    assert document.source_url is not None and document.source_url.startswith(INSPIRE_API + "?")
    assert document.licenses == outcome.candidate.licenses
    assert outcome.candidate.ref == CandidateRef("inspire", "1920956")
    request = replay.requests[0]
    assert request.url.path == "/api/literature"
    assert request.url.params["q"] == "control_number:1920956"
    replay.assert_all_used()


def test_fetch_without_an_abstract_returns_metadata_text() -> None:
    replay = transport(fetch_doc("9999901", [hit()]))
    outcome = run(inspire(replay).fetch(CandidateRef("inspire", "9999901")))
    assert isinstance(outcome, FetchResult)
    assert outcome.document.kind is DocumentKind.METADATA_TEXT
    assert outcome.document.text == "Synthetic INSPIRE record\n"
    assert outcome.candidate.content is ContentAvailability.METADATA_ONLY


@pytest.mark.parametrize(
    ("hits", "total"),
    [([], 0), ([hit(deleted=True)], 1), ([], 3)],
    ids=["no-hit", "deleted", "empty-hits"],
)
def test_fetch_not_found_and_deleted(hits: list[dict[str, object]], total: int) -> None:
    replay = transport(fetch_doc("9999901", hits, total))
    outcome = run(inspire(replay).fetch(CandidateRef("inspire", "9999901")))
    assert outcome == ProviderError(ProviderErrorKind.NOT_FOUND, "not_found")


@pytest.mark.parametrize(
    "hits",
    [[hit(9999902)], [{"metadata": {"control_number": "x"}}], [hit(titles=[{"title": " "}])]],
    ids=["other-record", "malformed", "blank-title"],
)
def test_fetch_of_an_unusable_hit_is_unexpected_payload(hits: list[dict[str, object]]) -> None:
    replay = transport(fetch_doc("9999901", hits))
    outcome = run(inspire(replay).fetch(CandidateRef("inspire", "9999901")))
    assert outcome == ProviderError(ProviderErrorKind.MALFORMED_RESPONSE, "unexpected_payload")


@pytest.mark.parametrize("native_id", ["0", "01", "abc", "12345678901", "1920956v1"])
def test_fetch_refuses_invalid_native_ids_without_a_request(native_id: str) -> None:
    replay = transport()
    outcome = run(inspire(replay).fetch(CandidateRef("inspire", native_id)))
    assert outcome == ProviderError(ProviderErrorKind.UNSUPPORTED, "invalid_native_id")
    assert replay.requests == []


def test_fetch_maps_http_errors() -> None:
    doc = fetch_doc("9999901", [])
    doc["response"] = {**doc["response"], "status": 500}  # type: ignore[dict-item]
    replay = transport(doc)
    outcome = run(inspire(replay).fetch(CandidateRef("inspire", "9999901")))
    assert outcome == ProviderError(ProviderErrorKind.HTTP_STATUS, "http_500", 500)


def test_fetch_maps_a_bad_content_type() -> None:
    doc = fetch_doc("9999901", [])
    doc["response"] = {**doc["response"], "headers": {"content-type": "text/html"}}  # type: ignore[dict-item]
    replay = transport(doc)
    outcome = run(inspire(replay).fetch(CandidateRef("inspire", "9999901")))
    assert outcome == ProviderError(ProviderErrorKind.MALFORMED_RESPONSE, "unexpected_content_type")


# ---------------------------------------------------------------------- errors


def test_rate_limit_is_reported_with_a_clamped_retry_after() -> None:
    replay = transport("inspire/rate_limited_429.json")
    outcome = run(inspire(replay).search(EXIT))
    assert outcome == ProviderError(ProviderErrorKind.RATE_LIMITED, "http_429", 429, 3600)


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirects_are_refused_and_never_followed(status: int) -> None:
    replay = transport(
        search_doc([], status=status, headers={"location": "https://evil.example/next"})
    )
    outcome = run(inspire(replay).search(QUERY))
    assert outcome == ProviderError(
        ProviderErrorKind.UNEXPECTED_REDIRECT, "redirect_refused", status
    )
    assert len(replay.requests) == 1 and not replay.unexpected


def test_wrong_content_type_is_malformed() -> None:
    replay = transport(
        search_doc([], headers={"content-type": "text/html"}, body="<html>maintenance</html>")
    )
    outcome = run(inspire(replay).search(QUERY))
    assert outcome == ProviderError(ProviderErrorKind.MALFORMED_RESPONSE, "unexpected_content_type")


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ("not json", "invalid_json"),
        ('{"hits": []}', "unexpected_payload"),
        ('{"hits": {"total": -1, "hits": []}}', "unexpected_payload"),
        ("[1, 2]", "unexpected_payload"),
    ],
)
def test_unparseable_payloads_are_malformed(body: str, code: str) -> None:
    replay = transport(search_doc([], body=body))
    outcome = run(inspire(replay).search(QUERY))
    assert outcome == ProviderError(ProviderErrorKind.MALFORMED_RESPONSE, code)


def test_invalid_items_are_dropped_and_counted() -> None:
    hits: list[dict[str, object]] = [
        hit(9999901),
        {"metadata": {"control_number": "9999902"}},
        hit(9999903, deleted=True),
        hit(9999904, titles=[]),
        hit(9999905, titles=[{"title": "\x1b\x07 "}]),
        {"metadata": {"control_number": 0, "titles": [{"title": "Zero"}]}},
        "not an object",
        hit(9999906),
    ]
    replay = transport(search_doc(hits, total=40, query=KnowledgeQuery("synthetic query", 10)))
    outcome = run(inspire(replay).search(KnowledgeQuery("synthetic query", 10)))
    assert isinstance(outcome, SearchResult)
    assert [c.ref.native_id for c in outcome.candidates] == ["9999901", "9999906"]
    assert [c.rank for c in outcome.candidates] == [0, 1]
    assert (outcome.total_reported, outcome.dropped_items) == (40, 6)


def test_more_hits_than_the_limit_are_cut() -> None:
    hits = [hit(9999900 + index) for index in range(1, 5)]
    query = KnowledgeQuery("synthetic query", 2)
    replay = transport(search_doc(hits, query=query))
    outcome = run(inspire(replay).search(query))
    assert isinstance(outcome, SearchResult)
    assert len(outcome.candidates) == 2


def test_transport_failures_map_to_fixed_codes() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("secret-canary connection refused", request=request)

    provider = inspire(httpx2.MockTransport(handler))
    outcome = run(provider.search(QUERY))
    assert outcome == ProviderError(ProviderErrorKind.CONNECT_FAILED, "connect_failed")
    assert "secret-canary" not in repr(outcome)


def test_the_adapter_applies_its_own_timeout() -> None:
    class Hanging(httpx2.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
            await asyncio.sleep(30)
            raise AssertionError("unreachable")  # pragma: no cover

    provider = inspire(Hanging(), timeout_s=1.0)
    outcome = run(provider.search(QUERY))
    assert outcome == ProviderError(ProviderErrorKind.TIMEOUT, "provider_timeout")
    health = run(provider.health())
    assert health.state is HealthState.UNAVAILABLE
    assert health.error == ProviderError(ProviderErrorKind.TIMEOUT, "provider_timeout")


# ---------------------------------------------------------------------- mapping details


def test_mapping_of_pids_versions_licences_and_facts() -> None:
    long_doi = "10.5555/" + "x" * 120
    record = hit(
        9999901,
        dois=[
            {"value": "10.5555/ASCA-TEST.1"},
            {"value": "doi:10.5555/asca-test.1", "material": "publication"},
            {"value": "10.5555/asca-test.2", "material": "erratum"},
            {"value": "10.5555/asca-test.3"},
            {"value": "10.5555/asca-test.3", "material": "addendum"},
            {"value": "not a doi"},
            {"value": long_doi, "material": "publication"},
        ],
        arxiv_eprints=[{"value": "2511.99901"}, {"value": "2511.99902"}, {"value": "bad"}],
        report_numbers=[
            {"value": "atlas-conf-2026-001"},
            {"value": "FERMILAB-PUB-26-001-E"},
            {"value": "garbage"},
        ],
        external_system_identifiers=[
            {"schema": "CDS", "value": "2999001"},
            {"schema": "CDS", "value": "not-a-number"},
            {"schema": "HAL", "value": "hal-0001"},
        ],
        license=[
            {"url": "https://creativecommons.org/licenses/by/4.0"},
            {"license": "Publisher licence"},
            {"license": "Publisher licence", "url": "not a url"},
            {"imposing": "Synthetic Publisher"},
            {"url": "https://example.org/licence"},
            {},
            {"license": "Overflow licence"},
        ],
        publication_info=[
            {"journal_title": "Synthetic J.", "journal_volume": 7, "year": 2026, "page_start": "11"}
        ],
        collaborations=[{"value": "Synthetic"}, {"value": "Synthetic"}, {"value": "Other"}],
        document_type=["Article", "Conference Paper"],
        refereed=True,
        earliest_date="2026-02",
        author_count=0,
        first_author={"full_name": "Doe, J."},
        abstracts=[{"source": "Publisher", "value": "Publisher abstract."}],
    )
    replay = transport(search_doc([record]))
    outcome = run(inspire(replay).search(QUERY))
    assert isinstance(outcome, SearchResult)
    candidate = outcome.candidates[0]
    assert pid_texts(candidate, PidRole.IDENTITY) == {
        "doi:10.5555/asca-test.1",
        f"doi:{long_doi}",
        "arxiv:2511.99901",
        "inspire:9999901",
        "cds_report:ATLAS-CONF-2026-001",
    }
    assert pid_texts(candidate, PidRole.RELATED) == {
        "doi:10.5555/asca-test.2",
        "doi:10.5555/asca-test.3",
        "arxiv:2511.99902",
        "cds_report:FERMILAB-PUB-26-001-E",
        "cds_record:2999001",
    }
    assert candidate.version.label == "doi:10.5555/asca-test.1", "the smallest identity DOI"
    assert candidate.licenses == (
        LicenseInfo("CC0-1.0", None, LicenseScope.METADATA),
        LicenseInfo(
            "CC-BY-4.0", "https://creativecommons.org/licenses/by/4.0", LicenseScope.CONTENT
        ),
        LicenseInfo("Publisher licence", None, LicenseScope.CONTENT),
        LicenseInfo("Synthetic Publisher", None, LicenseScope.CONTENT),
    )
    assert candidate.facts.journal_ref == "Synthetic J. 7 (2026) 11"
    assert candidate.facts.collaborations == ("Synthetic", "Other")
    assert candidate.facts.document_types == ("article", "conference paper")
    assert candidate.issued == PartialDate(2026, 2)
    assert candidate.author_count is None, "an author count below the listed authors is dropped"
    assert candidate.snippet == "Publisher abstract."


def test_version_falls_back_to_report_number_then_record_snapshot() -> None:
    long_doi = "10.5555/" + "y" * 120
    hits: list[dict[str, object]] = [
        hit(9999901, dois=[{"value": long_doi}], report_numbers=[{"value": "CERN-EP-2026-001"}]),
        hit(9999902, report_numbers=[{"value": "FERMILAB-PUB-26-001"}]),
        hit(
            9999905,
            report_numbers=[{"value": "CERN-" + "-".join(["ABCDEFGHIJKLMNOPQRSTUVWXYZ"] * 4)}],
        ),
        {"metadata": {"control_number": 9999903, "titles": [{"title": "No update stamp"}]}},
        {
            "updated": "2026-11",
            "metadata": {"control_number": 9999904, "titles": [{"title": "Partial stamp"}]},
        },
    ]
    replay = transport(search_doc(hits))
    outcome = run(inspire(replay).search(QUERY))
    assert isinstance(outcome, SearchResult)
    labels = [(c.version.kind, c.version.label) for c in outcome.candidates]
    assert labels == [
        (VersionKind.REPORT_NUMBER, "report:CERN-EP-2026-001"),
        (VersionKind.RECORD_SNAPSHOT, "inspire:9999902@2026-11-01"),
        (VersionKind.RECORD_SNAPSHOT, "inspire:9999905@2026-11-01"),
        (VersionKind.RECORD_SNAPSHOT, "retrieved@2026-11-14"),
        (VersionKind.RECORD_SNAPSHOT, "retrieved@2026-11-14"),
    ]


def test_imprint_date_wins_and_arxiv_abstract_is_preferred() -> None:
    record = hit(
        imprints=[{"date": "not a date"}, {"date": "2020-01-01"}],
        earliest_date="2025-05-06",
        abstracts=[
            {"source": "Publisher", "value": "Publisher text."},
            {"source": "ARXIV", "value": "  "},
            {"source": "arXiv", "value": "Preprint text."},
        ],
    )
    replay = transport(search_doc([record]))
    outcome = run(inspire(replay).search(QUERY))
    assert isinstance(outcome, SearchResult)
    candidate = outcome.candidates[0]
    assert candidate.issued == PartialDate(2025, 5, 6), "an unparseable imprint falls back"
    assert candidate.snippet == "Preprint text."


def test_long_titles_are_truncated_and_flagged() -> None:
    replay = transport(search_doc([hit(titles=[{"title": "T" * 400}])]))
    outcome = run(inspire(replay).search(QUERY))
    assert isinstance(outcome, SearchResult)
    candidate = outcome.candidates[0]
    assert candidate.title_truncated is True
    assert len(candidate.title) == 300 and candidate.title.endswith("…")


# ---------------------------------------------------------------------- gate, health, contract


def test_requests_are_spaced_by_the_rate_gate() -> None:
    time = FakeTime()
    replay = transport(search_doc([hit()]))
    provider = inspire(replay, time=time)
    for _ in range(3):
        assert isinstance(run(provider.search(QUERY)), SearchResult)
    assert time.sleeps == [pytest.approx(0.35), pytest.approx(0.35)]


def test_health_is_one_small_request() -> None:
    replay = transport(health_doc())
    health = run(inspire(replay).health(deep=True))
    assert (health.state, health.error) == (HealthState.AVAILABLE, None)
    assert [dict(r.url.params) for r in replay.requests] == [
        {"q": "control_number:1", "size": "1", "fields": "control_number"}
    ]


@pytest.mark.parametrize(
    ("status", "state"),
    [
        (401, HealthState.AUTH_REQUIRED),
        (403, HealthState.AUTH_REQUIRED),
        (503, HealthState.UNAVAILABLE),
    ],
)
def test_health_failures(status: int, state: HealthState) -> None:
    health = run(inspire(transport(health_doc(status))).health())
    assert health.state is state
    assert health.error is not None and health.error.http_status == status


def test_descriptor() -> None:
    descriptor = inspire(transport()).descriptor
    assert (descriptor.id, descriptor.kind, descriptor.label) == (
        "inspire",
        ProviderKind.INSPIRE,
        "INSPIRE-HEP",
    )
    assert descriptor.adapter_version == "inspire/1"
    assert descriptor.access_class is AccessClass.PUBLIC
    assert descriptor.max_query_access is AccessClass.PUBLIC
    assert descriptor.uses_network and descriptor.supports_fetch
    assert descriptor.timeout_s == 10.0


def test_provider_contract() -> None:
    replay = transport("inspire/lar_nn_search.json", health_doc())
    assert_provider_contract(inspire(replay), EXIT)
    replay.assert_all_used()


def test_internal_queries_are_refused_without_a_request() -> None:
    replay = transport()
    outcome = run(inspire(replay).search(KnowledgeQuery("x" * 3, 5, AccessClass.INTERNAL)))
    assert outcome == ProviderError(ProviderErrorKind.NOT_CONSULTED, "query_access_class")
    assert replay.requests == []
