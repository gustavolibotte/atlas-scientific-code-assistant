"""arXiv adapter over recorded and synthetic Atom fixtures (never the network)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from http_replay import make_fixture_document
from knowledge_adapters import (
    EXIT_QUERY,
    FakeTime,
    arxiv,
    assert_polite_requests,
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
from asca.infrastructure.knowledge.arxiv import (
    ARXIV_API,
    HEALTH_PARAMS,
    fetch_params,
    search_params,
)

pytestmark = pytest.mark.contract

EXIT = KnowledgeQuery(EXIT_QUERY, 5)
QUERY = KnowledgeQuery("synthetic query", 5)
ATOM_CT = "application/atom+xml; charset=utf-8"
SENTENCE = "Optimal filtering minimises the noise variance of the amplitude estimate."


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def feed(*entries: str, total: int | None = None) -> str:
    total_text = (
        "" if total is None else f"<opensearch:totalResults>{total}</opensearch:totalResults>"
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<feed xmlns="http://www.w3.org/2005/Atom" xmlns:arxiv="http://arxiv.org/schemas/atom" '
        'xmlns:opensearch="http://a9.com/-/spec/opensearch/1.1/">'
        f"<id>https://arxiv.org/api/synthetic</id>{total_text}{''.join(entries)}</feed>"
    )


def entry(
    abs_id: str = "2511.99901v1",
    *,
    title: str = "Synthetic preprint",
    authors: tuple[str, ...] = ("A. Author",),
    doi: str | None = None,
    journal_ref: str | None = None,
    summary: str | None = "Synthetic summary.",
    published: str = "2025-11-03T10:00:00Z",
    id_prefix: str = "http://arxiv.org/abs/",
) -> str:
    parts = [f"<id>{id_prefix}{abs_id}</id>", f"<title>{title}</title>"]
    if summary is not None:
        parts.append(f"<summary>{summary}</summary>")
    parts.append(f"<published>{published}</published>")
    parts.extend(f"<author><name>{name}</name></author>" for name in authors)
    if doi is not None:
        parts.append(f"<arxiv:doi>{doi}</arxiv:doi>")
    if journal_ref is not None:
        parts.append(f"<arxiv:journal_ref>{journal_ref}</arxiv:journal_ref>")
    return f"<entry>{''.join(parts)}</entry>"


def doc(
    body: str,
    *,
    params: tuple[tuple[str, str], ...] | None = None,
    status: int = 200,
    content_type: str = ATOM_CT,
    headers: dict[str, str] | None = None,
) -> dict[str, object]:
    query_params = params if params is not None else search_params(QUERY)
    assert query_params is not None
    return make_fixture_document(
        provider="arxiv",
        scenario="synthetic",
        url=ARXIV_API,
        params=query_params,
        status=status,
        headers={"content-type": content_type, **(headers or {})},
        body_text=body,
    )


def exit_search() -> Any:
    replay = transport("arxiv/lar_nn_search.json")
    outcome = run(arxiv(replay).search(EXIT))
    assert isinstance(outcome, SearchResult)
    return outcome, replay


# ---------------------------------------------------------------------- recorded fixtures


def test_exit_fixture_maps_four_entries_with_versions_from_their_ids() -> None:
    outcome, replay = exit_search()
    assert [c.ref.native_id for c in outcome.candidates] == [
        "2109.05124v2",
        "2302.07555v2",
        "2111.08590v1",
        "2510.11469v3",
    ]
    assert [c.version.label for c in outcome.candidates] == [
        "arXiv:2109.05124v2",
        "arXiv:2302.07555v2",
        "arXiv:2111.08590v1",
        "arXiv:2510.11469v3",
    ]
    assert all(c.version.kind is VersionKind.ARXIV_VERSION for c in outcome.candidates)
    assert (outcome.total_reported, outcome.dropped_items) == (4, 0)
    replay.assert_all_used()
    assert_polite_requests(replay, {"export.arxiv.org"})
    assert replay.requests[0].headers["Accept"] == "application/atom+xml"


def test_exit_fixture_doi_is_an_asserted_identity_and_the_preprint_is_working_material() -> None:
    outcome, _ = exit_search()
    first = outcome.candidates[0]
    by_scheme = {item.pid.scheme: item for item in first.pids}
    assert by_scheme[PidScheme.ARXIV].pid.value == "2109.05124"
    assert (by_scheme[PidScheme.ARXIV].role, by_scheme[PidScheme.ARXIV].origin) == (
        PidRole.IDENTITY,
        PidOrigin.NATIVE,
    )
    assert by_scheme[PidScheme.DOI].pid.value == "10.1088/1748-0221/17/01/p01002"
    assert (by_scheme[PidScheme.DOI].role, by_scheme[PidScheme.DOI].origin) == (
        PidRole.IDENTITY,
        PidOrigin.PROVIDER_ASSERTED,
    )
    assert first.facts.refereed is None
    assert first.facts.document_types == ("preprint",)
    assert first.authors == ("L. Polson", "L. Kurchaninov", "M. Lefebvre")
    assert first.author_count == 3
    assert first.issued == PartialDate(2021, 9, 10)
    assert first.landing_url == "https://arxiv.org/abs/2109.05124v2"
    assert first.content is ContentAvailability.ABSTRACT
    assert first.snippet is not None and SENTENCE in first.snippet
    assert outcome.candidates[1].facts.journal_ref == "JINST 18 (2023) P05017"
    for candidate in outcome.candidates:
        suggestion = suggest_authority(candidate)
        assert suggestion.authority is SourceAuthority.WORKING_MATERIAL
        assert suggestion.rule is AuthorityRule.ARXIV_PREPRINT


def test_fetch_returns_abstract_text_for_a_versioned_id() -> None:
    replay = transport("arxiv/fetch_2109.05124v2.json")
    outcome = run(arxiv(replay).fetch(CandidateRef("arxiv", "2109.05124v2")))
    assert isinstance(outcome, FetchResult)
    assert outcome.candidate.ref == CandidateRef("arxiv", "2109.05124v2")
    assert outcome.document.kind is DocumentKind.ABSTRACT_TEXT
    assert outcome.document.text.startswith(
        "Energy reconstruction in a liquid argon calorimeter cell using convolutional "
        "neural networks\n\nSynthetic abstract"
    )
    assert outcome.document.source_url == f"{ARXIV_API}?id_list=2109.05124v2&max_results=1"
    assert dict(replay.requests[0].url.params) == {"id_list": "2109.05124v2", "max_results": "1"}


def test_fetch_of_an_unknown_id_is_not_found() -> None:
    replay = transport("arxiv/fetch_unknown.json")
    outcome = run(arxiv(replay).fetch(CandidateRef("arxiv", "9912.99999")))
    assert outcome == ProviderError(ProviderErrorKind.NOT_FOUND, "not_found")


def test_fetch_without_a_version_keeps_the_ref_and_reports_the_latest_version() -> None:
    replay = transport(doc(feed(entry("0912.2642v4")), params=fetch_params("0912.2642")))
    outcome = run(arxiv(replay).fetch(CandidateRef("arxiv", "0912.2642")))
    assert isinstance(outcome, FetchResult)
    assert outcome.candidate.ref == CandidateRef("arxiv", "0912.2642")
    assert outcome.candidate.version.label == "arXiv:0912.2642v4"


@pytest.mark.parametrize(
    ("requested", "returned"),
    [("2511.99901v1", "2511.99901v2"), ("2511.99901", "2511.99902v1")],
)
def test_fetch_of_a_different_record_is_unexpected(requested: str, returned: str) -> None:
    replay = transport(doc(feed(entry(returned)), params=fetch_params(requested)))
    outcome = run(arxiv(replay).fetch(CandidateRef("arxiv", requested)))
    assert outcome == ProviderError(ProviderErrorKind.MALFORMED_RESPONSE, "unexpected_payload")


def test_fetch_of_an_unusable_entry_and_metadata_only_text() -> None:
    bad = transport(doc(feed(entry("2511.99901")), params=fetch_params("2511.99901v1")))
    outcome = run(arxiv(bad).fetch(CandidateRef("arxiv", "2511.99901v1")))
    assert outcome == ProviderError(ProviderErrorKind.MALFORMED_RESPONSE, "unexpected_payload")
    plain = transport(
        doc(feed(entry("2511.99901v1", summary=None)), params=fetch_params("2511.99901v1"))
    )
    fetched = run(arxiv(plain).fetch(CandidateRef("arxiv", "2511.99901v1")))
    assert isinstance(fetched, FetchResult)
    assert fetched.document.kind is DocumentKind.METADATA_TEXT
    assert fetched.document.text == "Synthetic preprint\n"
    assert fetched.candidate.content is ContentAvailability.METADATA_ONLY


def test_fetch_propagates_transport_and_parse_errors() -> None:
    gone = transport(doc("", params=fetch_params("2511.99901v1"), status=500))
    assert run(arxiv(gone).fetch(CandidateRef("arxiv", "2511.99901v1"))) == ProviderError(
        ProviderErrorKind.HTTP_STATUS, "http_500", 500
    )
    broken = transport(doc("<feed", params=fetch_params("2511.99901v1")))
    assert run(arxiv(broken).fetch(CandidateRef("arxiv", "2511.99901v1"))) == ProviderError(
        ProviderErrorKind.MALFORMED_RESPONSE, "invalid_xml"
    )


@pytest.mark.parametrize(
    "native_id",
    ["2109.05124v0", "2109.0512", "2113.05124", "https://arxiv.org/abs/2109.05124", "1"],
)
def test_fetch_refuses_invalid_native_ids_without_a_request(native_id: str) -> None:
    replay = transport()
    outcome = run(arxiv(replay).fetch(CandidateRef("arxiv", native_id)))
    assert outcome == ProviderError(ProviderErrorKind.UNSUPPORTED, "invalid_native_id")
    assert replay.requests == []


# ---------------------------------------------------------------------- errors


def test_error_entry_is_reported_as_a_provider_error() -> None:
    replay = transport("arxiv/error_entry.json")
    outcome = run(arxiv(replay).search(EXIT))
    assert outcome == ProviderError(ProviderErrorKind.MALFORMED_RESPONSE, "provider_error_entry")


def test_unavailable_carries_the_retry_after() -> None:
    replay = transport("arxiv/unavailable_503.json")
    outcome = run(arxiv(replay).search(EXIT))
    assert outcome == ProviderError(ProviderErrorKind.HTTP_STATUS, "http_503", 503, 10)


def test_empty_feed_is_zero_results() -> None:
    replay = transport(doc(feed(total=0)))
    outcome = run(arxiv(replay).search(QUERY))
    assert outcome == SearchResult((), 0, 0)


@pytest.mark.parametrize(
    ("body", "content_type", "code"),
    [
        (feed(), "text/html", "unexpected_content_type"),
        ("<html>oops</html>", ATOM_CT, "unexpected_payload"),
        ("not xml at all", ATOM_CT, "invalid_xml"),
    ],
)
def test_malformed_feeds(body: str, content_type: str, code: str) -> None:
    replay = transport(doc(body, content_type=content_type))
    outcome = run(arxiv(replay).search(QUERY))
    assert outcome == ProviderError(ProviderErrorKind.MALFORMED_RESPONSE, code)


def test_invalid_entries_are_dropped_and_counted() -> None:
    body = feed(
        entry("2511.99901v1"),
        entry("2511.99902"),
        entry("not-an-id"),
        entry("2511.99903v1", title="   "),
        entry("2511.99904v1", id_prefix="https://example.org/abs/"),
        entry("2511.99905v2", id_prefix="https://arxiv.org/abs/"),
        entry("2513.99906v1"),
        total=99,
    )
    query = KnowledgeQuery("synthetic query", 10)
    replay = transport(doc(body, params=search_params(query)))
    outcome = run(arxiv(replay).search(query))
    assert isinstance(outcome, SearchResult)
    assert [c.ref.native_id for c in outcome.candidates] == ["2511.99901v1", "2511.99905v2"]
    assert (outcome.total_reported, outcome.dropped_items) == (99, 5)


def test_author_names_are_cleaned_and_counted() -> None:
    names = ("  Leading Space", "B.\tAuthor", "C. Author", "D. Author", "E. Author", "F. Author")
    body = feed(
        entry(
            authors=names,
            title="Multi\n   line   title",
            doi="DOI:10.5555/ASCA-TEST.7",
            journal_ref="Synthetic J. 1 (2026) 1",
        )
    )
    replay = transport(doc(body))
    outcome = run(arxiv(replay).search(QUERY))
    assert isinstance(outcome, SearchResult)
    candidate = outcome.candidates[0]
    assert candidate.authors == (
        "Leading Space",
        "B. Author",
        "C. Author",
        "D. Author",
        "E. Author",
    )
    assert candidate.author_count == 6
    assert candidate.title == "Multi line title"
    assert "doi:10.5555/asca-test.7" in {
        f"{p.pid.scheme.value}:{p.pid.value}" for p in candidate.pids
    }
    assert candidate.facts.journal_ref == "Synthetic J. 1 (2026) 1"
    assert candidate.kind is ProviderKind.ARXIV


def test_old_style_ids_keep_their_case() -> None:
    replay = transport(doc(feed(entry("math.GT/0309136v1"))))
    outcome = run(arxiv(replay).search(QUERY))
    assert isinstance(outcome, SearchResult)
    assert outcome.candidates[0].ref.native_id == "math.GT/0309136v1"
    assert outcome.candidates[0].version.label == "arXiv:math.GT/0309136v1"


# ---------------------------------------------------------------------- query building


def test_query_is_built_from_lowercase_terms_without_stopwords() -> None:
    query = KnowledgeQuery('Observation of the Higgs (boson) AND title:"X" in ATLAS', 3)
    params = search_params(query)
    assert params is not None
    search = dict(params)["search_query"]
    assert search == "all:observation AND all:higgs AND all:boson AND all:title AND all:atlas"
    assert ":" not in search.replace("all:", "") and "(" not in search and '"' not in search
    replay = transport(doc(feed(total=0), params=params))
    assert run(arxiv(replay).search(query)) == SearchResult((), 0, 0)
    assert list(replay.requests[0].url.params.multi_items()) == [
        ("search_query", search),
        ("start", "0"),
        ("max_results", "3"),
        ("sortBy", "relevance"),
        ("sortOrder", "descending"),
    ]


def test_terms_are_capped_at_eight() -> None:
    query = KnowledgeQuery(" ".join(f"term{index}" for index in range(12)), 5)
    params = search_params(query)
    assert params is not None
    assert dict(params)["search_query"].count("all:") == 8


@pytest.mark.parametrize("text", ["of the and", "a", "( ) :"])
def test_empty_queries_are_unsupported_without_a_request(text: str) -> None:
    replay = transport()
    outcome = run(arxiv(replay).search(KnowledgeQuery(text, 5)))
    assert outcome == ProviderError(ProviderErrorKind.UNSUPPORTED, "empty_query")
    assert replay.requests == []


# ---------------------------------------------------------------------- etiquette and health


def test_second_call_waits_at_least_three_seconds() -> None:
    time = FakeTime()
    replay = transport(doc(feed(total=0)))
    provider = arxiv(replay, time=time)
    run(provider.search(QUERY))
    assert time.sleeps == []
    run(provider.search(QUERY))
    assert time.sleeps == [pytest.approx(3.0)]


def test_configured_interval_above_the_floor_is_used() -> None:
    time = FakeTime()
    provider = arxiv(transport(doc(feed(total=0))), time=time, min_interval_s=5.0)
    run(provider.search(QUERY))
    run(provider.search(QUERY))
    assert time.sleeps == [pytest.approx(5.0)]


def test_gate_over_budget_is_a_local_rate_limit_without_a_request() -> None:
    time = FakeTime()
    replay = transport(doc(feed(total=0)))
    provider = arxiv(replay, time=time, timeout_s=2.0)
    run(provider.search(QUERY))
    outcome = run(provider.search(QUERY))
    assert outcome == ProviderError(ProviderErrorKind.RATE_LIMITED, "local_gate")
    assert len(replay.requests) == 1 and time.sleeps == []


def test_client_spec_uses_one_connection() -> None:
    provider = arxiv(transport())
    spec = provider.client_spec(1024)
    assert spec.max_connections == 1
    assert spec.accept == "application/atom+xml"
    assert spec.host == "export.arxiv.org"


def test_shallow_health_sends_nothing() -> None:
    replay = transport()
    health = run(arxiv(replay).health())
    assert (health.state, health.error) == (HealthState.NOT_PROBED, None)
    assert replay.requests == []


def test_deep_health() -> None:
    ok = transport(doc(feed(entry("0912.2642v4")), params=HEALTH_PARAMS))
    assert run(arxiv(ok).health(deep=True)).state is HealthState.AVAILABLE
    failing = transport(doc("", params=HEALTH_PARAMS, status=503))
    health = run(arxiv(failing).health(deep=True))
    assert health.state is HealthState.UNAVAILABLE
    assert health.error == ProviderError(ProviderErrorKind.HTTP_STATUS, "http_503", 503)
    bad = transport(doc("<html/>", params=HEALTH_PARAMS, content_type="text/html"))
    health = run(arxiv(bad).health(deep=True))
    assert health.error == ProviderError(
        ProviderErrorKind.MALFORMED_RESPONSE, "unexpected_content_type"
    )


def test_descriptor_and_contract() -> None:
    replay = transport("arxiv/lar_nn_search.json")
    provider = arxiv(replay)
    descriptor = provider.descriptor
    assert (descriptor.id, descriptor.label, descriptor.adapter_version) == (
        "arxiv",
        "arXiv",
        "arxiv/1",
    )
    assert descriptor.access_class is AccessClass.PUBLIC and descriptor.supports_fetch
    assert descriptor.timeout_s == 15.0
    assert_provider_contract(provider, EXIT)
    replay.assert_all_used()
