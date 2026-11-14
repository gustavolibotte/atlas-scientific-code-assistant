"""Knowledge model invariants and text hygiene."""

from dataclasses import replace
from datetime import UTC, date, datetime, timedelta, timezone

import pytest
from knowledge_contract import (
    INTERNAL_CONDITIONS,
    RETRIEVED_AT,
    identity,
    make_candidate,
    make_descriptor,
    make_document,
    related,
)

from asca.application.knowledge.models import (
    CandidatePid,
    CandidateRef,
    CandidateVersion,
    DocumentKind,
    FetchedDocument,
    FetchResult,
    HealthState,
    LicenseInfo,
    LicenseScope,
    PartialDate,
    PidOrigin,
    PidRole,
    ProviderDescriptor,
    ProviderError,
    ProviderErrorKind,
    ProviderHealth,
    ProviderKind,
    PublicationFacts,
    SearchResult,
    VersionKind,
    license_from_url,
)
from asca.application.knowledge.text import (
    clean_block,
    clean_line,
    is_block,
    is_line,
    query_terms,
    terminal_safe,
)
from asca.domain.provenance import AccessClass, PersistentIdentifier, PidScheme, SourceAuthority

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------- PartialDate


def test_partial_dates_keep_their_precision() -> None:
    assert PartialDate(2022).as_date() is None
    assert PartialDate(2022, 1).as_date() is None
    assert PartialDate(2022, 1, 4).as_date() == date(2022, 1, 4)
    assert PartialDate(2022).iso() == "2022"
    assert PartialDate(2022, 1).iso() == "2022-01"
    assert PartialDate(2022, 1, 4).iso() == "2022-01-04"


@pytest.mark.parametrize(
    ("year", "month", "day"),
    [
        (999, None, None),
        (2101, None, None),
        (2022, 13, None),
        (2022, None, 4),
        (2023, 2, 29),
        (2022, 4, 31),
    ],
)
def test_invalid_partial_dates_are_rejected(year: int, month: int | None, day: int | None) -> None:
    with pytest.raises(ValueError):
        PartialDate(year, month, day)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2022", PartialDate(2022)),
        ("2022-01", PartialDate(2022, 1)),
        (" 2022-01-04 ", PartialDate(2022, 1, 4)),
        ("2021-09-10T17:59:59Z", PartialDate(2021, 9, 10)),
        ("2021-09-10 17:59:59+00:00", PartialDate(2021, 9, 10)),
        ("2022-13", None),
        ("2023-02-29", None),
        ("22-01-04", None),
        ("2021-09-10Tgarbage", None),
        ("yesterday", None),
    ],
)
def test_partial_date_parsing(raw: str, expected: PartialDate | None) -> None:
    assert PartialDate.parse(raw) == expected


def test_partial_date_parse_rejects_non_strings() -> None:
    assert PartialDate.parse(2022) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------- versions


@pytest.mark.parametrize(
    ("kind", "good", "bad"),
    [
        (VersionKind.ARXIV_VERSION, "arXiv:2109.05124v2", "arXiv:2109.05124"),
        (VersionKind.ARXIV_VERSION, "arXiv:math.GT/0309136v1", "arxiv:2109.05124v2"),
        (VersionKind.JOURNAL_PUBLICATION, "doi:10.1088/1748-0221/17/01/p01002", "10.1088/x"),
        (VersionKind.REPORT_NUMBER, "report:ATLAS-CONF-2023-001", "report:atlas-conf-1"),
        (VersionKind.DATASET_VERSION, "doi:10.17182/hepdata.1.v2", "doi:10.17182/hepdata.1"),
        (VersionKind.DECLARED, "declared:2026-11-01", "declared: x"),
        (VersionKind.RECORD_SNAPSHOT, "inspire:2744105@2026-11-01", "inspire:0@2026-11-01"),
        (VersionKind.RECORD_SNAPSHOT, "retrieved@2026-11-14", "retrieved@today"),
    ],
)
def test_version_label_grammar_per_kind(kind: VersionKind, good: str, bad: str) -> None:
    assert CandidateVersion(kind, good).label == good
    with pytest.raises(ValueError):
        CandidateVersion(kind, bad)


def test_version_label_is_bounded() -> None:
    with pytest.raises(ValueError):
        CandidateVersion(VersionKind.DECLARED, "declared:" + "x" * 95)


# ---------------------------------------------------------------------- licences and facts


def test_known_licence_urls_map_to_identifiers() -> None:
    info = license_from_url("https://creativecommons.org/licenses/by/4.0", LicenseScope.CONTENT)
    assert info == LicenseInfo(
        "CC-BY-4.0", "https://creativecommons.org/licenses/by/4.0", LicenseScope.CONTENT
    )
    arxiv = license_from_url(
        "http://arxiv.org/licenses/nonexclusive-distrib/1.0/", LicenseScope.CONTENT
    )
    assert arxiv is not None and arxiv.identifier == "arXiv-nonexclusive-distrib-1.0"
    unknown = license_from_url("https://example.org/licence", LicenseScope.CONTENT)
    assert unknown is not None and unknown.identifier is None
    assert license_from_url("ftp://example.org/licence", LicenseScope.CONTENT) is None
    assert license_from_url("https://example.org/a b", LicenseScope.CONTENT) is None


def test_licence_needs_identifier_or_url() -> None:
    with pytest.raises(ValueError):
        LicenseInfo(None, None, LicenseScope.METADATA)
    with pytest.raises(ValueError):
        LicenseInfo(None, "javascript:alert(1)", LicenseScope.METADATA)
    with pytest.raises(ValueError):
        LicenseInfo("x" * 65, None, LicenseScope.METADATA)


def test_publication_facts_validation() -> None:
    good = PublicationFacts(True, ("article",), "JINST 17 (2022) P01002", ("ATLAS",), False)
    assert good.refereed is True
    for bad in (
        {"refereed": "yes"},
        {"document_types": ("Article",)},
        {"document_types": ("a",) * 6},
        {"document_types": ["article"]},
        {"journal_ref": "x" * 301},
        {"collaborations": ("ATLAS\x1b",)},
        {"generated": None},
    ):
        with pytest.raises(ValueError):
            replace(good, **bad)  # type: ignore[arg-type]


# ---------------------------------------------------------------------- refs and pids


def test_candidate_ref_validation() -> None:
    assert CandidateRef("mcp:chatlas", "doc-1").native_id == "doc-1"
    for provider_id, native_id in (
        ("INSPIRE", "1"),
        ("inspire", "has space"),
        ("inspire", ""),
        ("inspire", "x" * 201),
        ("inspire", "esc\x1b"),
    ):
        with pytest.raises(ValueError):
            CandidateRef(provider_id, native_id)


def test_identity_pids_need_identity_schemes() -> None:
    url = PersistentIdentifier(PidScheme.URL, "https://example.org/x")
    assert CandidatePid(url, PidRole.RELATED, PidOrigin.PROVIDER_ASSERTED).pid == url
    with pytest.raises(ValueError):
        CandidatePid(url, PidRole.IDENTITY, PidOrigin.NATIVE)
    with pytest.raises(ValueError):
        CandidatePid("doi:10.1000/x", PidRole.RELATED, PidOrigin.NATIVE)  # type: ignore[arg-type]


# ---------------------------------------------------------------------- candidates


def test_candidate_properties_split_identity_and_related_pids() -> None:
    candidate = make_candidate(
        pids=[identity("inspire:1"), identity("doi:10.5555/asca-test.1"), related("cds_record:5")]
    )
    assert [p.scheme for p in candidate.identity_pids] == [PidScheme.DOI, PidScheme.INSPIRE]
    assert [p.scheme for p in candidate.related_pids] == [PidScheme.CDS_RECORD]


def test_candidate_rank_and_pid_order_rules() -> None:
    candidate = make_candidate(pids=[identity("inspire:1"), identity("doi:10.5555/asca-test.1")])
    with pytest.raises(ValueError):
        replace(candidate, rank=-1)
    with pytest.raises(ValueError):
        replace(candidate, pids=tuple(reversed(candidate.pids)))
    with pytest.raises(ValueError):
        replace(candidate, pids=(candidate.pids[0], candidate.pids[0]))
    duplicate_roles = (identity("doi:10.5555/asca-test.1"), related("doi:10.5555/asca-test.1"))
    with pytest.raises(ValueError):
        replace(candidate, pids=duplicate_roles)


def test_candidate_holds_one_inspire_and_one_arxiv_identity_at_most() -> None:
    with pytest.raises(ValueError):
        make_candidate(pids=[identity("inspire:1"), identity("inspire:2")])
    with pytest.raises(ValueError):
        make_candidate(pids=[identity("arxiv:2109.05124"), identity("arxiv:2111.08590")])
    two_related = make_candidate(pids=[related("arxiv:2109.05124"), related("arxiv:2111.08590")])
    assert len(two_related.related_pids) == 2


def test_non_public_candidate_requires_conditions() -> None:
    candidate = make_candidate(ProviderKind.LOCAL, "notes/a.md", access_class=AccessClass.INTERNAL)
    assert candidate.access_conditions == INTERNAL_CONDITIONS
    with pytest.raises(ValueError):
        replace(candidate, access_conditions=None)
    with pytest.raises(ValueError):
        replace(make_candidate(), access_conditions="Should not be here.")


def test_generated_only_for_mcp() -> None:
    generated = make_candidate(
        ProviderKind.MCP,
        "doc",
        generated=True,
        declared_authority=SourceAuthority.AUTOMATED_INFERENCE,
        access_class=AccessClass.INTERNAL,
    )
    assert generated.facts.generated
    with pytest.raises(ValueError):
        make_candidate(ProviderKind.INSPIRE, generated=True)


@pytest.mark.parametrize(
    ("kind", "authority", "ok"),
    [
        (ProviderKind.INSPIRE, SourceAuthority.PUBLISHED, False),
        (ProviderKind.LOCAL, SourceAuthority.PUBLISHED, True),
        (ProviderKind.LOCAL, SourceAuthority.APPROVED_INTERNAL, False),
        (ProviderKind.MCP, SourceAuthority.WORKING_MATERIAL, True),
        (ProviderKind.MCP, SourceAuthority.AUTOMATED_INFERENCE, True),
        (ProviderKind.MCP, SourceAuthority.PUBLISHED, False),
    ],
)
def test_declared_authority_per_kind(
    kind: ProviderKind, authority: SourceAuthority, ok: bool
) -> None:
    native = "notes/a.md" if kind is ProviderKind.LOCAL else "1"
    if ok:
        assert make_candidate(kind, native, declared_authority=authority).declared_authority
    else:
        with pytest.raises(ValueError):
            make_candidate(kind, native, declared_authority=authority)


def test_local_and_mcp_require_declared_authority() -> None:
    local = make_candidate(ProviderKind.LOCAL, "notes/a.md")
    with pytest.raises(ValueError):
        replace(local, declared_authority=None)


def test_mcp_candidates_never_carry_identity_pids() -> None:
    assert make_candidate(ProviderKind.MCP, "x", pids=[related("doi:10.5555/asca-test.1")])
    with pytest.raises(ValueError):
        make_candidate(ProviderKind.MCP, "x", pids=[identity("doi:10.5555/asca-test.1")])


@pytest.mark.parametrize(
    "url",
    [
        "http://inspirehep.net/literature/1",
        "https://user:pw@inspirehep.net/literature/1",
        "https://inspirehep.net/a b",
        "https:///nohost",
        "https://inspirehep.net:99999/x",
        "https://inspirehep.net/" + "x" * 500,
    ],
)
def test_landing_url_must_be_plain_https(url: str) -> None:
    with pytest.raises(ValueError):
        replace(make_candidate(), landing_url=url)


def test_candidate_field_validation() -> None:
    candidate = make_candidate()
    assert replace(candidate, landing_url="https://inspirehep.net/literature/1").landing_url
    for bad in (
        {"title": ""},
        {"title": "x" * 301},
        {"title_truncated": 1},
        {"authors": ("a",) * 6},
        {"author_count": 0},
        {"issued": "2022"},
        {"version": "doi:x"},
        {"facts": None},
        {"content": "abstract"},
        {"licenses": (LicenseInfo("CC0-1.0", None, LicenseScope.METADATA),) * 5},
        {"snippet": "x" * 501},
        {"retrieved_at": datetime(2026, 11, 14)},
        {"retrieved_at": datetime(2026, 11, 14, tzinfo=timezone(timedelta(hours=1)))},
        {"ref": ("inspire", "1")},
        {"kind": "inspire"},
        {"access_class": "public"},
        {"pids": [identity("inspire:1")]},
    ):
        with pytest.raises(ValueError):
            replace(candidate, **bad)  # type: ignore[arg-type]


# ---------------------------------------------------------------------- documents


def test_fetched_document_checks_hash_time_and_text() -> None:
    candidate = make_candidate()
    document = make_document(candidate, "Title\n\nAbstract.\n")
    assert document.kind is DocumentKind.ABSTRACT_TEXT
    with pytest.raises(ValueError):
        replace(document, text_sha256="0" * 64)
    with pytest.raises(ValueError):
        replace(document, retrieved_at=datetime(2026, 11, 14))
    with pytest.raises(ValueError):
        FetchedDocument(
            **{
                **{name: getattr(document, name) for name in document.__slots__},  # type: ignore[attr-defined]
                "text": "a\x00b",
            }
        )
    for bad in (
        {"text": ""},
        {"media_type": "text/html"},
        {"raw_sha256": "ABC"},
        {"source_url": "http://inspirehep.net/api"},
        {"redactions": -1},
        {"access_class": AccessClass.INTERNAL},
    ):
        with pytest.raises(ValueError):
            replace(document, **bad)  # type: ignore[arg-type]


def test_fetched_document_rejects_lone_surrogates_and_oversize_text() -> None:
    document = make_document(make_candidate())
    with pytest.raises(ValueError):
        replace(document, text="\ud800")
    with pytest.raises(ValueError):
        replace(document, text="x" * (4_194_304 + 1))


def test_fetch_result_binds_document_to_candidate() -> None:
    candidate = make_candidate()
    document = make_document(candidate)
    assert FetchResult(candidate, document).document is document
    other = make_candidate(native_id="2")
    with pytest.raises(ValueError):
        FetchResult(other, document)
    internal = make_candidate(ProviderKind.LOCAL, "notes/a.md", access_class=AccessClass.INTERNAL)
    public_doc = replace(
        make_document(internal), access_class=AccessClass.PUBLIC, access_conditions=None
    )
    with pytest.raises(ValueError):
        FetchResult(internal, public_doc)


# ---------------------------------------------------------------------- results and errors


def test_search_result_rank_contiguity_and_one_provider() -> None:
    first = make_candidate(native_id="1", rank=0)
    second = make_candidate(native_id="2", rank=1)
    assert SearchResult((first, second), 17, 0).total_reported == 17
    with pytest.raises(ValueError):
        SearchResult((second,), None, 0)
    with pytest.raises(ValueError):
        SearchResult((first, make_candidate(ProviderKind.ARXIV, "2109.05124v2", rank=1)), None, 0)
    with pytest.raises(ValueError):
        SearchResult((first,), -1, 0)
    with pytest.raises(ValueError):
        SearchResult((first,), None, -1)
    with pytest.raises(ValueError):
        SearchResult((first,) * 26, None, 0)


def test_provider_error_code_and_bounds() -> None:
    error = ProviderError(ProviderErrorKind.RATE_LIMITED, "http_429", 429, 3600)
    assert error.retry_after_s == 3600
    for bad in (
        {"code": "Bad-Code"},
        {"code": ""},
        {"code": "x" * 41},
        {"http_status": 99},
        {"http_status": 600},
        {"retry_after_s": -1},
        {"retry_after_s": 3601},
        {"kind": "rate_limited"},
    ):
        with pytest.raises(ValueError):
            replace(error, **bad)  # type: ignore[arg-type]


def test_provider_health_error_iff_unhealthy() -> None:
    assert ProviderHealth("inspire", HealthState.AVAILABLE, None).error is None
    assert ProviderHealth("inspire", HealthState.NOT_PROBED, None).tool_names == ()
    failure = ProviderError(ProviderErrorKind.TIMEOUT, "provider_timeout")
    assert ProviderHealth("inspire", HealthState.UNAVAILABLE, failure).error is failure
    with pytest.raises(ValueError):
        ProviderHealth("inspire", HealthState.UNAVAILABLE, None)
    with pytest.raises(ValueError):
        ProviderHealth("inspire", HealthState.AVAILABLE, failure)
    with pytest.raises(ValueError):
        ProviderHealth("mcp:x", HealthState.AVAILABLE, None, ("bad name",))
    with pytest.raises(ValueError):
        ProviderHealth("mcp:x", HealthState.AVAILABLE, None, ("t",) * 201)


# ---------------------------------------------------------------------- descriptors


def test_descriptor_invariants_per_kind() -> None:
    inspire = make_descriptor(ProviderKind.INSPIRE)
    for bad in (
        {"access_class": AccessClass.INTERNAL, "access_conditions": "x"},
        {"max_query_access": AccessClass.INTERNAL},
        {"uses_network": False},
        {"id": "inspire2"},
    ):
        with pytest.raises(ValueError):
            replace(inspire, **bad)  # type: ignore[arg-type]
    local = make_descriptor(ProviderKind.LOCAL)
    assert local.max_query_access is AccessClass.RESTRICTED
    for bad in (
        {"uses_network": True},
        {"max_query_access": AccessClass.PUBLIC},
        {"id": "library"},
    ):
        with pytest.raises(ValueError):
            replace(local, **bad)  # type: ignore[arg-type]
    mcp = make_descriptor(ProviderKind.MCP, "mcp:chatlas", access_class=AccessClass.INTERNAL)
    assert mcp.access_conditions is not None
    for bad in ({"uses_network": False}, {"id": "chatlas"}):
        with pytest.raises(ValueError):
            replace(mcp, **bad)  # type: ignore[arg-type]


def test_descriptor_field_validation() -> None:
    descriptor = make_descriptor(ProviderKind.ARXIV)
    for bad in (
        {"label": ""},
        {"label": "x" * 81},
        {"adapter_version": "arxiv/0"},
        {"timeout_s": 0.5},
        {"timeout_s": 31},
        {"timeout_s": True},
        {"supports_fetch": "yes"},
        {"kind": "arxiv"},
        {"access_conditions": "Public data needs no conditions."},
    ):
        with pytest.raises(ValueError):
            replace(descriptor, **bad)  # type: ignore[arg-type]
    assert isinstance(descriptor, ProviderDescriptor)


# ---------------------------------------------------------------------- text hygiene


def test_clean_line_removes_escape_osc_and_bidi() -> None:
    raw = "\x1b[31mRed\x1b[0m \x1b]52;c;ZXZpbA==\x07title ‮reversed⁦ ﻿end‎"
    cleaned = clean_line(raw, 300)
    assert cleaned is not None
    text, truncated = cleaned
    assert not truncated
    assert "\x1b" not in text and "\x07" not in text and "‮" not in text
    assert text == "[31mRed[0m ]52;c;ZXZpbA==title reversed end"
    assert is_line(text)


def test_clean_line_collapses_whitespace_and_truncates() -> None:
    assert clean_line("  a \n\t b  ", 10) == ("a b", False)
    assert clean_line("abcdefghijkl", 5) == ("abcd…", True)
    assert clean_line(" \x00\x1b ", 10) is None
    assert clean_line("é", 10) == ("é", False)


def test_clean_block_keeps_newlines_and_tabs() -> None:
    raw = "Line one  \r\nLine\ttwo\r\n\n\n\n\n\nLine \x1b[1mthree‮"
    assert clean_block(raw, 500) == "Line one\nLine\ttwo\n\n\nLine [1mthree"
    assert clean_block("\n\n", 10) is None
    assert clean_block("x" * 20, 10) == "x" * 9 + "…"
    assert is_block("a\nb\tc") and not is_line("a\nb")
    assert not is_block("a\x1bb") and not is_block(" ") and not is_block(5)


def test_terminal_safe_escapes_controls_and_bidi() -> None:
    escaped = terminal_safe("ok\n\x1b]52;c;x\x07‮\t")
    assert "\x1b" not in escaped and "‮" not in escaped
    assert escaped == "ok\n\\u001b]52;c;x\\u0007\\u202e\\u0009"


def test_query_terms_drop_stopwords_and_duplicates() -> None:
    assert query_terms("Observation of the Higgs boson and the HIGGS") == (
        "observation",
        "higgs",
        "boson",
    )
    assert query_terms("a b c x") == ()
    assert query_terms("energy reconstruction liquid argon calorimeter neural network", 3) == (
        "energy",
        "reconstruction",
        "liquid",
    )
    assert query_terms("title:(foo) AND bar:baz") == ("title", "foo", "bar", "baz")


def test_retrieved_at_fixture_is_utc() -> None:
    assert RETRIEVED_AT.tzinfo is UTC
