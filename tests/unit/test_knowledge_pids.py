"""PID normaliser tests: DOI, arXiv, INSPIRE, report numbers, HEPData, sort key."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from asca.application.knowledge.pids import (
    PidRole,
    normalize_arxiv,
    normalize_doi,
    normalize_inspire,
    normalize_report_number,
    parse_pid_text,
    pid_sort_key,
    pid_text,
    split_hepdata_doi,
)
from asca.domain.provenance import PersistentIdentifier, PidScheme

pytestmark = pytest.mark.unit

DOI = PersistentIdentifier(PidScheme.DOI, "10.1088/1748-0221/17/01/p01002")


@pytest.mark.parametrize(
    "raw",
    [
        "10.1088/1748-0221/17/01/P01002",
        "  10.1088/1748-0221/17/01/p01002 ",
        "doi:10.1088/1748-0221/17/01/P01002",
        "DOI:10.1088/1748-0221/17/01/p01002",
        "https://doi.org/10.1088/1748-0221/17/01/P01002",
        "http://doi.org/10.1088/1748-0221/17/01/p01002",
        "https://dx.doi.org/10.1088/1748-0221/17/01/p01002",
        "http://dx.doi.org/10.1088/1748-0221/17/01/P01002",
        "https://doi.org/10.1088%2F1748-0221%2F17%2F01%2FP01002",
    ],
)
def test_doi_forms_normalise_to_one_value(raw: str) -> None:
    assert normalize_doi(raw) == DOI


def test_doi_normalisation_is_idempotent_and_lowercases_inspire_dois() -> None:
    once = normalize_doi("10.1016/S0168-9002(97)00068-5")
    assert once is not None and once.value == "10.1016/s0168-9002(97)00068-5"
    assert normalize_doi(once.value) == once


def test_doi_percent_decoding_happens_only_after_a_url_prefix() -> None:
    assert normalize_doi("doi:10.1000/a%2Fb") == PersistentIdentifier(
        PidScheme.DOI, "10.1000/a%2fb"
    )


@pytest.mark.parametrize(
    "raw",
    ["", "10.1000/has space", "10.1/x", "11.1000/x", "10.1000/" + "x" * 201, "doi:doi:10.1000/x"],
)
def test_invalid_dois_are_rejected(raw: str) -> None:
    assert normalize_doi(raw) is None


def test_non_string_inputs_are_rejected() -> None:
    assert normalize_doi(None) is None  # type: ignore[arg-type]
    assert normalize_arxiv(5) is None  # type: ignore[arg-type]
    assert normalize_report_number(5) is None  # type: ignore[arg-type]
    assert normalize_inspire(True) is None
    assert normalize_inspire(1.5) is None  # type: ignore[arg-type]
    assert parse_pid_text(None) is None  # type: ignore[arg-type]


@st.composite
def new_style_ids(draw: st.DrawFn) -> tuple[str, int | None]:
    year = draw(st.integers(min_value=7, max_value=99))
    month = draw(st.integers(min_value=1, max_value=12))
    yymm = year * 100 + month
    digits = 4 if yymm < 1501 else 5
    number = draw(st.integers(min_value=0, max_value=10**digits - 1))
    version = draw(st.none() | st.integers(min_value=1, max_value=9999))
    return f"{yymm:04d}.{number:0{digits}d}", version


@given(new_style_ids())
def test_new_style_arxiv_ids_round_trip_with_the_era_rule(case: tuple[str, int | None]) -> None:
    value, version = case
    raw = value if version is None else f"{value}v{version}"
    result = normalize_arxiv(raw)
    assert result is not None
    assert result[0] == PersistentIdentifier(PidScheme.ARXIV, value)
    assert result[1] == version
    assert normalize_arxiv(result[0].value) == (result[0], None)


@pytest.mark.parametrize(
    "raw",
    [
        "arXiv:2109.05124v2",
        "ARXIV:2109.05124v2",
        "https://arxiv.org/abs/2109.05124v2",
        "http://arxiv.org/abs/2109.05124v2",
    ],
)
def test_arxiv_prefixes_and_version_split(raw: str) -> None:
    assert normalize_arxiv(raw) == (PersistentIdentifier(PidScheme.ARXIV, "2109.05124"), 2)


@pytest.mark.parametrize(
    "raw",
    [
        "2113.05124",
        "1412.12345",
        "1501.1234",
        "2109.0512",
        "2109.05124v0",
        "MATH.GT/0309136",
        "math/030913",
    ],
)
def test_invalid_arxiv_ids_are_rejected(raw: str) -> None:
    assert normalize_arxiv(raw) is None


def test_old_style_arxiv_ids_keep_their_case() -> None:
    assert normalize_arxiv("math.GT/0309136") == (
        PersistentIdentifier(PidScheme.ARXIV, "math.GT/0309136"),
        None,
    )
    assert normalize_arxiv("solv-int/9901001v3") == (
        PersistentIdentifier(PidScheme.ARXIV, "solv-int/9901001"),
        3,
    )
    assert normalize_arxiv("hep-ex/0101001")[0].value == "hep-ex/0101001"  # type: ignore[index]


def test_inspire_record_ids() -> None:
    assert normalize_inspire(1920956) == PersistentIdentifier(PidScheme.INSPIRE, "1920956")
    assert normalize_inspire("458161") == PersistentIdentifier(PidScheme.INSPIRE, "458161")
    assert normalize_inspire("0123") is None
    assert normalize_inspire(0) is None


@pytest.mark.parametrize(
    ("raw", "role"),
    [
        ("ATLAS-CONF-2023-001", PidRole.IDENTITY),
        ("atl-phys-pub-2022-010", PidRole.IDENTITY),
        ("CERN-EP-2021-123", PidRole.IDENTITY),
        ("FERMILAB-PUB-21-001-E", PidRole.RELATED),
    ],
)
def test_report_numbers_are_identity_only_for_atlas_and_cern(raw: str, role: PidRole) -> None:
    result = normalize_report_number(raw)
    assert result is not None
    assert result[0].value == raw.upper()
    assert result[1] is role


def test_invalid_report_number_is_rejected() -> None:
    assert normalize_report_number("not a report") is None


def test_hepdata_doi_split() -> None:
    doi = PersistentIdentifier(PidScheme.DOI, "10.17182/hepdata.12345.v2")
    concept = PersistentIdentifier(PidScheme.DOI, "10.17182/hepdata.12345")
    assert split_hepdata_doi(doi) == (concept, 2)
    table = PersistentIdentifier(PidScheme.DOI, "10.17182/hepdata.12345.v2/t1")
    assert split_hepdata_doi(table) == (concept, 2)
    assert split_hepdata_doi(concept) is None
    assert split_hepdata_doi(DOI) is None
    assert split_hepdata_doi(PersistentIdentifier(PidScheme.INSPIRE, "1")) is None


def test_pid_text_parsing() -> None:
    assert parse_pid_text("arxiv:2109.05124") == PersistentIdentifier(PidScheme.ARXIV, "2109.05124")
    assert parse_pid_text("arxiv:2109.05124v2") == PersistentIdentifier(
        PidScheme.ARXIV, "2109.05124"
    )
    assert parse_pid_text("DOI:10.1000/X") == PersistentIdentifier(PidScheme.DOI, "10.1000/x")
    assert parse_pid_text("doi:doi:10.1000/x") == PersistentIdentifier(PidScheme.DOI, "10.1000/x")
    assert parse_pid_text("inspire:1920956") == PersistentIdentifier(PidScheme.INSPIRE, "1920956")
    assert parse_pid_text("cds_report:ATLAS-CONF-2023-001") == PersistentIdentifier(
        PidScheme.CDS_REPORT, "ATLAS-CONF-2023-001"
    )
    for text in ("arxiv:bad", "cds_report:bad", "url:https://example.org", "no-separator"):
        assert parse_pid_text(text) is None


def test_pid_sort_key_orders_schemes_then_values() -> None:
    pids = [
        PersistentIdentifier(PidScheme.URL, "https://example.org/a"),
        PersistentIdentifier(PidScheme.SYNTHETIC, "synthetic:x"),
        PersistentIdentifier(PidScheme.LOCAL_DOCUMENT, "notes/a.md"),
        PersistentIdentifier(PidScheme.CDS_RECORD, "5"),
        PersistentIdentifier(PidScheme.CDS_REPORT, "ATLAS-CONF-2023-001"),
        PersistentIdentifier(PidScheme.INSPIRE, "2"),
        PersistentIdentifier(PidScheme.INSPIRE, "10"),
        PersistentIdentifier(PidScheme.ARXIV, "2109.05124"),
        PersistentIdentifier(PidScheme.DOI, "10.1000/b"),
        PersistentIdentifier(PidScheme.DOI, "10.1000/a"),
    ]
    ordered = sorted(pids, key=pid_sort_key)
    assert [pid_text(item) for item in ordered] == [
        "doi:10.1000/a",
        "doi:10.1000/b",
        "arxiv:2109.05124",
        "inspire:10",
        "inspire:2",
        "cds_report:ATLAS-CONF-2023-001",
        "cds_record:5",
        "local_document:notes/a.md",
        "url:https://example.org/a",
        "synthetic:synthetic:x",
    ]
