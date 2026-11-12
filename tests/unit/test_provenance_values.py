"""Value validators: ids, text, time, paths, persistent identifiers and locators."""

from datetime import UTC, datetime, timedelta, timezone

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from provenance_strategies import ids, locators, multiline_text, pids, single_line_text

from asca.domain.provenance import (
    AccessClass,
    IdKind,
    Locator,
    LocatorKind,
    LocatorPart,
    PersistentIdentifier,
    PidScheme,
    ProvenanceInvariantError,
    id_kind,
    make_id,
    most_restrictive,
    require_id,
    require_int,
    require_relative_path,
    require_sha256,
    require_text,
    require_utc,
)
from asca.domain.provenance.values import optional_text

pytestmark = pytest.mark.unit


def _rule(call: object) -> str:
    assert callable(call)
    with pytest.raises(ProvenanceInvariantError) as error:
        call()
    return error.value.rule


@settings(max_examples=100)
@given(st.sampled_from(IdKind), st.text(alphabet="0123456789abcdef", min_size=32, max_size=32))
def test_require_id_accepts_every_kind_and_rejects_other_prefixes(kind: IdKind, body: str) -> None:
    value = f"{kind}_{body}"
    assert require_id(kind, value, "id") == value
    assert make_id(kind, body) == value
    assert id_kind(value) is kind
    for other in IdKind:
        if other is not kind:
            assert _rule(lambda other=other: require_id(other, value, "id")) == "R.id.kind"


@pytest.mark.parametrize(
    "value",
    [
        None,
        7,
        "",
        "prj_",
        "prj_" + "A" * 32,
        "prj_" + "0" * 31,
        "prj_" + "0" * 33,
        " prj_" + "0" * 32,
    ],
)
def test_require_id_rejects_malformed_values(value: object) -> None:
    assert _rule(lambda: require_id(IdKind.PROJECT, value, "id")) == "R.id.format"


def test_id_kind_rejects_unknown_and_malformed() -> None:
    assert _rule(lambda: id_kind("xyz_" + "0" * 32)) == "R.id.kind"
    assert _rule(lambda: id_kind("nonsense")) == "R.id.format"


@settings(max_examples=100)
@given(ids(IdKind.CLAIM))
def test_id_strategy_produces_valid_ids(value: str) -> None:
    assert id_kind(value) is IdKind.CLAIM


PID_CASES = [
    (PidScheme.DOI, "10.5555/asca-test.1", True),
    (PidScheme.DOI, "10.5555/ASCA-TEST.1", False),
    (PidScheme.DOI, "10.55/asca-test.1", False),
    (PidScheme.DOI, "10.5555/asca test", False),
    (PidScheme.ARXIV, "2101.00001", True),
    (PidScheme.ARXIV, "2101.00001v2", False),
    (PidScheme.ARXIV, "hep-ex/9901001", True),
    (PidScheme.ARXIV, "math.GT/0309136", True),
    (PidScheme.ARXIV, "math.gt/0309136", False),
    (PidScheme.ARXIV, "math/0309136", True),
    (PidScheme.INSPIRE, "1234567", True),
    (PidScheme.INSPIRE, "0123", False),
    (PidScheme.CDS_REPORT, "ATL-PHYS-PUB-2019-001", True),
    (PidScheme.CDS_REPORT, "ATL-PHYS", False),
    (PidScheme.CDS_REPORT, "atl-phys-pub-2019", False),
    (PidScheme.CDS_RECORD, "2654321", True),
    (PidScheme.CDS_RECORD, "x1", False),
    (PidScheme.GIT_REPOSITORY, "https://example.org/asca-test/reco.git", True),
    (PidScheme.GIT_REPOSITORY, "https://user@example.org/asca-test/reco.git", False),
    (PidScheme.GIT_REPOSITORY, "http://example.org/asca-test/reco.git", False),
    (PidScheme.URL, "https://example.org/asca-test/doc", True),
    (PidScheme.URL, "https://example.org", True),
    (PidScheme.URL, "https://example.org:8443/x", True),
    (PidScheme.URL, "https://user@host", False),
    (PidScheme.URL, "https://example.org/a b", False),
    (PidScheme.URL, "javascript:alert(1)", False),
    (PidScheme.URL, "https://example.org/" + "a" * 2000, False),
    (PidScheme.LOCAL_DOCUMENT, "docs/notes.md", True),
    (PidScheme.LOCAL_DOCUMENT, "/etc/passwd", False),
    (PidScheme.SYNTHETIC, "synthetic:demo-1", True),
    (PidScheme.SYNTHETIC, "synthetic:Demo", False),
    (PidScheme.SYNTHETIC, "demo", False),
]


@pytest.mark.parametrize(("scheme", "value", "valid"), PID_CASES)
def test_persistent_identifier_patterns(scheme: PidScheme, value: str, valid: bool) -> None:
    if valid:
        assert PersistentIdentifier(scheme, value).value == value
    else:
        assert _rule(lambda: PersistentIdentifier(scheme, value)) == "R.pid.format"


def test_persistent_identifier_normalization_and_type() -> None:
    pid = PersistentIdentifier.normalized(PidScheme.DOI, "  10.5555/ASCA-TEST.7 ")
    assert pid.value == "10.5555/asca-test.7"
    assert not pid.is_synthetic
    assert PersistentIdentifier.normalized(PidScheme.URL, " https://example.org/X ").value == (
        "https://example.org/X"
    )
    assert PersistentIdentifier(PidScheme.SYNTHETIC, "synthetic:x").is_synthetic
    assert _rule(lambda: PersistentIdentifier("doi", "10.5555/x")) == "R.enum.type"  # type: ignore[arg-type]
    assert _rule(lambda: PersistentIdentifier(PidScheme.DOI, 5)) == "R.pid.format"  # type: ignore[arg-type]


@settings(max_examples=100)
@given(st.sampled_from(PidScheme).flatmap(pids))
def test_pid_strategy_produces_valid_values(pid: PersistentIdentifier) -> None:
    assert PersistentIdentifier(pid.scheme, pid.value) == pid


@settings(max_examples=100)
@given(st.sampled_from(AccessClass), st.sampled_from(AccessClass), st.sampled_from(AccessClass))
def test_access_class_permits_is_a_total_order(
    a: AccessClass, b: AccessClass, c: AccessClass
) -> None:
    assert a.permits(a)
    assert a.permits(b) or b.permits(a)
    if a.permits(b) and b.permits(a):
        assert a is b
    if a.permits(b) and b.permits(c):
        assert a.permits(c)


@settings(max_examples=100)
@given(st.lists(st.sampled_from(AccessClass), max_size=6))
def test_most_restrictive_is_the_maximum_rank(classes: list[AccessClass]) -> None:
    result = most_restrictive(classes)
    assert result.rank == max((item.rank for item in classes), default=0)
    assert all(result.permits(item) for item in classes)


@settings(max_examples=100)
@given(st.datetimes())
def test_naive_datetimes_are_rejected(value: datetime) -> None:
    assert _rule(lambda: require_utc("t", value)) == "R.time.utc"


@settings(max_examples=100)
@given(
    st.datetimes(),
    st.integers(min_value=-23 * 60, max_value=23 * 60).filter(lambda minutes: minutes != 0),
)
def test_non_utc_datetimes_are_rejected(value: datetime, minutes: int) -> None:
    aware = value.replace(tzinfo=timezone(timedelta(minutes=minutes)))
    assert _rule(lambda: require_utc("t", aware)) == "R.time.utc"
    assert require_utc("t", value.replace(tzinfo=UTC)) == value.replace(tzinfo=UTC)


def test_require_utc_rejects_non_datetimes() -> None:
    assert _rule(lambda: require_utc("t", "2026-01-01")) == "R.time.utc"


@settings(max_examples=100)
@given(single_line_text(), st.integers(min_value=0, max_value=39))
def test_nul_is_always_rejected(value: str, position: int) -> None:
    position = min(position, len(value))
    poisoned = value[:position] + "\x00" + value[position:]
    assert _rule(lambda: require_text("f", poisoned, max_len=100, multiline=True)) == "R.text.nul"


@settings(max_examples=100)
@given(st.text(alphabet=" \t\r\n\u2003\u00a0", max_size=20))
def test_blank_text_is_always_rejected(value: str) -> None:
    assert _rule(lambda: require_text("f", value, max_len=100, multiline=True)) == "R.text.blank"


@settings(max_examples=100)
@given(single_line_text(), st.sampled_from(["\n", "\r", "\r\n"]))
def test_newlines_are_rejected_in_single_line_fields(value: str, newline: str) -> None:
    text = value + newline + "x"
    assert _rule(lambda: require_text("f", text, max_len=200)) == "R.text.newline"
    assert require_text("f", text, max_len=200, multiline=True) == text


@settings(max_examples=100)
@given(multiline_text())
def test_multiline_strategy_values_are_accepted(value: str) -> None:
    assert require_text("f", value, max_len=100, multiline=True) == value


def test_text_type_and_length() -> None:
    assert _rule(lambda: require_text("f", 3, max_len=5)) == "R.text.type"
    assert _rule(lambda: require_text("f", "abcdef", max_len=5)) == "R.text.length"
    assert optional_text("f", None, max_len=5) is None
    assert optional_text("f", "ok", max_len=5) == "ok"


@pytest.mark.parametrize("value", ["/abs", "a/../b", "a\\b", "C:/x", "a//b", "./a", "", "a/", 3])
def test_relative_path_negatives(value: object) -> None:
    assert _rule(lambda: require_relative_path("p", value)) == "R.path.relative"


@pytest.mark.parametrize("value", ["a", "src/pkg/module.py", "a/b:c", ".hidden/x"])
def test_relative_path_positives(value: str) -> None:
    assert require_relative_path("p", value) == value


def test_relative_path_length_and_nul() -> None:
    assert _rule(lambda: require_relative_path("p", "a" * 501)) == "R.path.relative"
    assert _rule(lambda: require_relative_path("p", "a\x00b")) == "R.path.relative"


def test_require_int_and_sha256() -> None:
    assert require_int("n", 3, minimum=1) == 3
    for value in (True, 0, "1", 1.0):
        assert _rule(lambda value=value: require_int("n", value, minimum=1)) == "R.int.range"
    assert require_sha256("h", "a" * 64) == "a" * 64
    for value in ("A" * 64, "a" * 63, None):
        assert _rule(lambda value=value: require_sha256("h", value)) == "R.hash.format"


@pytest.mark.parametrize(
    ("kind", "value", "valid"),
    [
        (LocatorKind.PAGE, "3", True),
        (LocatorKind.PAGE, "3-5", True),
        (LocatorKind.PAGE, "5-3", False),
        (LocatorKind.PAGE, "0", False),
        (LocatorKind.PAGE, "0-2", False),
        (LocatorKind.LINE_RANGE, "1234567", False),
        (LocatorKind.LINE_RANGE, "x", False),
        (LocatorKind.PATH, "src/a.py", True),
        (LocatorKind.PATH, "../a.py", False),
        (LocatorKind.SECTION, "2.1 Results", True),
        (LocatorKind.SECTION, "a\nb", False),
        (LocatorKind.ANCHOR, "x" * 201, False),
        (LocatorKind.FIGURE, " ", False),
    ],
)
def test_locator_part_rules(kind: LocatorKind, value: str, valid: bool) -> None:
    if valid:
        assert LocatorPart(kind, value).value == value
    else:
        assert _rule(lambda: LocatorPart(kind, value)) == "R.locator.part"


def test_locator_parts_rules() -> None:
    page = LocatorPart(LocatorKind.PAGE, "1")
    assert _rule(lambda: Locator(())) == "R.locator.parts"
    assert _rule(lambda: Locator((page, LocatorPart(LocatorKind.PAGE, "2")))) == "R.locator.parts"
    seven = tuple(LocatorPart(kind, "1") for kind in list(LocatorKind)[:7])
    assert _rule(lambda: Locator(seven)) == "R.locator.parts"
    assert _rule(lambda: Locator([page])) == "R.locator.parts"  # type: ignore[arg-type]
    six = Locator(seven[:6])
    assert six.has(LocatorKind.PAGE)
    assert not six.has(LocatorKind.ANCHOR)
    assert Locator((LocatorPart(LocatorKind.SECTION, "b"), page)).parts[0].kind is (
        LocatorKind.SECTION
    )


@settings(max_examples=100)
@given(locators())
def test_locator_strategy_produces_valid_locators(locator: Locator) -> None:
    assert 1 <= len(locator.parts) <= 6
