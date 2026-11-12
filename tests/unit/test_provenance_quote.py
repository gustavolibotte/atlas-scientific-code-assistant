"""Quote checking is bound to the source content hash."""

import re
from dataclasses import replace

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from asca.application.demo import DEMO_TIME
from asca.domain.provenance import (
    AccessClass,
    AssertionOrigin,
    Claim,
    ClaimCheckId,
    ClaimCheckOutcome,
    ClaimId,
    Locator,
    LocatorKind,
    LocatorPart,
    ProjectId,
    ProvenanceInvariantError,
    SourceAuthority,
    SourceId,
    SourceVersion,
    SourceVersionId,
    check_quote,
    normalize_for_match,
    sha256_text,
    unavailable_check,
)

pytestmark = pytest.mark.unit

PROJECT = ProjectId("prj_" + "1" * 32)
VERSION = SourceVersionId("ver_" + "2" * 32)
CHECK = ClaimCheckId("chk_" + "3" * 32)
SENTINEL = "☃"
TEXT_ALPHABET = st.sampled_from([*"abcdefghij XYZ.,;-0123456789", "\n", "\t", "  "])
TEXTS = st.lists(TEXT_ALPHABET, min_size=1, max_size=200).map("".join)


def _version(text: str | None) -> SourceVersion:
    return SourceVersion(
        VERSION,
        PROJECT,
        SourceId("src_" + "4" * 32),
        "v1",
        SourceAuthority.WORKING_MATERIAL,
        AccessClass.PUBLIC,
        None,
        None,
        None if text is None else sha256_text(text),
        None if text is None else DEMO_TIME,
        None,
        DEMO_TIME,
    )


def _claim(quote: str, version_id: SourceVersionId = VERSION) -> Claim:
    return Claim(
        ClaimId("clm_" + "5" * 32),
        PROJECT,
        version_id,
        quote,
        Locator((LocatorPart(LocatorKind.PAGE, "1"),)),
        None,
        AssertionOrigin.HUMAN,
        DEMO_TIME,
    )


def _check(quote: str, text: str, given_text: str | None = None) -> ClaimCheckOutcome:
    check = check_quote(
        _claim(quote),
        _version(text),
        text if given_text is None else given_text,
        check_id=CHECK,
        sequence=1,
        checked_at=DEMO_TIME,
    )
    assert check.content_sha256 == sha256_text(text)
    assert check.detail is None
    return check.outcome


@settings(max_examples=100)
@given(TEXTS, st.data())
def test_any_slice_with_content_is_source_text_checked(text: str, data: st.DataObject) -> None:
    start = data.draw(st.integers(min_value=0, max_value=len(text) - 1))
    end = data.draw(st.integers(min_value=start + 1, max_value=len(text)))
    quote = text[start:end]
    assume(normalize_for_match(quote) != "")
    assert _check(quote, text) is ClaimCheckOutcome.SOURCE_TEXT_CHECKED


@settings(max_examples=100)
@given(TEXTS, st.data())
def test_whitespace_perturbed_slices_are_still_checked(text: str, data: st.DataObject) -> None:
    start = data.draw(st.integers(min_value=0, max_value=len(text) - 1))
    end = data.draw(st.integers(min_value=start + 1, max_value=len(text)))
    quote = text[start:end]
    assume(normalize_for_match(quote) != "")
    whitespace = data.draw(st.sampled_from([" \n ", "\t", "\u00a0", "\r\n", "  "]))
    perturbed = re.sub(r"\s+", whitespace, quote)
    perturbed = data.draw(st.sampled_from(["", " ", "\n"])) + perturbed + "­"
    assert _check(perturbed, text) is ClaimCheckOutcome.SOURCE_TEXT_CHECKED


@settings(max_examples=100)
@given(TEXTS, TEXTS)
def test_quote_with_absent_sentinel_is_mismatch(text: str, prefix: str) -> None:
    quote = prefix + SENTINEL
    assert _check(quote, text) is ClaimCheckOutcome.MISMATCH


@settings(max_examples=100)
@given(TEXTS, TEXTS)
def test_any_wrong_text_raises_content_hash(text: str, other: str) -> None:
    assume(other != text)
    with pytest.raises(ProvenanceInvariantError) as error:
        _check("abc", text, given_text=other)
    assert error.value.rule == "R.check.content_hash"
    assert "abc" not in str(error.value)


def test_version_without_content_cannot_be_checked() -> None:
    with pytest.raises(ProvenanceInvariantError) as error:
        check_quote(
            _claim("abc"), _version(None), "abc", check_id=CHECK, sequence=1, checked_at=DEMO_TIME
        )
    assert error.value.rule == "R.check.no_content"


def test_claim_must_quote_the_checked_version() -> None:
    other = _claim("abc", SourceVersionId("ver_" + "9" * 32))
    with pytest.raises(ProvenanceInvariantError) as error:
        check_quote(other, _version("abc"), "abc", check_id=CHECK, sequence=1, checked_at=DEMO_TIME)
    assert error.value.rule == "R.check.version"


def test_unavailable_check_shape() -> None:
    check = unavailable_check(
        _claim("abc").id,
        reason="Fixture: not retrievable.",
        check_id=CHECK,
        sequence=2,
        checked_at=DEMO_TIME,
        project_id=PROJECT,
    )
    assert check.outcome is ClaimCheckOutcome.UNAVAILABLE
    assert check.content_sha256 is None
    assert replace(check, sequence=3).sequence == 3


def test_normalization() -> None:
    assert normalize_for_match("  ﬁne­ tuned \n\t value ") == "fine tuned value"
    assert sha256_text("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
