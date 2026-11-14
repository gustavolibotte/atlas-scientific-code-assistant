"""Search port input validation tests."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from asca.application.ports import KnowledgeQuery
from asca.domain.provenance import AccessClass


@pytest.mark.parametrize("limit", [0, -1, 26, 1000])
def test_invalid_limits_are_rejected(limit: int) -> None:
    with pytest.raises(ValueError):
        KnowledgeQuery("test", limit)


@given(st.integers(min_value=1, max_value=25))
def test_valid_limits_are_preserved(limit: int) -> None:
    assert KnowledgeQuery("test", limit).limit == limit


def test_boolean_limit_is_rejected() -> None:
    with pytest.raises(ValueError):
        KnowledgeQuery("test", True)


def test_blank_query_is_rejected() -> None:
    with pytest.raises(ValueError, match="blank"):
        KnowledgeQuery("   ")


@pytest.mark.parametrize(
    "text", [" padded", "padded ", "line\nbreak", "esc\x1b[31m", "bidi‮", "x" * 301]
)
def test_unclean_queries_are_rejected(text: str) -> None:
    with pytest.raises(ValueError):
        KnowledgeQuery(text)


def test_query_access_class_defaults_to_public() -> None:
    query = KnowledgeQuery("liquid argon calorimeter")
    assert query.access_class is AccessClass.PUBLIC
    assert KnowledgeQuery("x" * 300).limit == 5
    with pytest.raises(ValueError):
        KnowledgeQuery("test", access_class="internal")  # type: ignore[arg-type]
