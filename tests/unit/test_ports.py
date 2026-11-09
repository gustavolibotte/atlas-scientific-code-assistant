"""Search port input validation tests."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from asca.application.ports import KnowledgeQuery


@pytest.mark.parametrize("limit", [0, -1, 101, 1000])
def test_invalid_limits_are_rejected(limit: int) -> None:
    with pytest.raises(ValueError):
        KnowledgeQuery("test", limit)


@given(st.integers(min_value=1, max_value=100))
def test_valid_limits_are_preserved(limit: int) -> None:
    assert KnowledgeQuery("test", limit).limit == limit


def test_blank_query_is_rejected() -> None:
    with pytest.raises(ValueError, match="blank"):
        KnowledgeQuery("   ")
