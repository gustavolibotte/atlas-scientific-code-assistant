"""Domain invariant tests."""

from dataclasses import FrozenInstanceError

import pytest
from hypothesis import given
from hypothesis import strategies as st

from asca.application.demo import create_synthetic_trace
from asca.domain.provenance import (
    EvidenceAuthority,
    EvidenceReference,
    ProvenanceTrace,
    ScientificDecision,
)


def test_demo_has_no_real_sources_or_executed_tests() -> None:
    trace = create_synthetic_trace()
    assert trace.is_synthetic
    assert not any(source.is_real_source for source in trace.evidence)
    assert all(record.state == "not_run" for record in trace.verifications)


def test_domain_models_are_immutable() -> None:
    with pytest.raises(FrozenInstanceError):
        create_synthetic_trace().decision.id = "modified"  # type: ignore[misc]


def test_published_sources_cannot_be_synthetic() -> None:
    with pytest.raises(ValueError, match="synthetic"):
        EvidenceReference("e", "title", "loc", EvidenceAuthority.PUBLISHED, False)


def test_broken_relationship_is_rejected() -> None:
    original = create_synthetic_trace()
    broken = ScientificDecision(
        id="d",
        statement="s",
        rationale="r",
        evidence_ids=("missing",),
        code_symbol_ids=original.decision.code_symbol_ids,
        verification_ids=original.decision.verification_ids,
    )
    with pytest.raises(ValueError, match="Broken evidence"):
        ProvenanceTrace(broken, original.evidence, original.symbols, original.verifications, True)


@given(st.text(alphabet=" \t\n\r", max_size=60))
def test_blank_evidence_ids_always_fail(value: str) -> None:
    with pytest.raises(ValueError, match="non-empty"):
        EvidenceReference(value, "valid", "loc", EvidenceAuthority.UNVERIFIED, False)
