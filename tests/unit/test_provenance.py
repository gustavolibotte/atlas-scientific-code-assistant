"""Domain invariant tests carried forward from the legacy trace model."""

from dataclasses import FrozenInstanceError, replace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from asca.api.legacy import legacy_trace_from_graph
from asca.application.demo import (
    DEMO_DECISION_ID,
    DEMO_PROJECT_ID,
    DEMO_TIME,
    seed_synthetic_demo,
)
from asca.domain.provenance import (
    AccessClass,
    Claim,
    IdKind,
    PersistentIdentifier,
    PidScheme,
    Project,
    ProjectId,
    ProvenanceGraph,
    ProvenanceInvariantError,
    ScientificDecision,
    Source,
    SourceAuthority,
    SourceId,
    SourceVersion,
    SourceVersionId,
    require_id,
)
from asca.infrastructure.memory_provenance import InMemoryProvenanceRepository

pytestmark = pytest.mark.unit

PROJECT_ID = ProjectId("prj_" + "1" * 32)


def _demo_graph() -> ProvenanceGraph:
    repository = InMemoryProvenanceRepository()
    seed_synthetic_demo(repository)
    return repository.load(DEMO_PROJECT_ID)


def test_demo_has_no_real_sources_or_executed_tests() -> None:
    graph = _demo_graph()
    assert graph.project.is_synthetic
    assert not any(not source.is_synthetic for source in graph.sources)
    assert graph.runs == ()
    trace = legacy_trace_from_graph(graph, DEMO_DECISION_ID)
    assert trace.verifications
    assert all(record.state == "not_run" for record in trace.verifications)
    assert not any(item.is_real_source for item in trace.evidence)


def test_domain_records_are_immutable() -> None:
    decision = _demo_graph().get(ScientificDecision, DEMO_DECISION_ID)
    with pytest.raises(FrozenInstanceError):
        decision.title = "modified"  # type: ignore[misc]


def _synthetic_project_with(authority: SourceAuthority) -> ProvenanceGraph:
    project = Project(PROJECT_ID, "Synthetic", True, DEMO_TIME)
    source = Source(
        SourceId("src_" + "2" * 32),
        PROJECT_ID,
        "Synthetic source",
        PersistentIdentifier(PidScheme.SYNTHETIC, "synthetic:demo"),
        DEMO_TIME,
    )
    version = SourceVersion(
        SourceVersionId("ver_" + "3" * 32),
        PROJECT_ID,
        source.id,
        "v1",
        authority,
        AccessClass.PUBLIC,
        None,
        None,
        None,
        None,
        None,
        DEMO_TIME,
    )
    return ProvenanceGraph(project, 1, sources=(source,), versions=(version,))


def test_published_sources_cannot_be_synthetic() -> None:
    assert _synthetic_project_with(SourceAuthority.WORKING_MATERIAL).revision == 1
    with pytest.raises(ProvenanceInvariantError) as error:
        _synthetic_project_with(SourceAuthority.PUBLISHED)
    assert error.value.rule == "G.authority.published_pid"


def test_broken_relationship_is_rejected() -> None:
    graph = _demo_graph()
    claim = graph.claims[0]
    broken = replace(claim, source_version_id=SourceVersionId("ver_" + "f" * 32))
    with pytest.raises(ProvenanceInvariantError) as error:
        replace(graph, claims=(broken, *graph.claims[1:]))
    assert error.value.rule == "G.dangling"
    assert isinstance(graph.get(Claim, claim.id), Claim)


@settings(max_examples=100)
@given(st.text(alphabet=" \t\n\r", max_size=60), st.sampled_from(IdKind))
def test_blank_ids_always_fail(value: str, kind: IdKind) -> None:
    with pytest.raises(ProvenanceInvariantError) as error:
        require_id(kind, value, "id")
    assert error.value.rule == "R.id.format"
