"""The synthetic demonstration project is stored, deterministic and honest."""

import pytest

from asca.application.demo import (
    DEMO_DECISION_ID,
    DEMO_NAMESPACE,
    DEMO_PROJECT_ID,
    DEMO_TIME,
    SYNTHETIC_SOURCE_TEXTS,
    DeterministicIdFactory,
    FixedClock,
    seed_synthetic_demo,
)
from asca.application.errors import DuplicateProjectError
from asca.application.ports import ProjectSummary
from asca.domain.provenance import (
    AccessClass,
    Claim,
    ClaimVerificationState,
    DecisionStatus,
    IdKind,
    LinkFreshness,
    Project,
    ProjectId,
    ProvenanceGraph,
    ScientificDecision,
    SourceVersion,
    StatusReason,
    derive_status,
    link_freshness,
    normalize_for_match,
    sha256_text,
)
from asca.infrastructure.memory_provenance import InMemoryProvenanceRepository

pytestmark = pytest.mark.unit


def _seeded() -> tuple[InMemoryProvenanceRepository, ProvenanceGraph]:
    repository = InMemoryProvenanceRepository()
    assert seed_synthetic_demo(repository) == DEMO_PROJECT_ID
    return repository, repository.load(DEMO_PROJECT_ID)


def test_seeding_twice_is_idempotent() -> None:
    repository, graph = _seeded()
    assert seed_synthetic_demo(repository) == DEMO_PROJECT_ID
    projects = repository.list_projects()
    assert [item.project.id for item in projects] == [DEMO_PROJECT_ID]
    assert projects[0].revision == graph.revision == 19
    assert repository.load(DEMO_PROJECT_ID) == graph


class _RacingRepository(InMemoryProvenanceRepository):
    """Hides the demo from listings to simulate a concurrent seeder."""

    def list_projects(self) -> list[ProjectSummary]:
        return []


def test_duplicate_project_during_seeding_counts_as_seeded() -> None:
    repository = _RacingRepository()
    repository.create_project(Project(DEMO_PROJECT_ID, "Seeded elsewhere", True, DEMO_TIME))
    assert seed_synthetic_demo(repository) == DEMO_PROJECT_ID
    assert repository.load(DEMO_PROJECT_ID).revision == 0
    with pytest.raises(DuplicateProjectError):
        repository.create_project(Project(DEMO_PROJECT_ID, "Again", True, DEMO_TIME))


def test_demo_ids_match_the_seeded_records() -> None:
    _, graph = _seeded()
    assert graph.project.id == DEMO_PROJECT_ID
    decision = graph.get(ScientificDecision, DEMO_DECISION_ID)
    assert decision.title == "Illustrative estimator choice"
    factory = DeterministicIdFactory(DEMO_NAMESPACE)
    assert factory.new(IdKind.PROJECT) == DEMO_PROJECT_ID
    assert factory.new(IdKind.PROJECT) != DEMO_PROJECT_ID
    assert FixedClock(DEMO_TIME).now() == DEMO_TIME
    assert all(record.project_id == ProjectId(DEMO_PROJECT_ID) for record in graph.records())


def test_demo_quotes_are_substrings_of_matching_texts() -> None:
    _, graph = _seeded()
    hashes = {sha256_text(text): text for text in SYNTHETIC_SOURCE_TEXTS.values()}
    assert {version.content_sha256 for version in graph.versions} == set(hashes)
    for claim in graph.claims:
        version = graph.get(SourceVersion, claim.source_version_id)
        assert version.content_sha256 is not None
        text = hashes[version.content_sha256]
        assert claim.quote in text
        assert normalize_for_match(claim.quote) in normalize_for_match(text)
        assert graph.claim_state(claim.id) is ClaimVerificationState.SOURCE_TEXT_CHECKED


def test_demo_statuses_and_access() -> None:
    _, graph = _seeded()
    d1 = derive_status(graph, DEMO_DECISION_ID)
    assert d1.status is DecisionStatus.SUPPORTED
    assert d1.effective_access_class is AccessClass.PUBLIC
    other = next(item for item in graph.decisions if item.id != DEMO_DECISION_ID)
    d2 = derive_status(graph, other.id)
    assert d2.status is DecisionStatus.UNSUPPORTED
    assert d2.reasons == (StatusReason.NO_EVIDENCE_LINKS,)
    assert d2.effective_access_class is AccessClass.INTERNAL
    for link in graph.implementation_links:
        assert link_freshness(graph, link) is LinkFreshness.UNKNOWN
    assert len(graph.supersessions) == 1
    assert {claim.quote for claim in graph.claims} == {
        graph.get(Claim, claim.id).quote for claim in graph.claims
    }


def test_demo_has_no_approvals_and_no_runs() -> None:
    _, graph = _seeded()
    assert graph.approvals == ()
    assert graph.runs == ()
    assert graph.environments == ()
    assert graph.project.is_synthetic
    assert all(source.is_synthetic for source in graph.sources)
