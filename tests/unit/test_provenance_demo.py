"""The synthetic demonstration project is stored, deterministic and honest."""

from collections.abc import Sequence
from dataclasses import replace

import pytest

from asca.application.demo import (
    DEMO_DECISION_ID,
    DEMO_NAMESPACE,
    DEMO_PROJECT_ID,
    DEMO_TIME,
    SYNTHETIC_SOURCE_TEXTS,
    DemoSeedError,
    DeterministicIdFactory,
    FixedClock,
    seed_synthetic_demo,
)
from asca.application.errors import DuplicateProjectError, ProjectNotFoundError
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
    ProvenanceRecord,
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


_DEMO_WRITES = 20  # create_project plus one append per revision


class _RacingRepository(InMemoryProvenanceRepository):
    """A rival seeder completes the demo just before this seeder's n-th write."""

    def __init__(self, race_at: int) -> None:
        super().__init__()
        self._writes = 0
        self._race_at = race_at

    def _race(self) -> None:
        self._writes += 1
        if self._writes == self._race_at:
            self._race_at = 0
            seed_synthetic_demo(self)

    def create_project(self, project: Project) -> None:
        self._race()
        super().create_project(project)

    def append(
        self,
        project_id: ProjectId,
        expected_revision: int,
        records: Sequence[ProvenanceRecord],
    ) -> int:
        self._race()
        return super().append(project_id, expected_revision, records)


@pytest.mark.parametrize("race_at", [1, 2, 10, _DEMO_WRITES])
def test_concurrent_seeders_converge_on_the_complete_demo(race_at: int) -> None:
    _, expected = _seeded()
    repository = _RacingRepository(race_at)
    assert seed_synthetic_demo(repository) == DEMO_PROJECT_ID
    assert repository.load(DEMO_PROJECT_ID) == expected
    with pytest.raises(DuplicateProjectError):
        repository.create_project(Project(DEMO_PROJECT_ID, "Again", True, DEMO_TIME))


class _CrashError(Exception):
    """Stands for a process killed in the middle of the first seed."""


class _CrashErroringRepository(InMemoryProvenanceRepository):
    def __init__(self, crash_at: int) -> None:
        super().__init__()
        self._appends = 0
        self.crash_at = crash_at

    def append(
        self,
        project_id: ProjectId,
        expected_revision: int,
        records: Sequence[ProvenanceRecord],
    ) -> int:
        self._appends += 1
        if self._appends == self.crash_at:
            raise _CrashError()
        return super().append(project_id, expected_revision, records)


@pytest.mark.parametrize("crash_at", [1, 4, 10, 19])
def test_an_interrupted_seed_is_completed_on_the_next_start(crash_at: int) -> None:
    _, expected = _seeded()
    repository = _CrashErroringRepository(crash_at)
    with pytest.raises(_CrashError):
        seed_synthetic_demo(repository)
    assert repository.load(DEMO_PROJECT_ID).revision == crash_at - 1
    repository.crash_at = 0
    assert seed_synthetic_demo(repository) == DEMO_PROJECT_ID
    assert repository.load(DEMO_PROJECT_ID) == expected


def test_a_foreign_project_with_the_demo_id_fails_loudly() -> None:
    repository = InMemoryProvenanceRepository()
    repository.create_project(Project(DEMO_PROJECT_ID, "Seeded elsewhere", True, DEMO_TIME))
    with pytest.raises(DemoSeedError, match="does not match"):
        seed_synthetic_demo(repository)
    assert repository.load(DEMO_PROJECT_ID).revision == 0


class _FixedGraphRepository(InMemoryProvenanceRepository):
    def __init__(self, graph: ProvenanceGraph) -> None:
        super().__init__()
        self._graph = graph

    def load(self, project_id: ProjectId) -> ProvenanceGraph:
        return self._graph


def test_a_complete_project_that_differs_from_the_demo_fails_loudly() -> None:
    _, graph = _seeded()
    foreign = replace(graph, project=replace(graph.project, title="Seeded elsewhere"))
    with pytest.raises(DemoSeedError):
        seed_synthetic_demo(_FixedGraphRepository(foreign))
    assert seed_synthetic_demo(_FixedGraphRepository(graph)) == DEMO_PROJECT_ID


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


class _VanishingRepository(InMemoryProvenanceRepository):
    """Never shows the project it reports as existing, so seeding cannot progress."""

    def load(self, project_id: ProjectId) -> ProvenanceGraph:
        raise ProjectNotFoundError("project not found")

    def create_project(self, project: Project) -> None:
        raise DuplicateProjectError("project already exists")


def test_seeding_that_cannot_progress_fails_instead_of_looping() -> None:
    with pytest.raises(DemoSeedError):
        seed_synthetic_demo(_VanishingRepository())
