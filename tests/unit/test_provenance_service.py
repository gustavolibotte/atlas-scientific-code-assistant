"""Provenance service write paths on the in-memory repository."""

from __future__ import annotations

from datetime import timedelta

import pytest
from provenance_builders import (
    ENVIRONMENT,
    JOURNAL_TEXT,
    CompleteProject,
    StepClock,
    build_complete_real_project,
    make_service,
)

from asca.application.demo import DEMO_TIME
from asca.application.errors import (
    ConcurrentModificationError,
    DuplicateProjectError,
    ProjectNotFoundError,
    StoredGraphIntegrityError,
)
from asca.application.provenance import (
    DecisionDraft,
    EnvironmentDraft,
    ProvenanceService,
    RunDraft,
    SourceDraft,
    VersionDraft,
)
from asca.domain.provenance import (
    AccessClass,
    Approval,
    ApprovalVerdict,
    ClaimCheck,
    ClaimVerificationState,
    DecisionId,
    DecisionStatus,
    EnvironmentSnapshot,
    IdKind,
    PackagePin,
    PersistentIdentifier,
    PidScheme,
    Project,
    ProjectId,
    ProvenanceInvariantError,
    RunOrigin,
    ScientificDecision,
    SourceAuthority,
    SourceVersion,
    TestOutcome,
    TestResult,
    derive_status,
    sha256_text,
    support_fingerprint,
)
from asca.infrastructure.memory_provenance import InMemoryProvenanceRepository
from asca.infrastructure.system import SystemClock, Uuid4IdFactory

pytestmark = pytest.mark.unit


@pytest.fixture
def built() -> tuple[ProvenanceService, CompleteProject]:
    service = make_service()
    return service, build_complete_real_project(service)


def test_complete_project_has_the_expected_statuses(
    built: tuple[ProvenanceService, CompleteProject],
) -> None:
    service, names = built
    graph = service.load(names.project)
    expected = {
        names.da: DecisionStatus.APPROVED,
        names.db: DecisionStatus.APPROVED,
        names.dc: DecisionStatus.PROPOSED,
        names.dd: DecisionStatus.UNSUPPORTED,
        names.de: DecisionStatus.REJECTED,
        names.df: DecisionStatus.UNSUPPORTED,
    }
    for decision_id, status in expected.items():
        assert derive_status(graph, decision_id).status is status
    assert derive_status(graph, names.db).evidential_status is DecisionStatus.CONFLICTING
    assert derive_status(graph, names.dc).superseded_by == names.df
    assert len(graph.environments) == 1
    assert graph.environments[0].id == names.environment
    assert len(graph.runs) == 2
    assert [item.project.id for item in service.list_projects()] == [names.project]


def test_wrong_text_raises_and_records_nothing(
    built: tuple[ProvenanceService, CompleteProject],
) -> None:
    service, names = built
    before = service.load(names.project)
    with pytest.raises(ProvenanceInvariantError) as error:
        service.check_claim_text(names.project, names.journal_claim, JOURNAL_TEXT + " ")
    assert error.value.rule == "R.check.content_hash"
    assert service.load(names.project) is before


def test_stale_expected_revision_is_a_concurrent_modification() -> None:
    repository = InMemoryProvenanceRepository()
    service = make_service(repository)
    pid = service.create_project("Fixture", is_synthetic=False)
    stale = repository.load(pid)
    service.propose_decision(pid, DecisionDraft("Other writer", "Statement.", "Rationale."))
    late = ScientificDecision(
        DecisionId("dec_" + "e" * 32),
        pid,
        "Late writer",
        "Statement.",
        "Rationale.",
        (),
        (),
        AccessClass.PUBLIC,
        None,
        DEMO_TIME,
    )
    assert stale.append([late]).revision == 1
    with pytest.raises(ConcurrentModificationError):
        repository.append(pid, stale.revision, [late])
    current = repository.load(pid)
    assert current.revision == 1
    assert current.find(ScientificDecision, late.id) is None
    assert repository.append(pid, current.revision, [late]) == 2


def test_repository_errors() -> None:
    repository = InMemoryProvenanceRepository()
    project = Project(ProjectId("prj_" + "1" * 32), "Fixture", False, DEMO_TIME)
    repository.create_project(project)
    with pytest.raises(DuplicateProjectError):
        repository.create_project(project)
    unknown = ProjectId("prj_" + "2" * 32)
    with pytest.raises(ProjectNotFoundError):
        repository.load(unknown)
    with pytest.raises(ProjectNotFoundError):
        repository.append(unknown, 0, [])
    with pytest.raises(ProvenanceInvariantError):
        repository.append(project.id, 0, [])
    assert repository.load(project.id).revision == 0
    assert str(StoredGraphIntegrityError()) == "stored provenance failed integrity validation"


def test_service_computes_sequences_and_fingerprints(
    built: tuple[ProvenanceService, CompleteProject],
) -> None:
    service, names = built
    service.check_claim_text(names.project, names.journal_claim, JOURNAL_TEXT)
    state = service.mark_claim_unavailable(
        names.project, names.journal_claim, reason="Fixture: offline."
    )
    assert state is ClaimVerificationState.UNAVAILABLE
    graph = service.load(names.project)
    assert [check.sequence for check in graph.checks_for(names.journal_claim)] == [1, 2, 3]
    assert all(isinstance(check, ClaimCheck) for check in graph.checks)
    rejection = service.review_decision(
        names.project,
        names.dd,
        ApprovalVerdict.REJECTED,
        reviewer="Fixture reviewer",
        rationale="Not enough evidence.",
    )
    graph = service.load(names.project)
    approval = graph.get(Approval, rejection)
    assert approval.sequence == 1
    assert approval.support_fingerprint == support_fingerprint(graph, names.dd)
    second = service.review_decision(
        names.project,
        names.db,
        ApprovalVerdict.REJECTED,
        reviewer="Fixture reviewer",
        rationale="Revisited.",
    )
    assert service.load(names.project).get(Approval, second).sequence == 2
    for name in ("sequence", "support_fingerprint", "status", "content_sha256"):
        assert name not in ProvenanceService.review_decision.__code__.co_varnames
        assert name not in ProvenanceService.check_claim_text.__code__.co_varnames


def test_source_versions_hash_content_only(
    built: tuple[ProvenanceService, CompleteProject],
) -> None:
    service, names = built
    graph = service.load(names.project)
    journal = graph.get(SourceVersion, names.journal_version)
    assert journal.content_sha256 == sha256_text(JOURNAL_TEXT)
    assert journal.retrieved_at == journal.recorded_at
    working = graph.get(SourceVersion, names.working_version)
    assert working.content_sha256 is None and working.retrieved_at is None
    assert JOURNAL_TEXT not in repr(graph)


def test_record_validation_run_reuses_an_existing_environment(
    built: tuple[ProvenanceService, CompleteProject],
) -> None:
    service, names = built
    before = service.load(names.project)
    run = service.record_validation_run(
        names.project,
        RunDraft(
            revision_id=names.revision2,
            environment=EnvironmentDraft(
                ENVIRONMENT.python_version,
                ENVIRONMENT.implementation,
                ENVIRONMENT.platform,
                tuple(reversed(ENVIRONMENT.packages)),
            ),
            origin=RunOrigin.EXECUTED,
            started_at=DEMO_TIME + timedelta(hours=3),
            finished_at=DEMO_TIME + timedelta(hours=3),
            results=(TestResult(names.test_unit, TestOutcome.PASSED, 0.0, None),),
        ),
    )
    after = service.load(names.project)
    assert after.revision == before.revision + 1
    assert after.environments == before.environments
    assert run in {item.id for item in after.runs}
    service.record_validation_run(
        names.project,
        RunDraft(
            revision_id=names.revision2,
            environment=EnvironmentDraft("3.13.0", "CPython", "Linux", (PackagePin("x", "1"),)),
            origin=RunOrigin.EXECUTED,
            started_at=DEMO_TIME,
            finished_at=DEMO_TIME,
            results=(TestResult(names.test_unit, TestOutcome.SKIPPED, None, None),),
        ),
    )
    assert len(service.load(names.project).environments) == 2
    assert isinstance(service.load(names.project).environments[0], EnvironmentSnapshot)


def test_every_write_increments_the_revision_by_one() -> None:
    service = make_service()
    pid = service.create_project("Fixture", is_synthetic=False)
    assert service.load(pid).revision == 0
    source = service.register_source(
        pid,
        SourceDraft("Fixture", PersistentIdentifier(PidScheme.DOI, "10.5555/asca-test.42")),
    )
    assert service.load(pid).revision == 1
    service.add_source_version(
        pid, source, VersionDraft("v1", SourceAuthority.PUBLISHED, AccessClass.PUBLIC)
    )
    assert service.load(pid).revision == 2
    build_complete_real_project(service)
    revisions = [item.revision for item in service.list_projects()]
    assert revisions == [2, 50]


def test_production_clock_and_ids() -> None:
    now = SystemClock().now()
    assert now.utcoffset() == timedelta(0)
    first, second = Uuid4IdFactory().new(IdKind.CLAIM), Uuid4IdFactory().new(IdKind.CLAIM)
    assert first != second
    assert first.startswith("clm_") and len(first) == 36
    service = ProvenanceService(InMemoryProvenanceRepository(), SystemClock(), Uuid4IdFactory())
    pid = service.create_project("Production composition", is_synthetic=True)
    assert service.load(pid).project.is_synthetic


def test_step_clock_advances_one_second() -> None:
    clock = StepClock()
    assert clock.now() == DEMO_TIME
    assert clock.now() == DEMO_TIME + timedelta(seconds=1)
