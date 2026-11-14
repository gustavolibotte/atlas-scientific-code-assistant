"""Deterministic builders for provenance tests (synthetic, public-safe fixtures only).

Real (non-synthetic) fixtures use only ``10.5555/asca-test.<n>`` DOIs and
``https://example.org/asca-test/...`` URLs and git repositories.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta

from asca.application.demo import DEMO_TIME, DeterministicIdFactory
from asca.application.ports import ProvenanceRepository
from asca.application.provenance import (
    DecisionDraft,
    EnvironmentDraft,
    ProvenanceService,
    RunDraft,
    SourceDraft,
    SymbolDraft,
    VersionDraft,
)
from asca.domain.provenance import (
    EVIDENTIAL_STATUSES,
    RECORD_FIELDS,
    AccessClass,
    ApprovalId,
    ApprovalVerdict,
    AssertionOrigin,
    ClaimCheckOutcome,
    ClaimId,
    DecisionId,
    DecisionStatus,
    EnvironmentId,
    EvidenceLink,
    EvidenceLinkId,
    ImplementationLinkId,
    Language,
    Locator,
    LocatorKind,
    LocatorPart,
    PackagePin,
    PersistentIdentifier,
    PidScheme,
    ProjectId,
    ProvenanceGraph,
    ProvenanceRecord,
    RevisionId,
    RunId,
    RunOrigin,
    SourceAuthority,
    SourceId,
    SourceSpan,
    SourceVersionId,
    Stance,
    StatusReason,
    SupersessionDimension,
    SupersessionId,
    SymbolId,
    SymbolKind,
    TestCaseId,
    TestKind,
    TestOutcome,
    TestResult,
    derive_status,
    environment_id_for,
    support_fingerprint,
)
from asca.infrastructure.memory_provenance import InMemoryProvenanceRepository

TEST_NAMESPACE = "asca-test"


class StepClock:
    """Each ``now()`` call returns DEMO_TIME advanced by one more second."""

    def __init__(self, start: datetime = DEMO_TIME) -> None:
        self._next = start

    def now(self) -> datetime:
        value = self._next
        self._next = value + timedelta(seconds=1)
        return value


class CountingIdFactory(DeterministicIdFactory):
    """Deterministic per-kind counters in a test namespace."""

    def __init__(self, namespace: str = TEST_NAMESPACE) -> None:
        super().__init__(namespace)


def make_service(
    repo: ProvenanceRepository | None = None, *, namespace: str = TEST_NAMESPACE
) -> ProvenanceService:
    return ProvenanceService(
        repo if repo is not None else InMemoryProvenanceRepository(),
        StepClock(),
        CountingIdFactory(namespace),
    )


def fingerprint(n: int) -> str:
    """A deterministic sha256-shaped symbol fingerprint."""
    return f"{n:064x}"


JOURNAL_TEXT = (
    "Test fixture article, not a real publication.\n"
    "Section 3. The weighted estimator is unbiased when the noise covariance is known.\n"
)
INTERNAL_TEXT = (
    "Test fixture internal note, not a real document.\n"
    "Pedestals are measured per event before amplitude estimation.\n"
)
IMPLEMENTATION_TEXT = (
    "def estimate_amplitude(samples, weights):\n"
    "    # Pedestals are not subtracted here; callers subtract them first.\n"
    "    return sum(s * w for s, w in zip(samples, weights))\n"
)
AUTOMATED_TEXT = "Automated summary fixture: the estimator is always optimal.\n"
IMPLEMENTATION_COMMIT = "0123456789abcdef0123456789abcdef01234567"
ENVIRONMENT = EnvironmentDraft(
    python_version="3.12.3",
    implementation="CPython",
    platform="Linux-x86_64",
    packages=(PackagePin("numpy", "2.1.0"), PackagePin("asca-fixture", "0.1.0")),
)


@dataclass(frozen=True, slots=True)
class CompleteProject:
    project: ProjectId
    journal_source: SourceId
    journal_version: SourceVersionId
    internal_version: SourceVersionId
    implementation_version: SourceVersionId
    working_version: SourceVersionId
    automated_version: SourceVersionId
    journal_notice: SupersessionId
    journal_claim: ClaimId
    internal_claim: ClaimId
    implementation_claim: ClaimId
    working_claim: ClaimId
    automated_claim: ClaimId
    da: DecisionId
    db: DecisionId
    dc: DecisionId
    dd: DecisionId
    de: DecisionId
    df: DecisionId
    da_support: EvidenceLinkId
    da_context: EvidenceLinkId
    revision1: RevisionId
    revision2: RevisionId
    symbol_current: SymbolId
    symbol_stale: SymbolId
    symbol_moved: SymbolId
    symbol_orphaned: SymbolId
    revision2_symbols: tuple[SymbolId, ...]
    link_current: ImplementationLinkId
    link_stale: ImplementationLinkId
    link_moved: ImplementationLinkId
    link_orphaned: ImplementationLinkId
    test_analytic: TestCaseId
    test_regression: TestCaseId
    test_unit: TestCaseId
    environment: EnvironmentId
    run1: RunId
    run2: RunId
    approval_da: ApprovalId
    approval_db: ApprovalId
    rejection_de: ApprovalId


def _url(slug: str) -> PersistentIdentifier:
    return PersistentIdentifier(PidScheme.URL, f"https://example.org/asca-test/{slug}")


def build_complete_real_project(service: ProvenanceService) -> CompleteProject:
    """A real project exercising every status, freshness and test-result branch.

    Expected statuses: Da approved, Db approved (conflicting with a resolution),
    Dc proposed and superseded by Df, Dd unsupported (automated inference only),
    De rejected, Df unsupported.
    """
    pid = service.create_project("Complete fixture project", is_synthetic=False)

    journal = service.register_source(
        pid,
        SourceDraft(
            "Fixture journal article",
            PersistentIdentifier.normalized(PidScheme.DOI, "10.5555/ASCA-TEST.1"),
        ),
    )
    journal_v = service.add_source_version(
        pid,
        journal,
        VersionDraft(
            "journal",
            SourceAuthority.PUBLISHED,
            AccessClass.PUBLIC,
            content_text=JOURNAL_TEXT,
            published_on=date(2024, 1, 15),
        ),
    )
    internal = service.register_source(pid, SourceDraft("Fixture internal note", _url("note")))
    internal_v = service.add_source_version(
        pid,
        internal,
        VersionDraft(
            "v1",
            SourceAuthority.APPROVED_INTERNAL,
            AccessClass.INTERNAL,
            access_conditions="Fixture access condition.",
            authority_basis="Fixture approval basis.",
            content_text=INTERNAL_TEXT,
        ),
    )
    implementation = service.register_source(
        pid,
        SourceDraft(
            "Fixture reference implementation",
            PersistentIdentifier(
                PidScheme.GIT_REPOSITORY, "https://example.org/asca-test/reco.git"
            ),
        ),
    )
    implementation_v = service.add_source_version(
        pid,
        implementation,
        VersionDraft(
            IMPLEMENTATION_COMMIT,
            SourceAuthority.VERIFIED_IMPLEMENTATION,
            AccessClass.PUBLIC,
            content_text=IMPLEMENTATION_TEXT,
        ),
    )
    working = service.register_source(pid, SourceDraft("Fixture working notes", _url("work")))
    working_v = service.add_source_version(
        pid, working, VersionDraft("draft", SourceAuthority.WORKING_MATERIAL, AccessClass.PUBLIC)
    )
    automated = service.register_source(pid, SourceDraft("Fixture automated summary", _url("auto")))
    automated_v = service.add_source_version(
        pid,
        automated,
        VersionDraft(
            "auto-1",
            SourceAuthority.AUTOMATED_INFERENCE,
            AccessClass.PUBLIC,
            content_text=AUTOMATED_TEXT,
        ),
    )
    notice = service.record_supersession(
        pid,
        superseded=journal_v,
        superseding=None,
        dimension=SupersessionDimension.TECHNICAL,
        reason="Fixture: the article's code listing was revised.",
    )

    journal_c = service.add_claim(
        pid,
        journal_v,
        quote="The weighted estimator is unbiased when the noise covariance is known.",
        locator=Locator(
            (LocatorPart(LocatorKind.PAGE, "3"), LocatorPart(LocatorKind.SECTION, "3"))
        ),
        statement="Weighted estimation is unbiased under known covariance.",
    )
    internal_c = service.add_claim(
        pid,
        internal_v,
        quote="Pedestals are measured per event before amplitude estimation.",
        locator=Locator((LocatorPart(LocatorKind.PARAGRAPH, "2"),)),
    )
    implementation_c = service.add_claim(
        pid,
        implementation_v,
        quote="# Pedestals are not subtracted here; callers subtract them first.",
        locator=Locator(
            (
                LocatorPart(LocatorKind.PATH, "src/reco/estimators.py"),
                LocatorPart(LocatorKind.LINE_RANGE, "2-2"),
            )
        ),
    )
    working_c = service.add_claim(
        pid,
        working_v,
        quote="We expect the calibration to be stable.",
        locator=Locator((LocatorPart(LocatorKind.ANCHOR, "calibration"),)),
    )
    automated_c = service.add_claim(
        pid,
        automated_v,
        quote="the estimator is always optimal",
        locator=Locator((LocatorPart(LocatorKind.PARAGRAPH, "1"),)),
        extracted_by=AssertionOrigin.AUTOMATED,
    )
    service.check_claim_text(pid, journal_c, JOURNAL_TEXT)
    service.check_claim_text(pid, internal_c, INTERNAL_TEXT)
    service.check_claim_text(pid, implementation_c, IMPLEMENTATION_TEXT)
    service.check_claim_text(pid, automated_c, AUTOMATED_TEXT)

    def decision(title: str, supersedes: DecisionId | None = None) -> DecisionId:
        return service.propose_decision(
            pid,
            DecisionDraft(
                title=title,
                statement=f"Fixture statement for {title}.",
                rationale=f"Fixture rationale for {title}.",
                supersedes_id=supersedes,
            ),
        )

    da = decision("Da weighted estimator")
    db = decision("Db pedestal handling")
    dc = decision("Dc calibration stability")
    dd = decision("Dd automated optimality")
    de = decision("De rejected shortcut")

    da_support = service.link_evidence(pid, da, journal_c, Stance.SUPPORTS)
    da_context = service.link_evidence(pid, da, working_c, Stance.CONTEXT)
    service.link_evidence(pid, db, internal_c, Stance.SUPPORTS)
    service.link_evidence(pid, db, implementation_c, Stance.CONTRADICTS)
    service.link_evidence(pid, dc, working_c, Stance.SUPPORTS)
    service.link_evidence(
        pid, dd, automated_c, Stance.SUPPORTS, asserted_by=AssertionOrigin.AUTOMATED
    )
    service.link_evidence(pid, de, journal_c, Stance.SUPPORTS, note="Fixture note.")

    estimators = "src/reco/estimators.py"
    rev1 = service.record_workspace_revision(
        pid,
        vcs_ref="fixture-rev-1",
        symbols=[
            SymbolDraft(
                Language.PYTHON,
                SymbolKind.FUNCTION,
                "estimate_amplitude",
                estimators,
                SourceSpan(1, 3),
                fingerprint(1),
            ),
            SymbolDraft(
                Language.PYTHON,
                SymbolKind.FUNCTION,
                "subtract_pedestal",
                estimators,
                SourceSpan(5, 9),
                fingerprint(2),
            ),
            SymbolDraft(
                Language.PYTHON, SymbolKind.FUNCTION, "calibrate", estimators, None, fingerprint(3)
            ),
            SymbolDraft(
                Language.PYTHON,
                SymbolKind.METHOD,
                "LegacyFit.fit",
                estimators,
                None,
                fingerprint(4),
            ),
        ],
        symbols_indexed=True,
    )
    rev2 = service.record_workspace_revision(
        pid,
        vcs_ref=None,
        symbols=[
            SymbolDraft(
                Language.PYTHON,
                SymbolKind.FUNCTION,
                "estimate_amplitude",
                estimators,
                SourceSpan(1, 3),
                fingerprint(1),
            ),
            SymbolDraft(
                Language.PYTHON,
                SymbolKind.FUNCTION,
                "subtract_pedestal",
                estimators,
                SourceSpan(5, 12),
                fingerprint(20),
            ),
            SymbolDraft(
                Language.PYTHON,
                SymbolKind.FUNCTION,
                "calibrate",
                "src/reco/calibration.py",
                None,
                fingerprint(3),
            ),
        ],
        symbols_indexed=True,
    )
    current, stale, moved, orphaned = rev1.symbol_ids
    link_current = service.link_implementation(pid, da, current)
    link_stale = service.link_implementation(pid, db, stale)
    link_moved = service.link_implementation(pid, dd, moved)
    link_orphaned = service.link_implementation(pid, de, orphaned)

    test_analytic = service.register_test_case(
        pid,
        node_id="tests/test_estimators.py::test_amplitude_analytic",
        kind=TestKind.ANALYTIC,
        description="Analytic check of the weighted estimator.",
    )
    test_regression = service.register_test_case(
        pid,
        node_id="tests/test_estimators.py::test_pedestal_regression",
        kind=TestKind.REGRESSION,
        description="Pedestal regression test.",
    )
    test_unit = service.register_test_case(
        pid,
        node_id="tests/test_calibration.py::test_calibrate",
        kind=TestKind.UNIT,
        description="Calibration unit test.",
    )
    service.link_verification(pid, test_analytic, decision_id=da)
    service.link_verification(pid, test_regression, decision_id=db)
    service.link_verification(pid, test_unit, symbol_id=moved)

    run1 = service.record_validation_run(
        pid,
        RunDraft(
            revision_id=rev1.revision_id,
            environment=ENVIRONMENT,
            origin=RunOrigin.EXECUTED,
            started_at=DEMO_TIME + timedelta(hours=1),
            finished_at=DEMO_TIME + timedelta(hours=1, minutes=5),
            results=(
                TestResult(test_analytic, TestOutcome.PASSED, 0.5, None),
                TestResult(test_regression, TestOutcome.PASSED, 1.25, None),
                TestResult(test_unit, TestOutcome.PASSED, None, None),
            ),
        ),
    )
    run2 = service.record_validation_run(
        pid,
        RunDraft(
            revision_id=rev2.revision_id,
            environment=ENVIRONMENT,
            origin=RunOrigin.IMPORTED,
            started_at=DEMO_TIME + timedelta(hours=2),
            finished_at=DEMO_TIME + timedelta(hours=2, minutes=5),
            results=(
                TestResult(test_analytic, TestOutcome.PASSED, 0.5, None),
                TestResult(test_regression, TestOutcome.FAILED, 2.0, "Fixture failure."),
            ),
        ),
    )

    approval_da = service.review_decision(
        pid,
        da,
        ApprovalVerdict.APPROVED,
        reviewer="Fixture reviewer",
        rationale="Checked against the fixture article.",
    )
    approval_db = service.review_decision(
        pid,
        db,
        ApprovalVerdict.APPROVED,
        reviewer="Fixture reviewer",
        rationale="Accepted despite the contradicting comment.",
        conflict_resolution="The implementation comment predates the note.",
    )
    rejection_de = service.review_decision(
        pid,
        de,
        ApprovalVerdict.REJECTED,
        reviewer="Fixture reviewer",
        rationale="Shortcut rejected.",
    )
    df = decision("Df calibration replacement", supersedes=dc)

    return CompleteProject(
        project=pid,
        journal_source=journal,
        journal_version=journal_v,
        internal_version=internal_v,
        implementation_version=implementation_v,
        working_version=working_v,
        automated_version=automated_v,
        journal_notice=notice,
        journal_claim=journal_c,
        internal_claim=internal_c,
        implementation_claim=implementation_c,
        working_claim=working_c,
        automated_claim=automated_c,
        da=da,
        db=db,
        dc=dc,
        dd=dd,
        de=de,
        df=df,
        da_support=da_support,
        da_context=da_context,
        revision1=rev1.revision_id,
        revision2=rev2.revision_id,
        symbol_current=current,
        symbol_stale=stale,
        symbol_moved=moved,
        symbol_orphaned=orphaned,
        revision2_symbols=rev2.symbol_ids,
        link_current=link_current,
        link_stale=link_stale,
        link_moved=link_moved,
        link_orphaned=link_orphaned,
        test_analytic=test_analytic,
        test_regression=test_regression,
        test_unit=test_unit,
        environment=environment_id_for(
            pid,
            ENVIRONMENT.python_version,
            ENVIRONMENT.implementation,
            ENVIRONMENT.platform,
            ENVIRONMENT.packages,
        ),
        run1=run1,
        run2=run2,
        approval_da=approval_da,
        approval_db=approval_db,
        rejection_de=rejection_de,
    )


def with_records(graph: ProvenanceGraph, *records: ProvenanceRecord) -> ProvenanceGraph:
    """Construct (not append) a graph with extra records: only state rules are checked."""
    groups = {name: list(getattr(graph, name)) for name in RECORD_FIELDS.values()}
    for record in records:
        groups[RECORD_FIELDS[type(record)]].append(record)
    return replace(graph, **{name: tuple(items) for name, items in groups.items()})


def _countable(graph: ProvenanceGraph, link: EvidenceLink) -> bool:
    """Independent restatement of the countable-link rule."""
    claim = next(item for item in graph.claims if item.id == link.claim_id)
    version = next(item for item in graph.versions if item.id == claim.source_version_id)
    checks = [item for item in graph.checks if item.claim_id == claim.id]
    latest = max(checks, key=lambda item: item.sequence) if checks else None
    return (
        latest is not None
        and latest.outcome is ClaimCheckOutcome.SOURCE_TEXT_CHECKED
        and version.authority is not SourceAuthority.AUTOMATED_INFERENCE
    )


def assert_status_sound(graph: ProvenanceGraph) -> None:
    """Soundness predicates that every derived decision status must satisfy."""
    for decision in graph.decisions:
        report = derive_status(graph, decision.id)
        links = [item for item in graph.evidence_links if item.decision_id == decision.id]
        approvals = sorted(
            (item for item in graph.approvals if item.decision_id == decision.id),
            key=lambda item: item.sequence,
        )
        last = approvals[-1] if approvals else None
        supports = [item for item in links if item.stance is Stance.SUPPORTS]
        countable_support = any(_countable(graph, item) for item in supports)
        countable_contra = any(
            _countable(graph, item) for item in links if item.stance is Stance.CONTRADICTS
        )
        if report.status is DecisionStatus.APPROVED:
            assert last is not None and last.verdict is ApprovalVerdict.APPROVED
            assert last.support_fingerprint == support_fingerprint(graph, decision.id)
        if report.status in (
            DecisionStatus.SUPPORTED,
            DecisionStatus.CONFLICTING,
            DecisionStatus.APPROVED,
        ):
            assert countable_support
        if DecisionStatus.CONFLICTING in (report.status, report.evidential_status):
            assert countable_support and countable_contra
        if report.status is DecisionStatus.UNSUPPORTED:
            assert not countable_support
            for link in supports:
                claim = next(item for item in graph.claims if item.id == link.claim_id)
                version = next(
                    item for item in graph.versions if item.id == claim.source_version_id
                )
                unchecked = not any(item.claim_id == claim.id for item in graph.checks)
                assert not (
                    unchecked and version.authority is not SourceAuthority.AUTOMATED_INFERENCE
                )
        if report.status is DecisionStatus.REJECTED:
            assert last is not None and last.verdict is ApprovalVerdict.REJECTED
        assert report.evidential_status in EVIDENTIAL_STATUSES
        assert list(report.reasons) == sorted(set(report.reasons), key=list(StatusReason).index)
