"""Function inspector read model: link gathering, ordering, warnings and symbol summaries."""

from __future__ import annotations

from datetime import timedelta

import pytest
from provenance_builders import (
    ENVIRONMENT,
    CompleteProject,
    build_complete_real_project,
    fingerprint,
    make_service,
)

from asca.application.demo import DEMO_PROJECT_ID, DEMO_TIME, seed_synthetic_demo
from asca.application.inspection import (
    FunctionInspection,
    InspectionWarning,
    inspect_function,
    link_health,
    list_symbols,
)
from asca.application.provenance import DecisionDraft, ProvenanceService, RunDraft, SymbolDraft
from asca.domain.provenance import (
    CheckMethod,
    ClaimCheck,
    ClaimCheckOutcome,
    ClaimVerificationState,
    CodeSymbol,
    Currency,
    DecisionStatus,
    FileIssue,
    FileIssueKind,
    FreshnessReason,
    IdKind,
    Language,
    LinkFreshness,
    ProvenanceGraph,
    RecordNotFoundError,
    RunOrigin,
    SourceVersion,
    Stance,
    SupersessionDimension,
    SymbolKind,
    TestKind,
    TestOutcome,
    TestResult,
    make_id,
)
from asca.infrastructure.memory_provenance import InMemoryProvenanceRepository

pytestmark = pytest.mark.unit

W = InspectionWarning


def _complete() -> tuple[ProvenanceService, ProvenanceGraph, CompleteProject]:
    service = make_service()
    names = build_complete_real_project(service)
    return service, service.load(names.project), names


@pytest.fixture(scope="module")
def complete() -> tuple[ProvenanceGraph, CompleteProject]:
    _, graph, names = _complete()
    return graph, names


def _demo_graph() -> ProvenanceGraph:
    repository = InMemoryProvenanceRepository()
    seed_synthetic_demo(repository)
    return repository.load(DEMO_PROJECT_ID)


def _symbol_named(graph: ProvenanceGraph, name: str) -> CodeSymbol:
    return next(item for item in graph.symbols if item.qualified_name == name)


def _single(inspection: FunctionInspection) -> None:
    assert len(inspection.decisions) == 1


# ---------------------------------------------------------------------- warning enum


def test_warning_values_are_snake_case_of_names_in_fixed_order() -> None:
    assert [item.value for item in InspectionWarning] == [
        item.name.lower() for item in InspectionWarning
    ]
    assert list(InspectionWarning)[:2] == [W.SYNTHETIC_PROJECT, W.NO_LINKED_DECISION]
    assert list(InspectionWarning)[-1] is W.TEST_RESULT_OUTDATED
    assert len(InspectionWarning) == 23


# ---------------------------------------------------------------------- demo


def test_demo_estimate_amplitude_warnings_match_the_spec() -> None:
    graph = _demo_graph()
    inspection = inspect_function(graph, _symbol_named(graph, "estimate_amplitude").id)
    assert inspection.warnings == (W.SYNTHETIC_PROJECT,)
    _single(inspection)
    view = inspection.decisions[0]
    assert view.warnings == (W.DECISION_NOT_REVIEWED, W.LINK_UNKNOWN_FRESHNESS, W.TEST_NOT_RUN)
    assert view.status.status is DecisionStatus.SUPPORTED
    assert view.freshness is LinkFreshness.UNKNOWN
    assert [item.claim_state for item in view.evidence] == [
        ClaimVerificationState.SOURCE_TEXT_CHECKED
    ]
    assert view.evidence[0].counts_as_support
    assert len(view.tests) == 1
    test = view.tests[0]
    assert (test.latest_run, test.latest_result, test.is_latest_revision) == (None, None, None)
    assert inspection.direct_tests == ()
    assert inspection.project.is_synthetic
    assert inspection.project_revision == graph.revision
    assert inspection.revision.id == inspection.symbol.revision_id


def test_demo_unsupported_decision_has_no_verifying_test_warning() -> None:
    graph = _demo_graph()
    inspection = inspect_function(graph, _symbol_named(graph, "subtract_pedestal").id)
    _single(inspection)
    view = inspection.decisions[0]
    assert view.status.status is DecisionStatus.UNSUPPORTED
    # The CONTEXT claim is never counted, so it adds no claim or currency warning.
    assert view.warnings == (
        W.DECISION_UNSUPPORTED,
        W.DECISION_NOT_REVIEWED,
        W.LINK_UNKNOWN_FRESHNESS,
        W.NO_VERIFYING_TEST,
    )
    assert [item.link.stance for item in view.evidence] == [Stance.CONTEXT]
    assert not view.evidence[0].counts_as_support


def test_inspection_is_deterministic() -> None:
    graph = _demo_graph()
    symbol = _symbol_named(graph, "estimate_amplitude")
    assert inspect_function(graph, symbol.id) == inspect_function(_demo_graph(), symbol.id)


# ---------------------------------------------------------------------- complete project


def test_links_on_the_same_key_are_gathered_across_revisions(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    rev2_estimate = next(
        graph.get(CodeSymbol, item)
        for item in names.revision2_symbols
        if graph.get(CodeSymbol, item).qualified_name == "estimate_amplitude"
    )
    assert rev2_estimate.id != names.symbol_current
    inspection = inspect_function(graph, rev2_estimate.id)
    assert [view.implementation_link.id for view in inspection.decisions] == [names.link_current]
    assert inspection.revision.id == names.revision2
    assert inspection.symbol.id == rev2_estimate.id


def test_symbol_tests_on_the_same_key_are_gathered_across_revisions() -> None:
    service, graph, names = _complete()
    rev2_estimate = next(
        item
        for item in names.revision2_symbols
        if graph.get(CodeSymbol, item).qualified_name == "estimate_amplitude"
    )
    before = inspect_function(graph, rev2_estimate)
    assert before.direct_tests == ()
    test = service.register_test_case(
        names.project,
        node_id="tests/test_estimators.py::test_amplitude_symbol",
        kind=TestKind.UNIT,
        description="Symbol-level test linked on the first revision.",
    )
    service.link_verification(names.project, test, symbol_id=names.symbol_current)
    graph = service.load(names.project)
    for symbol_id in (names.symbol_current, rev2_estimate):
        inspection = inspect_function(graph, symbol_id)
        assert [view.test_case.id for view in inspection.direct_tests] == [test]
        assert W.TEST_NOT_RUN in inspection.warnings


def test_links_from_several_revisions_are_ordered_by_decision() -> None:
    service, graph, names = _complete()
    rev2_estimate = next(
        item
        for item in names.revision2_symbols
        if graph.get(CodeSymbol, item).qualified_name == "estimate_amplitude"
    )
    later = service.link_implementation(names.project, names.df, rev2_estimate)
    graph = service.load(names.project)
    inspection = inspect_function(graph, names.symbol_current)
    assert [view.decision.id for view in inspection.decisions] == [names.da, names.df]
    assert [view.implementation_link.id for view in inspection.decisions] == [
        names.link_current,
        later,
    ]
    summary = next(
        item for item in list_symbols(graph) if item.symbol.qualified_name == "estimate_amplitude"
    )
    assert summary.decision_count == 2


@pytest.mark.parametrize(
    ("attribute", "freshness"),
    [
        ("symbol_current", LinkFreshness.CURRENT),
        ("symbol_stale", LinkFreshness.STALE),
        ("symbol_moved", LinkFreshness.MOVED),
        ("symbol_orphaned", LinkFreshness.ORPHANED),
    ],
)
def test_freshness_per_symbol(
    complete: tuple[ProvenanceGraph, CompleteProject], attribute: str, freshness: LinkFreshness
) -> None:
    graph, names = complete
    inspection = inspect_function(graph, getattr(names, attribute))
    _single(inspection)
    assert inspection.decisions[0].freshness is freshness


def test_evidence_ordering_puts_supports_before_contradicts_before_context(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    da = inspect_function(graph, names.symbol_current).decisions[0]
    assert [item.link.id for item in da.evidence] == [names.da_support, names.da_context]
    assert [item.link.stance for item in da.evidence] == [Stance.SUPPORTS, Stance.CONTEXT]
    db = inspect_function(graph, names.symbol_stale).decisions[0]
    assert [item.link.stance for item in db.evidence] == [Stance.SUPPORTS, Stance.CONTRADICTS]
    assert [item.claim.id for item in db.evidence] == [
        names.internal_claim,
        names.implementation_claim,
    ]


def test_evidence_is_ordered_by_stance_before_creation_time() -> None:
    service, _, names = _complete()
    pid = names.project
    decision = service.propose_decision(
        pid, DecisionDraft(title="Ordering", statement="Fixture.", rationale="Fixture.")
    )
    created = [
        service.link_evidence(pid, decision, claim, stance)
        for claim, stance in (
            (names.working_claim, Stance.CONTEXT),
            (names.implementation_claim, Stance.CONTRADICTS),
            (names.internal_claim, Stance.CONTEXT),
            (names.journal_claim, Stance.SUPPORTS),
        )
    ]
    service.link_implementation(pid, decision, names.symbol_current)
    graph = service.load(pid)
    view = next(
        item
        for item in inspect_function(graph, names.symbol_current).decisions
        if item.decision.id == decision
    )
    assert [item.link.id for item in view.evidence] == [
        created[3],
        created[1],
        created[0],
        created[2],
    ]


def test_decisions_are_ordered_by_decision_creation_not_link_id() -> None:
    service, _, names = _complete()
    pid = names.project
    decisions = [
        service.propose_decision(
            pid, DecisionDraft(title=f"Ordering {n}", statement="Fixture.", rationale="Fixture.")
        )
        for n in range(4)
    ]
    # Links are created in reverse decision order, so link order is not decision order.
    links = {
        decision: service.link_implementation(pid, decision, names.symbol_current)
        for decision in reversed(decisions)
    }
    graph = service.load(pid)
    shown = [
        view.decision.id
        for view in inspect_function(graph, names.symbol_current).decisions
        if view.decision.id in links
    ]
    assert shown == decisions
    assert sorted(links, key=lambda decision: links[decision]) != decisions


def test_counts_as_support_is_false_for_automated_inference_and_context(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    da = inspect_function(graph, names.symbol_current).decisions[0]
    assert [item.counts_as_support for item in da.evidence] == [True, False]
    dd = inspect_function(graph, names.symbol_moved).decisions[0]
    assert dd.decision.id == names.dd
    assert [item.claim.id for item in dd.evidence] == [names.automated_claim]
    assert dd.evidence[0].claim_state is ClaimVerificationState.SOURCE_TEXT_CHECKED
    assert not dd.evidence[0].counts_as_support
    db = inspect_function(graph, names.symbol_stale).decisions[0]
    # A checked contradiction is countable but never counts as support.
    assert [item.counts_as_support for item in db.evidence] == [True, False]


def test_evidence_view_carries_source_version_check_and_currency(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    support = inspect_function(graph, names.symbol_current).decisions[0].evidence[0]
    assert support.version.id == names.journal_version
    assert support.source.id == names.journal_source
    assert support.last_check is not None and support.last_check.sequence == 1
    assert support.scientific_currency.value == "current"
    assert support.technical_currency.value == "superseded"
    assert [item.id for item in support.superseded_by] == [names.journal_notice]
    context = inspect_function(graph, names.symbol_current).decisions[0].evidence[1]
    assert context.last_check is None
    assert context.claim_state is ClaimVerificationState.NOT_CHECKED


def test_latest_result_and_is_latest_revision(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    da = inspect_function(graph, names.symbol_current).decisions[0]
    (analytic,) = da.tests
    assert analytic.test_case.id == names.test_analytic
    assert analytic.latest_run is not None and analytic.latest_run.id == names.run2
    assert analytic.latest_result is not None
    assert analytic.latest_result.outcome is TestOutcome.PASSED
    assert analytic.is_latest_revision is True

    moved = inspect_function(graph, names.symbol_moved)
    (unit,) = moved.direct_tests
    assert unit.test_case.id == names.test_unit
    assert unit.latest_run is not None and unit.latest_run.id == names.run1
    assert unit.is_latest_revision is False


def test_test_failing_and_outdated_warnings_appear(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    db = inspect_function(graph, names.symbol_stale).decisions[0]
    assert db.warnings == (W.LINK_STALE, W.TEST_FAILING)
    assert db.tests[0].latest_result is not None
    assert db.tests[0].latest_result.outcome is TestOutcome.FAILED

    moved = inspect_function(graph, names.symbol_moved)
    assert moved.warnings == (W.TEST_RESULT_OUTDATED,)
    dd = moved.decisions[0]
    # A direct test on the symbol suppresses NO_VERIFYING_TEST for an untested decision.
    assert dd.tests == ()
    assert dd.warnings == (
        W.DECISION_UNSUPPORTED,
        W.DECISION_NOT_REVIEWED,
        W.AUTOMATED_INFERENCE_IGNORED,
        W.LINK_MOVED,
    )


@pytest.mark.parametrize(
    ("outcome", "failing"),
    [
        (TestOutcome.FAILED, True),
        (TestOutcome.ERROR, True),
        (TestOutcome.PASSED, False),
        (TestOutcome.SKIPPED, False),
        (TestOutcome.XFAILED, False),
        (TestOutcome.XPASSED, False),
    ],
)
def test_test_failing_follows_the_latest_outcome(outcome: TestOutcome, failing: bool) -> None:
    service, _, names = _complete()
    service.record_validation_run(
        names.project,
        RunDraft(
            revision_id=names.revision2,
            environment=ENVIRONMENT,
            origin=RunOrigin.EXECUTED,
            started_at=DEMO_TIME + timedelta(hours=3),
            finished_at=DEMO_TIME + timedelta(hours=3, minutes=5),
            results=(TestResult(names.test_regression, outcome, 1.0, None),),
        ),
    )
    db = inspect_function(service.load(names.project), names.symbol_stale).decisions[0]
    assert db.tests[0].latest_result is not None
    assert db.tests[0].latest_result.outcome is outcome
    assert (W.TEST_FAILING in db.warnings) is failing


def test_latest_run_is_the_one_that_finished_last() -> None:
    """A long failing run that started first but finished last is the latest result."""
    service, _, names = _complete()
    for start, end, outcome in (
        (timedelta(hours=3), timedelta(hours=6), TestOutcome.FAILED),
        (timedelta(hours=4), timedelta(hours=5), TestOutcome.PASSED),
    ):
        service.record_validation_run(
            names.project,
            RunDraft(
                revision_id=names.revision2,
                environment=ENVIRONMENT,
                origin=RunOrigin.EXECUTED,
                started_at=DEMO_TIME + start,
                finished_at=DEMO_TIME + end,
                results=(TestResult(names.test_regression, outcome, 1.0, None),),
            ),
        )
    db = inspect_function(service.load(names.project), names.symbol_stale).decisions[0]
    latest = db.tests[0].latest_result
    assert latest is not None and latest.outcome is TestOutcome.FAILED
    assert W.TEST_FAILING in db.warnings


def test_status_derived_warnings_for_rejected_and_approved_decisions(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    de = inspect_function(graph, names.symbol_orphaned).decisions[0]
    assert de.status.status is DecisionStatus.REJECTED
    assert [item.id for item in de.approvals] == [names.rejection_de]
    assert de.warnings == (
        W.DECISION_REJECTED,
        W.SOURCE_TECHNICALLY_SUPERSEDED,
        W.LINK_ORPHANED,
        W.NO_VERIFYING_TEST,
    )
    da = inspect_function(graph, names.symbol_current).decisions[0]
    assert da.status.status is DecisionStatus.APPROVED
    assert da.warnings == (W.SOURCE_TECHNICALLY_SUPERSEDED,)


def test_approval_stale_after_a_later_mismatch_check() -> None:
    _, graph, names = _complete()
    version = graph.get(SourceVersion, names.journal_version)
    mismatch = ClaimCheck(
        make_id(IdKind.CLAIM_CHECK, "f" * 32),
        graph.project.id,
        names.journal_claim,
        graph.next_check_sequence(names.journal_claim),
        ClaimCheckOutcome.MISMATCH,
        CheckMethod.NORMALIZED_SUBSTRING,
        version.content_sha256,
        None,
        DEMO_TIME + timedelta(days=1),
    )
    stale = graph.append([mismatch])
    da = inspect_function(stale, names.symbol_current).decisions[0]
    assert da.status.approval_stale
    assert da.status.status is DecisionStatus.UNSUPPORTED
    assert da.warnings == (
        W.DECISION_UNSUPPORTED,
        W.APPROVAL_STALE,
        W.CLAIM_MISMATCH,
        W.SOURCE_TECHNICALLY_SUPERSEDED,
    )
    assert da.evidence[0].last_check is not None
    assert da.evidence[0].last_check.sequence == 2


def test_scientific_supersession_of_counted_evidence_warns() -> None:
    service, _, names = _complete()
    service.record_supersession(
        names.project,
        superseded=names.journal_version,
        superseding=None,
        dimension=SupersessionDimension.SCIENTIFIC,
        reason="Fixture: the article's result was revised.",
    )
    da = inspect_function(service.load(names.project), names.symbol_current).decisions[0]
    assert W.SOURCE_SCIENTIFICALLY_SUPERSEDED in da.warnings
    assert W.SOURCE_TECHNICALLY_SUPERSEDED in da.warnings
    assert da.evidence[0].scientific_currency is Currency.SUPERSEDED
    assert len(da.evidence[0].superseded_by) == 2


def test_unchecked_and_unavailable_counted_claims_warn() -> None:
    service, _, names = _complete()
    service.mark_claim_unavailable(names.project, names.internal_claim, reason="Fixture.")
    service.link_evidence(names.project, names.db, names.working_claim, Stance.SUPPORTS)
    db = inspect_function(service.load(names.project), names.symbol_stale).decisions[0]
    assert W.CLAIM_UNAVAILABLE in db.warnings
    assert W.CLAIM_NOT_CHECKED in db.warnings
    assert W.DECISION_PROPOSED in db.warnings
    assert W.APPROVAL_STALE in db.warnings


def test_superseded_decision_warns() -> None:
    service, _, names = _complete()
    older = service.propose_decision(
        names.project,
        DecisionDraft(title="Dg superseded", statement="Fixture.", rationale="Fixture."),
    )
    service.link_evidence(names.project, older, names.working_claim, Stance.SUPPORTS)
    service.link_implementation(names.project, older, names.symbol_stale)
    newer = service.propose_decision(
        names.project,
        DecisionDraft(
            title="Dh replacement", statement="Fixture.", rationale="Fixture.", supersedes_id=older
        ),
    )
    graph = service.load(names.project)
    views = {
        view.decision.id: view for view in inspect_function(graph, names.symbol_stale).decisions
    }
    view = views[older]
    assert view.status.superseded_by == newer
    assert view.warnings == (
        W.DECISION_PROPOSED,
        W.DECISION_SUPERSEDED,
        W.DECISION_NOT_REVIEWED,
        W.CLAIM_NOT_CHECKED,
        W.LINK_STALE,
        W.NO_VERIFYING_TEST,
    )


def test_conflicting_evidential_status_warns_when_not_approved() -> None:
    service, _, names = _complete()
    decision = service.propose_decision(
        names.project,
        DecisionDraft(title="Dg conflicting", statement="Fixture.", rationale="Fixture."),
    )
    service.link_evidence(names.project, decision, names.internal_claim, Stance.SUPPORTS)
    service.link_evidence(names.project, decision, names.implementation_claim, Stance.CONTRADICTS)
    service.link_implementation(names.project, decision, names.symbol_current)
    graph = service.load(names.project)
    view = next(
        item
        for item in inspect_function(graph, names.symbol_current).decisions
        if item.decision.id == decision
    )
    assert view.status.status is DecisionStatus.CONFLICTING
    assert W.DECISION_CONFLICTING in view.warnings
    assert W.DECISION_NOT_REVIEWED in view.warnings


def test_symbol_without_links_warns_no_linked_decision() -> None:
    service, _, names = _complete()
    service.record_workspace_revision(
        names.project,
        vcs_ref="fixture-rev-3",
        symbols=[
            SymbolDraft(
                Language.PYTHON,
                SymbolKind.FUNCTION,
                "unlinked_helper",
                "src/reco/helpers.py",
                None,
                fingerprint(99),
            ),
        ],
        symbols_indexed=True,
    )
    graph = service.load(names.project)
    helper = _symbol_named(graph, "unlinked_helper")
    inspection = inspect_function(graph, helper.id)
    assert inspection.decisions == ()
    assert inspection.direct_tests == ()
    assert inspection.warnings == (W.NO_LINKED_DECISION,)
    assert inspection.file_issue is None


def test_moved_symbol_shows_the_carried_link(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    calibration = next(
        item
        for item in names.revision2_symbols
        if graph.get(CodeSymbol, item).file_path == "src/reco/calibration.py"
    )
    inspection = inspect_function(graph, calibration)
    assert inspection.symbol.id == calibration
    assert inspection.revision.id == names.revision2
    (view,) = inspection.decisions
    assert view.decision.id == names.dd
    assert view.implementation_link.id == names.link_moved
    assert view.freshness is LinkFreshness.MOVED
    assert W.LINK_MOVED in view.warnings
    trace = view.trace
    assert trace.freshness is view.freshness
    assert trace.reason is FreshnessReason.RELOCATED
    assert trace.relocated
    assert trace.origin.id == names.symbol_moved
    assert trace.origin.file_path == "src/reco/estimators.py"
    assert trace.current is not None and trace.current.id == calibration
    assert trace.last_seen.id == calibration
    assert trace.evaluated_revision is not None
    assert trace.evaluated_revision.id == names.revision2
    assert trace.lost_in_revision is None
    assert trace.candidates == ()
    assert trace.successors == (calibration,)
    # The symbol-level test linked to the origin follows the symbol to its new file.
    assert [item.test_case.id for item in inspection.direct_tests] == [names.test_unit]
    # Inspecting the origin shows the same decision with the same trace.
    origin = inspect_function(graph, names.symbol_moved)
    assert [item.trace for item in origin.decisions] == [trace]


def test_traces_carry_reasons_for_every_complete_project_link(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    reasons = {
        attribute: inspect_function(graph, getattr(names, attribute)).decisions[0].trace.reason
        for attribute in ("symbol_current", "symbol_stale", "symbol_moved", "symbol_orphaned")
    }
    assert reasons == {
        "symbol_current": FreshnessReason.UNCHANGED,
        "symbol_stale": FreshnessReason.CONTENT_CHANGED,
        "symbol_moved": FreshnessReason.RELOCATED,
        "symbol_orphaned": FreshnessReason.REMOVED,
    }
    orphaned = inspect_function(graph, names.symbol_orphaned).decisions[0].trace
    assert orphaned.current is None
    assert orphaned.lost_in_revision is not None
    assert orphaned.lost_in_revision.id == names.revision2
    assert orphaned.last_seen.id == names.symbol_orphaned


def test_a_reused_name_does_not_inherit_an_orphaned_link() -> None:
    service, _, names = _complete()
    revision = service.record_workspace_revision(
        names.project,
        vcs_ref="fixture-rev-3",
        symbols=[
            SymbolDraft(
                Language.PYTHON,
                SymbolKind.METHOD,
                "LegacyFit.fit",
                "src/reco/estimators.py",
                None,
                fingerprint(40),
            ),
        ],
        symbols_indexed=True,
    )
    graph = service.load(names.project)
    (reused,) = revision.symbol_ids
    inspection = inspect_function(graph, reused)
    assert inspection.decisions == ()
    assert W.NO_LINKED_DECISION in inspection.warnings
    (summary,) = list_symbols(graph)
    assert (summary.symbol.id, summary.decision_count, summary.worst_freshness) == (
        reused,
        0,
        None,
    )
    # The original link stays orphaned: a lost link is never resurrected.
    original = inspect_function(graph, names.symbol_orphaned).decisions[0]
    assert original.freshness is LinkFreshness.ORPHANED
    assert original.trace.lost_in_revision is not None
    assert original.trace.lost_in_revision.id == names.revision2


def test_file_issue_on_inspection() -> None:
    service, _, names = _complete()
    estimators = "src/reco/estimators.py"
    revision3 = service.record_workspace_revision(
        names.project,
        vcs_ref="fixture-rev-3",
        symbols=[
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
        file_issues=[FileIssue(estimators, FileIssueKind.SYNTAX_ERROR)],
    )
    graph = service.load(names.project)
    inspection = inspect_function(graph, names.symbol_current)
    assert inspection.file_issue == FileIssue(estimators, FileIssueKind.SYNTAX_ERROR)
    (view,) = inspection.decisions
    assert view.freshness is LinkFreshness.UNKNOWN
    assert view.trace.reason is FreshnessReason.FILE_NOT_PARSED
    assert view.trace.current is None
    rev2_estimate = next(
        item
        for item in names.revision2_symbols
        if graph.get(CodeSymbol, item).qualified_name == "estimate_amplitude"
    )
    # The last known symbol is carried forward, so the link is unknown, never orphaned.
    assert view.trace.last_seen.id == rev2_estimate
    assert W.LINK_UNKNOWN_FRESHNESS in view.warnings
    assert inspect_function(graph, rev2_estimate).file_issue == inspection.file_issue

    (calibration,) = revision3.symbol_ids
    assert inspect_function(graph, calibration).file_issue is None
    assert [item.symbol.file_path for item in list_symbols(graph)] == ["src/reco/calibration.py"]


def test_file_issue_is_none_without_an_indexed_revision() -> None:
    service = make_service()
    project = service.create_project("Unindexed fixture project", is_synthetic=False)
    revision = service.record_workspace_revision(
        project,
        vcs_ref=None,
        symbols=[SymbolDraft(Language.PYTHON, SymbolKind.FUNCTION, "f", "src/f.py")],
        symbols_indexed=False,
    )
    inspection = inspect_function(service.load(project), revision.symbol_ids[0])
    assert inspection.file_issue is None
    assert inspection.warnings == (W.NO_LINKED_DECISION,)


def test_synthetic_run_counts_as_not_run() -> None:
    repository = InMemoryProvenanceRepository()
    seed_synthetic_demo(repository)
    graph = repository.load(DEMO_PROJECT_ID)
    (revision,) = graph.revisions
    (test_case,) = graph.test_cases
    make_service(repository).record_validation_run(
        DEMO_PROJECT_ID,
        RunDraft(
            revision_id=revision.id,
            environment=ENVIRONMENT,
            origin=RunOrigin.SYNTHETIC,
            started_at=DEMO_TIME + timedelta(hours=3),
            finished_at=DEMO_TIME + timedelta(hours=3, minutes=1),
            results=(TestResult(test_case.id, TestOutcome.PASSED, None, None),),
        ),
    )
    graph = repository.load(DEMO_PROJECT_ID)
    view = inspect_function(graph, _symbol_named(graph, "estimate_amplitude").id).decisions[0]
    (test,) = view.tests
    assert test.latest_run is not None and test.latest_run.origin is RunOrigin.SYNTHETIC
    assert test.is_latest_revision is True
    assert W.TEST_NOT_RUN in view.warnings


def test_unknown_symbol_raises_record_not_found(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    with pytest.raises(RecordNotFoundError):
        inspect_function(graph, make_id(IdKind.SYMBOL, "0" * 32))
    with pytest.raises(RecordNotFoundError):
        inspect_function(graph, names.da)


# ---------------------------------------------------------------------- list_symbols


def test_list_symbols_worst_freshness_and_decision_count(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    summaries = list_symbols(graph)
    assert [item.symbol.id for item in summaries] == sorted(
        names.revision2_symbols,
        key=lambda item: (
            graph.get(CodeSymbol, item).file_path,
            graph.get(CodeSymbol, item).qualified_name,
        ),
    )
    table = {
        (item.symbol.file_path, item.symbol.qualified_name): (
            item.decision_count,
            item.worst_freshness,
        )
        for item in summaries
    }
    assert table == {
        ("src/reco/calibration.py", "calibrate"): (1, LinkFreshness.MOVED),
        ("src/reco/estimators.py", "estimate_amplitude"): (1, LinkFreshness.CURRENT),
        ("src/reco/estimators.py", "subtract_pedestal"): (1, LinkFreshness.STALE),
    }


def test_list_symbols_worst_freshness_prefers_the_most_severe() -> None:
    service, graph, names = _complete()
    rev2_subtract = next(
        item
        for item in names.revision2_symbols
        if graph.get(CodeSymbol, item).qualified_name == "subtract_pedestal"
    )
    service.link_implementation(names.project, names.df, rev2_subtract)
    summary = next(
        item
        for item in list_symbols(service.load(names.project))
        if item.symbol.qualified_name == "subtract_pedestal"
    )
    # The rev2 link is CURRENT, the rev1 link STALE: the worst one wins.
    assert summary.decision_count == 2
    assert summary.worst_freshness is LinkFreshness.STALE


def test_list_symbols_uses_the_latest_revision_even_when_unindexed() -> None:
    service, _, names = _complete()
    service.record_workspace_revision(
        names.project,
        vcs_ref="unindexed",
        symbols=[
            SymbolDraft(Language.PYTHON, SymbolKind.FUNCTION, "estimate_amplitude", "src/x.py"),
        ],
        symbols_indexed=False,
    )
    summaries = list_symbols(service.load(names.project))
    assert [(item.symbol.file_path, item.decision_count) for item in summaries] == [("src/x.py", 0)]


def test_list_symbols_without_revisions_is_empty() -> None:
    service = make_service()
    project = service.create_project("Empty fixture project", is_synthetic=False)
    assert list_symbols(service.load(project)) == ()


# ---------------------------------------------------------------------- link_health


def test_link_health_order() -> None:
    service, graph, names = _complete()
    pid = names.project
    rev2_estimate = next(
        item
        for item in names.revision2_symbols
        if graph.get(CodeSymbol, item).qualified_name == "estimate_amplitude"
    )
    second_current = service.link_implementation(pid, names.da, rev2_estimate)
    dg = service.propose_decision(
        pid, DecisionDraft(title="Dg late stale", statement="Fixture.", rationale="Fixture.")
    )
    second_stale = service.link_implementation(pid, dg, names.symbol_stale)
    late = service.record_workspace_revision(
        pid,
        vcs_ref="unindexed",
        symbols=[SymbolDraft(Language.PYTHON, SymbolKind.FUNCTION, "late", "src/reco/late.py")],
        symbols_indexed=False,
    )
    unknown = service.link_implementation(pid, names.df, late.symbol_ids[0])
    graph = service.load(pid)
    health = link_health(graph)
    assert [item.link.id for item in health] == [
        names.link_orphaned,
        names.link_stale,
        second_stale,
        names.link_moved,
        unknown,
        names.link_current,
        second_current,
    ]
    assert [item.trace.freshness for item in health] == [
        LinkFreshness.ORPHANED,
        LinkFreshness.STALE,
        LinkFreshness.STALE,
        LinkFreshness.MOVED,
        LinkFreshness.UNKNOWN,
        LinkFreshness.CURRENT,
        LinkFreshness.CURRENT,
    ]
    assert [item.decision.id for item in health] == [
        names.de,
        names.db,
        dg,
        names.dd,
        names.df,
        names.da,
        names.da,
    ]
    assert health[4].trace.reason is FreshnessReason.NOT_FINGERPRINTED
    assert all(item.link.decision_id == item.decision.id for item in health)
    assert all(item.trace.origin.id == item.link.symbol_id for item in health)
    assert link_health(service.load(pid)) == health


def test_link_health_is_empty_without_links() -> None:
    service = make_service()
    project = service.create_project("Empty fixture project", is_synthetic=False)
    assert link_health(service.load(project)) == ()
    assert link_health(_demo_graph())[0].trace.reason is FreshnessReason.NOT_FINGERPRINTED
