"""Function inspector read model: what a code symbol implements and how well it is backed.

Pure functions over a loaded :class:`ProvenanceGraph`. Nothing here writes, and every
result is deterministic for a given graph.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

from asca.domain.provenance import (
    COUNTED_STANCES,
    Approval,
    Claim,
    ClaimCheck,
    ClaimVerificationState,
    CodeSymbol,
    Currency,
    DecisionStatus,
    DecisionStatusReport,
    EvidenceLink,
    ImplementationLink,
    LinkFreshness,
    Project,
    ProvenanceGraph,
    RunOrigin,
    ScientificDecision,
    Source,
    SourceVersion,
    Stance,
    StatusReason,
    SupersessionDimension,
    SupersessionNotice,
    TestCase,
    TestOutcome,
    TestResult,
    ValidationRun,
    WorkspaceRevision,
    currency,
    derive_status,
    is_countable,
    latest_result,
    link_freshness,
)


class InspectionWarning(StrEnum):
    """Inspector warnings; declaration order is the presentation order."""

    SYNTHETIC_PROJECT = "synthetic_project"
    NO_LINKED_DECISION = "no_linked_decision"
    DECISION_PROPOSED = "decision_proposed"
    DECISION_UNSUPPORTED = "decision_unsupported"
    DECISION_CONFLICTING = "decision_conflicting"
    DECISION_REJECTED = "decision_rejected"
    DECISION_SUPERSEDED = "decision_superseded"
    DECISION_NOT_REVIEWED = "decision_not_reviewed"
    APPROVAL_STALE = "approval_stale"
    AUTOMATED_INFERENCE_IGNORED = "automated_inference_ignored"
    CLAIM_NOT_CHECKED = "claim_not_checked"
    CLAIM_MISMATCH = "claim_mismatch"
    CLAIM_UNAVAILABLE = "claim_unavailable"
    SOURCE_SCIENTIFICALLY_SUPERSEDED = "source_scientifically_superseded"
    SOURCE_TECHNICALLY_SUPERSEDED = "source_technically_superseded"
    LINK_UNKNOWN_FRESHNESS = "link_unknown_freshness"
    LINK_STALE = "link_stale"
    LINK_MOVED = "link_moved"
    LINK_ORPHANED = "link_orphaned"
    NO_VERIFYING_TEST = "no_verifying_test"
    TEST_NOT_RUN = "test_not_run"
    TEST_FAILING = "test_failing"
    TEST_RESULT_OUTDATED = "test_result_outdated"


_WARNING_ORDER = {warning: position for position, warning in enumerate(InspectionWarning)}
_STANCE_ORDER = {Stance.SUPPORTS: 0, Stance.CONTRADICTS: 1, Stance.CONTEXT: 2}
_FRESHNESS_SEVERITY = {
    LinkFreshness.CURRENT: 0,
    LinkFreshness.UNKNOWN: 1,
    LinkFreshness.MOVED: 2,
    LinkFreshness.STALE: 3,
    LinkFreshness.ORPHANED: 4,
}
_STATUS_WARNINGS = {
    DecisionStatus.PROPOSED: InspectionWarning.DECISION_PROPOSED,
    DecisionStatus.UNSUPPORTED: InspectionWarning.DECISION_UNSUPPORTED,
    DecisionStatus.CONFLICTING: InspectionWarning.DECISION_CONFLICTING,
    DecisionStatus.REJECTED: InspectionWarning.DECISION_REJECTED,
}
_CLAIM_WARNINGS = {
    ClaimVerificationState.NOT_CHECKED: InspectionWarning.CLAIM_NOT_CHECKED,
    ClaimVerificationState.MISMATCH: InspectionWarning.CLAIM_MISMATCH,
    ClaimVerificationState.UNAVAILABLE: InspectionWarning.CLAIM_UNAVAILABLE,
}
_FRESHNESS_WARNINGS = {
    LinkFreshness.UNKNOWN: InspectionWarning.LINK_UNKNOWN_FRESHNESS,
    LinkFreshness.STALE: InspectionWarning.LINK_STALE,
    LinkFreshness.MOVED: InspectionWarning.LINK_MOVED,
    LinkFreshness.ORPHANED: InspectionWarning.LINK_ORPHANED,
}
_FAILING_OUTCOMES = frozenset({TestOutcome.FAILED, TestOutcome.ERROR})


@dataclass(frozen=True, slots=True)
class EvidenceView:
    link: EvidenceLink
    claim: Claim
    claim_state: ClaimVerificationState
    last_check: ClaimCheck | None
    counts_as_support: bool
    source: Source
    version: SourceVersion
    scientific_currency: Currency
    technical_currency: Currency
    superseded_by: tuple[SupersessionNotice, ...]


@dataclass(frozen=True, slots=True)
class TestView:
    __test__: ClassVar[bool] = False

    test_case: TestCase
    latest_run: ValidationRun | None
    latest_result: TestResult | None
    is_latest_revision: bool | None


@dataclass(frozen=True, slots=True)
class DecisionView:
    decision: ScientificDecision
    status: DecisionStatusReport
    implementation_link: ImplementationLink
    freshness: LinkFreshness
    evidence: tuple[EvidenceView, ...]
    tests: tuple[TestView, ...]
    approvals: tuple[Approval, ...]
    warnings: tuple[InspectionWarning, ...]


@dataclass(frozen=True, slots=True)
class FunctionInspection:
    project: Project
    project_revision: int
    symbol: CodeSymbol
    revision: WorkspaceRevision
    decisions: tuple[DecisionView, ...]
    direct_tests: tuple[TestView, ...]
    warnings: tuple[InspectionWarning, ...]


@dataclass(frozen=True, slots=True)
class SymbolSummary:
    symbol: CodeSymbol
    decision_count: int
    worst_freshness: LinkFreshness | None


def _ordered(warnings: Iterable[InspectionWarning]) -> tuple[InspectionWarning, ...]:
    return tuple(sorted(set(warnings), key=_WARNING_ORDER.__getitem__))


def _evidence_view(graph: ProvenanceGraph, link: EvidenceLink) -> EvidenceView:
    claim = graph.get(Claim, link.claim_id)
    version = graph.get(SourceVersion, claim.source_version_id)
    notices = sorted(graph.notices_for(version.id), key=lambda item: (item.recorded_at, item.id))
    return EvidenceView(
        link=link,
        claim=claim,
        claim_state=graph.claim_state(claim.id),
        last_check=graph.latest_check(claim.id),
        counts_as_support=link.stance is Stance.SUPPORTS and is_countable(graph, link),
        source=graph.get(Source, version.source_id),
        version=version,
        scientific_currency=currency(graph, version.id, SupersessionDimension.SCIENTIFIC),
        technical_currency=currency(graph, version.id, SupersessionDimension.TECHNICAL),
        superseded_by=tuple(notices),
    )


def _test_view(graph: ProvenanceGraph, test_case: TestCase) -> TestView:
    latest = latest_result(graph, test_case.id)
    if latest is None:
        return TestView(test_case, None, None, None)
    run, result = latest
    newest = graph.latest_revision()
    return TestView(
        test_case,
        run,
        result,
        newest is not None and run.revision_id == newest.id,
    )


def _test_views(graph: ProvenanceGraph, test_case_ids: Iterable[str]) -> tuple[TestView, ...]:
    cases = sorted(
        (graph.get(TestCase, test_id) for test_id in set(test_case_ids)),
        key=lambda case: (case.node_id, case.id),
    )
    return tuple(_test_view(graph, case) for case in cases)


def _test_warnings(tests: Iterable[TestView]) -> set[InspectionWarning]:
    warnings: set[InspectionWarning] = set()
    for view in tests:
        if view.latest_run is None or view.latest_run.origin is RunOrigin.SYNTHETIC:
            warnings.add(InspectionWarning.TEST_NOT_RUN)
        if view.latest_result is not None and view.latest_result.outcome in _FAILING_OUTCOMES:
            warnings.add(InspectionWarning.TEST_FAILING)
        if view.is_latest_revision is False:
            warnings.add(InspectionWarning.TEST_RESULT_OUTDATED)
    return warnings


def _decision_warnings(
    report: DecisionStatusReport,
    freshness: LinkFreshness,
    evidence: tuple[EvidenceView, ...],
    tests: tuple[TestView, ...],
    approvals: tuple[Approval, ...],
    direct_tests: tuple[TestView, ...],
) -> tuple[InspectionWarning, ...]:
    warnings: set[InspectionWarning] = set()
    status_warning = _STATUS_WARNINGS.get(report.status)
    if status_warning is not None:
        warnings.add(status_warning)
    if report.superseded_by is not None:
        warnings.add(InspectionWarning.DECISION_SUPERSEDED)
    if not approvals:
        warnings.add(InspectionWarning.DECISION_NOT_REVIEWED)
    if report.approval_stale:
        warnings.add(InspectionWarning.APPROVAL_STALE)
    if StatusReason.AUTOMATED_INFERENCE_IGNORED in report.reasons:
        warnings.add(InspectionWarning.AUTOMATED_INFERENCE_IGNORED)
    for item in evidence:
        if item.link.stance not in COUNTED_STANCES:
            continue
        claim_warning = _CLAIM_WARNINGS.get(item.claim_state)
        if claim_warning is not None:
            warnings.add(claim_warning)
        if item.scientific_currency is Currency.SUPERSEDED:
            warnings.add(InspectionWarning.SOURCE_SCIENTIFICALLY_SUPERSEDED)
        if item.technical_currency is Currency.SUPERSEDED:
            warnings.add(InspectionWarning.SOURCE_TECHNICALLY_SUPERSEDED)
    freshness_warning = _FRESHNESS_WARNINGS.get(freshness)
    if freshness_warning is not None:
        warnings.add(freshness_warning)
    if not tests and not direct_tests:
        warnings.add(InspectionWarning.NO_VERIFYING_TEST)
    warnings.update(_test_warnings(tests))
    return _ordered(warnings)


def _decision_view(
    graph: ProvenanceGraph, link: ImplementationLink, direct_tests: tuple[TestView, ...]
) -> DecisionView:
    decision = graph.get(ScientificDecision, link.decision_id)
    report = derive_status(graph, decision.id)
    freshness = link_freshness(graph, link)
    evidence_links = sorted(
        graph.links_for(decision.id),
        key=lambda item: (_STANCE_ORDER[item.stance], item.created_at, item.id),
    )
    evidence = tuple(_evidence_view(graph, item) for item in evidence_links)
    tests = _test_views(
        graph, (item.test_case_id for item in graph.verification_links_for_decision(decision.id))
    )
    approvals = graph.approvals_for(decision.id)
    return DecisionView(
        decision=decision,
        status=report,
        implementation_link=link,
        freshness=freshness,
        evidence=evidence,
        tests=tests,
        approvals=approvals,
        warnings=_decision_warnings(report, freshness, evidence, tests, approvals, direct_tests),
    )


def inspect_function(graph: ProvenanceGraph, symbol_id: str) -> FunctionInspection:
    """Inspect one symbol; links on the same key in any revision are included.

    Raises ``RecordNotFoundError`` for an unknown symbol id.
    """
    symbol = graph.get(CodeSymbol, symbol_id)
    revision = graph.get(WorkspaceRevision, symbol.revision_id)
    same_key = {item.id for item in graph.symbols if item.key == symbol.key}
    direct_tests = _test_views(
        graph,
        (item.test_case_id for item in graph.verification_links if item.symbol_id in same_key),
    )
    links = graph.implementation_links_for_key(symbol.key)

    def link_order(link: ImplementationLink) -> tuple[object, ...]:
        decision = graph.get(ScientificDecision, link.decision_id)
        return (decision.created_at, decision.id, link.created_at, link.id)

    decisions = tuple(
        _decision_view(graph, link, direct_tests) for link in sorted(links, key=link_order)
    )
    warnings: set[InspectionWarning] = set()
    if graph.project.is_synthetic:
        warnings.add(InspectionWarning.SYNTHETIC_PROJECT)
    if not links:
        warnings.add(InspectionWarning.NO_LINKED_DECISION)
    warnings.update(_test_warnings(direct_tests))
    return FunctionInspection(
        project=graph.project,
        project_revision=graph.revision,
        symbol=symbol,
        revision=revision,
        decisions=decisions,
        direct_tests=direct_tests,
        warnings=_ordered(warnings),
    )


def list_symbols(graph: ProvenanceGraph) -> tuple[SymbolSummary, ...]:
    """Summaries of the latest revision's symbols, ordered by file path and name."""
    revision = graph.latest_revision()
    if revision is None:
        return ()
    summaries: list[SymbolSummary] = []
    for symbol in sorted(
        graph.symbols_in(revision.id), key=lambda item: (item.file_path, item.qualified_name)
    ):
        links = graph.implementation_links_for_key(symbol.key)
        worst = max(
            (link_freshness(graph, link) for link in links),
            key=_FRESHNESS_SEVERITY.__getitem__,
            default=None,
        )
        summaries.append(SymbolSummary(symbol, len(links), worst))
    return tuple(summaries)
