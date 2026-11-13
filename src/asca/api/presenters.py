"""Explicit mapping from domain records and inspection views to transport models."""

from asca.api.provenance_schemas import (
    AlternativeDTO,
    AssumptionDTO,
    ClaimCheckDTO,
    ClaimDTO,
    CodeSymbolDTO,
    DecisionViewDTO,
    EvidenceItemDTO,
    FileIssueDTO,
    FunctionInspectionResponse,
    ImplementationDTO,
    LinkHealthDTO,
    LocatorPartDTO,
    PersistentIdDTO,
    ProjectListResponse,
    ProjectSummaryDTO,
    ReviewDTO,
    RevisionDTO,
    SourceRefDTO,
    SourceVersionDTO,
    SpanDTO,
    SupersessionDTO,
    SymbolListResponse,
    SymbolLocationDTO,
    SymbolSummaryDTO,
    TestRunRefDTO,
    TestStatusDTO,
)
from asca.application.inspection import (
    DecisionView,
    EvidenceView,
    FunctionInspection,
    LinkHealth,
    SymbolSummary,
    TestView,
    link_health,
    list_symbols,
)
from asca.application.ports import ProjectSummary
from asca.domain.provenance import (
    POLICY_NOTE,
    REVIEW_NOTE,
    SYNTHETIC_NOTICE,
    Approval,
    ClaimCheck,
    CodeSymbol,
    FileIssueKind,
    FreshnessReason,
    Project,
    ProvenanceGraph,
    SourceSpan,
    SupersessionNotice,
    SymbolTrace,
    WorkspaceRevision,
)


def project_summary_dto(project: Project, revision: int) -> ProjectSummaryDTO:
    return ProjectSummaryDTO(
        id=project.id,
        title=project.title,
        is_synthetic=project.is_synthetic,
        revision=revision,
        created_at=project.created_at,
    )


def project_list_response(summaries: list[ProjectSummary]) -> ProjectListResponse:
    return ProjectListResponse(
        items=[project_summary_dto(item.project, item.revision) for item in summaries]
    )


def revision_dto(revision: WorkspaceRevision) -> RevisionDTO:
    return RevisionDTO(
        id=revision.id,
        sequence=revision.sequence,
        vcs_ref=revision.vcs_ref,
        symbols_indexed=revision.symbols_indexed,
        source_digest=revision.source_digest,
        file_issue_count=len(revision.file_issues),
    )


def _span_dto(span: SourceSpan | None) -> SpanDTO | None:
    return None if span is None else SpanDTO(start_line=span.start_line, end_line=span.end_line)


def code_symbol_dto(symbol: CodeSymbol, revision: WorkspaceRevision) -> CodeSymbolDTO:
    return CodeSymbolDTO(
        id=symbol.id,
        qualified_name=symbol.qualified_name,
        file_path=symbol.file_path,
        kind=symbol.kind,
        language=symbol.language,
        span=_span_dto(symbol.span),
        fingerprint=symbol.fingerprint,
        fingerprint_algorithm=symbol.fingerprint_algorithm,
        revision=revision_dto(revision),
    )


def symbol_location_dto(graph: ProvenanceGraph, symbol: CodeSymbol) -> SymbolLocationDTO:
    return SymbolLocationDTO(
        symbol_id=symbol.id,
        qualified_name=symbol.qualified_name,
        file_path=symbol.file_path,
        kind=symbol.kind,
        span=_span_dto(symbol.span),
        revision_sequence=graph.get(WorkspaceRevision, symbol.revision_id).sequence,
    )


def _optional_location(
    graph: ProvenanceGraph, symbol: CodeSymbol | None
) -> SymbolLocationDTO | None:
    return None if symbol is None else symbol_location_dto(graph, symbol)


def _trace_file_issue(trace: SymbolTrace) -> FileIssueKind | None:
    """The issue that kept the last seen file from being parsed (``file_not_parsed`` only)."""
    evaluated = trace.evaluated_revision
    if trace.reason is not FreshnessReason.FILE_NOT_PARSED or evaluated is None:
        return None
    issue = evaluated.issue_for(trace.last_seen.file_path)
    return None if issue is None else issue.kind


def link_health_dto(graph: ProvenanceGraph, health: LinkHealth) -> LinkHealthDTO:
    trace = health.trace
    return LinkHealthDTO(
        link_id=health.link.id,
        decision_id=health.decision.id,
        decision_title=health.decision.title,
        freshness=trace.freshness,
        freshness_reason=trace.reason,
        linked_symbol=symbol_location_dto(graph, trace.origin),
        current_symbol=_optional_location(graph, trace.current),
        created_at=health.link.created_at,
    )


def symbol_summary_dto(summary: SymbolSummary) -> SymbolSummaryDTO:
    symbol = summary.symbol
    return SymbolSummaryDTO(
        id=symbol.id,
        qualified_name=symbol.qualified_name,
        file_path=symbol.file_path,
        kind=symbol.kind,
        language=symbol.language,
        decision_count=summary.decision_count,
        worst_freshness=summary.worst_freshness,
    )


def symbol_list_response(graph: ProvenanceGraph) -> SymbolListResponse:
    revision = graph.latest_revision()
    return SymbolListResponse(
        project=project_summary_dto(graph.project, graph.revision),
        revision=None if revision is None else revision_dto(revision),
        items=[symbol_summary_dto(item) for item in list_symbols(graph)],
        file_issues=(
            []
            if revision is None
            else [
                FileIssueDTO(file_path=item.file_path, kind=item.kind)
                for item in revision.file_issues
            ]
        ),
        links=[link_health_dto(graph, item) for item in link_health(graph)],
    )


def _supersession_dto(notice: SupersessionNotice) -> SupersessionDTO:
    return SupersessionDTO(
        dimension=notice.dimension,
        superseding_version_id=notice.superseding_version_id,
        reason=notice.reason,
        recorded_at=notice.recorded_at,
    )


def _check_dto(check: ClaimCheck) -> ClaimCheckDTO:
    return ClaimCheckDTO(
        sequence=check.sequence,
        outcome=check.outcome,
        method=check.method,
        checked_at=check.checked_at,
        detail=check.detail,
    )


def _evidence_dto(view: EvidenceView) -> EvidenceItemDTO:
    claim = view.claim
    source = view.source
    version = view.version
    return EvidenceItemDTO(
        link_id=view.link.id,
        stance=view.link.stance,
        asserted_by=view.link.asserted_by,
        note=view.link.note,
        counts_as_support=view.counts_as_support,
        claim=ClaimDTO(
            id=claim.id,
            quote=claim.quote,
            locator=[
                LocatorPartDTO(kind=part.kind, value=part.value) for part in claim.locator.parts
            ],
            statement=claim.statement,
            extracted_by=claim.extracted_by,
            state=view.claim_state,
            last_check=None if view.last_check is None else _check_dto(view.last_check),
        ),
        source=SourceRefDTO(
            id=source.id,
            title=source.title,
            persistent_id=PersistentIdDTO(
                scheme=source.persistent_id.scheme, value=source.persistent_id.value
            ),
            is_synthetic=source.is_synthetic,
        ),
        version=SourceVersionDTO(
            id=version.id,
            version_label=version.version_label,
            authority=version.authority,
            authority_letter=version.authority.letter,
            access_class=version.access_class,
            access_conditions=version.access_conditions,
            authority_basis=version.authority_basis,
            content_sha256=version.content_sha256,
            retrieved_at=version.retrieved_at,
            published_on=version.published_on,
            scientific_currency=view.scientific_currency,
            technical_currency=view.technical_currency,
            superseded_by=[_supersession_dto(item) for item in view.superseded_by],
        ),
    )


def _test_dto(graph: ProvenanceGraph, view: TestView) -> TestStatusDTO:
    latest: TestRunRefDTO | None = None
    if view.latest_run is not None and view.latest_result is not None:
        run = view.latest_run
        latest = TestRunRefDTO(
            run_id=run.id,
            origin=run.origin,
            outcome=view.latest_result.outcome,
            finished_at=run.finished_at,
            revision_sequence=graph.get(WorkspaceRevision, run.revision_id).sequence,
            environment_id=run.environment_id,
            is_latest_revision=bool(view.is_latest_revision),
        )
    case = view.test_case
    return TestStatusDTO(
        id=case.id,
        node_id=case.node_id,
        kind=case.kind,
        description=case.description,
        latest=latest,
    )


def _review_dto(approval: Approval, current_id: str | None) -> ReviewDTO:
    return ReviewDTO(
        id=approval.id,
        sequence=approval.sequence,
        verdict=approval.verdict,
        reviewer=approval.reviewer,
        rationale=approval.rationale,
        conflict_resolution=approval.conflict_resolution,
        reviewed_at=approval.reviewed_at,
        is_current=approval.id == current_id,
    )


def _implementation_dto(graph: ProvenanceGraph, view: DecisionView) -> ImplementationDTO:
    trace = view.trace
    lost = trace.lost_in_revision
    return ImplementationDTO(
        link_id=view.implementation_link.id,
        freshness=view.freshness,
        created_at=view.implementation_link.created_at,
        freshness_reason=trace.reason,
        linked_symbol=symbol_location_dto(graph, trace.origin),
        current_symbol=_optional_location(graph, trace.current),
        last_seen_symbol=symbol_location_dto(graph, trace.last_seen),
        lost_in_revision_sequence=None if lost is None else lost.sequence,
        candidates=[symbol_location_dto(graph, item) for item in trace.candidates],
        file_issue=_trace_file_issue(trace),
    )


def _decision_dto(graph: ProvenanceGraph, view: DecisionView) -> DecisionViewDTO:
    decision = view.decision
    report = view.status
    return DecisionViewDTO(
        id=decision.id,
        title=decision.title,
        statement=decision.statement,
        rationale=decision.rationale,
        alternatives=[
            AlternativeDTO(
                label=item.label,
                description=item.description,
                reason_not_chosen=item.reason_not_chosen,
            )
            for item in decision.alternatives
        ],
        assumptions=[
            AssumptionDTO(statement=item.statement, justification=item.justification)
            for item in decision.assumptions
        ],
        access_floor=decision.access_floor,
        effective_access_class=report.effective_access_class,
        status=report.status,
        evidential_status=report.evidential_status,
        status_reasons=list(report.reasons),
        approval_stale=report.approval_stale,
        supersedes=decision.supersedes_id,
        superseded_by=report.superseded_by,
        implementation=_implementation_dto(graph, view),
        evidence=[_evidence_dto(item) for item in view.evidence],
        tests=[_test_dto(graph, item) for item in view.tests],
        reviews=[_review_dto(item, report.current_approval_id) for item in view.approvals],
        warnings=list(view.warnings),
    )


def function_inspection_response(
    graph: ProvenanceGraph, inspection: FunctionInspection
) -> FunctionInspectionResponse:
    project = inspection.project
    return FunctionInspectionResponse(
        project=project_summary_dto(project, inspection.project_revision),
        disclaimer=SYNTHETIC_NOTICE if project.is_synthetic else None,
        policy_note=POLICY_NOTE,
        review_note=REVIEW_NOTE,
        symbol=code_symbol_dto(inspection.symbol, inspection.revision),
        decisions=[_decision_dto(graph, item) for item in inspection.decisions],
        direct_tests=[_test_dto(graph, item) for item in inspection.direct_tests],
        warnings=list(inspection.warnings),
        file_issue=None if inspection.file_issue is None else inspection.file_issue.kind,
    )
