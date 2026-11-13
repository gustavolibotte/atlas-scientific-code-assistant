"""Mapping between domain provenance records and database rows.

Loading always goes through the domain constructors, so every record (``R.*``) and
graph state (``G.*``) rule runs again on the stored data.
"""

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, assert_never

from asca.domain.provenance import (
    RECORD_FIELDS,
    Alternative,
    Approval,
    ApprovalId,
    Assumption,
    Claim,
    ClaimCheck,
    ClaimCheckId,
    ClaimId,
    CodeSymbol,
    DecisionId,
    EnvironmentId,
    EnvironmentSnapshot,
    EvidenceLink,
    EvidenceLinkId,
    FileIssue,
    FileIssueKind,
    ImplementationLink,
    ImplementationLinkId,
    Locator,
    LocatorKind,
    LocatorPart,
    PackagePin,
    PersistentIdentifier,
    Project,
    ProjectId,
    ProvenanceGraph,
    ProvenanceRecord,
    RevisionId,
    RunId,
    ScientificDecision,
    Source,
    SourceId,
    SourceSpan,
    SourceVersion,
    SourceVersionId,
    SupersessionId,
    SupersessionNotice,
    SymbolId,
    TestCase,
    TestCaseId,
    TestResult,
    ValidationRun,
    VerificationLink,
    VerificationLinkId,
    WorkspaceRevision,
)
from asca.infrastructure.persistence.orm import (
    ApprovalRow,
    Base,
    ClaimCheckRow,
    ClaimRow,
    CodeSymbolRow,
    DecisionRow,
    EnvironmentSnapshotRow,
    EvidenceLinkRow,
    ImplementationLinkRow,
    ProjectRow,
    SourceRow,
    SourceVersionRow,
    SupersessionNoticeRow,
    TestCaseRow,
    ValidationResultRow,
    ValidationRunRow,
    VerificationLinkRow,
    WorkspaceRevisionRow,
)

#: Every record kind, from the domain registry. Insert order across tables comes from
#: ``orm.RECORD_ROW_TYPES``; within a table, batch order is kept.
_RECORD_KINDS: tuple[type[object], ...] = tuple(RECORD_FIELDS)


@dataclass(frozen=True, slots=True)
class LoadedRows:
    """All record rows of one project, one tuple per table."""

    sources: tuple[SourceRow, ...] = ()
    versions: tuple[SourceVersionRow, ...] = ()
    supersessions: tuple[SupersessionNoticeRow, ...] = ()
    claims: tuple[ClaimRow, ...] = ()
    checks: tuple[ClaimCheckRow, ...] = ()
    decisions: tuple[DecisionRow, ...] = ()
    evidence_links: tuple[EvidenceLinkRow, ...] = ()
    revisions: tuple[WorkspaceRevisionRow, ...] = ()
    symbols: tuple[CodeSymbolRow, ...] = ()
    implementation_links: tuple[ImplementationLinkRow, ...] = ()
    test_cases: tuple[TestCaseRow, ...] = ()
    verification_links: tuple[VerificationLinkRow, ...] = ()
    environments: tuple[EnvironmentSnapshotRow, ...] = ()
    runs: tuple[ValidationRunRow, ...] = ()
    results: tuple[ValidationResultRow, ...] = ()
    approvals: tuple[ApprovalRow, ...] = ()


#: ``LoadedRows`` field for each row type.
ROW_FIELDS: dict[type[Base], str] = {
    SourceRow: "sources",
    SourceVersionRow: "versions",
    SupersessionNoticeRow: "supersessions",
    ClaimRow: "claims",
    ClaimCheckRow: "checks",
    DecisionRow: "decisions",
    EvidenceLinkRow: "evidence_links",
    WorkspaceRevisionRow: "revisions",
    CodeSymbolRow: "symbols",
    ImplementationLinkRow: "implementation_links",
    TestCaseRow: "test_cases",
    VerificationLinkRow: "verification_links",
    EnvironmentSnapshotRow: "environments",
    ValidationRunRow: "runs",
    ValidationResultRow: "results",
    ApprovalRow: "approvals",
}


# ---------------------------------------------------------------------- records to rows


def project_to_row(project: Project) -> ProjectRow:
    return ProjectRow(
        id=project.id,
        title=project.title,
        is_synthetic=project.is_synthetic,
        created_at=project.created_at,
        revision=0,
    )


def record_to_rows(record: ProvenanceRecord, added_in_revision: int) -> list[Base]:
    """Rows for one record; a validation run yields its run row and one row per result."""
    if not isinstance(record, _RECORD_KINDS):
        raise TypeError("not a provenance record")
    common: dict[str, Any] = {
        "project_id": record.project_id,
        "added_in_revision": added_in_revision,
    }
    match record:
        case Source():
            return [
                SourceRow(
                    id=record.id,
                    title=record.title,
                    pid_scheme=record.persistent_id.scheme,
                    pid_value=record.persistent_id.value,
                    created_at=record.created_at,
                    **common,
                )
            ]
        case SourceVersion():
            return [
                SourceVersionRow(
                    id=record.id,
                    source_id=record.source_id,
                    version_label=record.version_label,
                    authority=record.authority,
                    access_class=record.access_class,
                    access_conditions=record.access_conditions,
                    authority_basis=record.authority_basis,
                    content_sha256=record.content_sha256,
                    retrieved_at=record.retrieved_at,
                    published_on=record.published_on,
                    recorded_at=record.recorded_at,
                    **common,
                )
            ]
        case SupersessionNotice():
            return [
                SupersessionNoticeRow(
                    id=record.id,
                    superseded_version_id=record.superseded_version_id,
                    superseding_version_id=record.superseding_version_id,
                    dimension=record.dimension,
                    reason=record.reason,
                    recorded_at=record.recorded_at,
                    **common,
                )
            ]
        case Claim():
            return [
                ClaimRow(
                    id=record.id,
                    source_version_id=record.source_version_id,
                    quote=record.quote,
                    locator=[
                        {"kind": part.kind.value, "value": part.value}
                        for part in record.locator.parts
                    ],
                    statement=record.statement,
                    extracted_by=record.extracted_by,
                    recorded_at=record.recorded_at,
                    **common,
                )
            ]
        case ClaimCheck():
            return [
                ClaimCheckRow(
                    id=record.id,
                    claim_id=record.claim_id,
                    sequence=record.sequence,
                    outcome=record.outcome,
                    method=record.method,
                    content_sha256=record.content_sha256,
                    detail=record.detail,
                    checked_at=record.checked_at,
                    **common,
                )
            ]
        case ScientificDecision():
            return [
                DecisionRow(
                    id=record.id,
                    title=record.title,
                    statement=record.statement,
                    rationale=record.rationale,
                    alternatives=[
                        {
                            "label": item.label,
                            "description": item.description,
                            "reason_not_chosen": item.reason_not_chosen,
                        }
                        for item in record.alternatives
                    ],
                    assumptions=[
                        {"statement": item.statement, "justification": item.justification}
                        for item in record.assumptions
                    ],
                    access_floor=record.access_floor,
                    supersedes_id=record.supersedes_id,
                    created_at=record.created_at,
                    **common,
                )
            ]
        case EvidenceLink():
            return [
                EvidenceLinkRow(
                    id=record.id,
                    decision_id=record.decision_id,
                    claim_id=record.claim_id,
                    stance=record.stance,
                    asserted_by=record.asserted_by,
                    note=record.note,
                    created_at=record.created_at,
                    **common,
                )
            ]
        case WorkspaceRevision():
            return [
                WorkspaceRevisionRow(
                    id=record.id,
                    sequence=record.sequence,
                    vcs_ref=record.vcs_ref,
                    symbols_indexed=record.symbols_indexed,
                    recorded_at=record.recorded_at,
                    source_digest=record.source_digest,
                    file_issues=[
                        {"file_path": item.file_path, "kind": item.kind.value}
                        for item in record.file_issues
                    ],
                    **common,
                )
            ]
        case CodeSymbol():
            return [
                CodeSymbolRow(
                    id=record.id,
                    revision_id=record.revision_id,
                    language=record.language,
                    kind=record.kind,
                    qualified_name=record.qualified_name,
                    file_path=record.file_path,
                    span_start=None if record.span is None else record.span.start_line,
                    span_end=None if record.span is None else record.span.end_line,
                    fingerprint=record.fingerprint,
                    fingerprint_algorithm=record.fingerprint_algorithm,
                    **common,
                )
            ]
        case ImplementationLink():
            return [
                ImplementationLinkRow(
                    id=record.id,
                    decision_id=record.decision_id,
                    symbol_id=record.symbol_id,
                    created_at=record.created_at,
                    **common,
                )
            ]
        case TestCase():
            return [
                TestCaseRow(
                    id=record.id,
                    node_id=record.node_id,
                    kind=record.kind,
                    description=record.description,
                    created_at=record.created_at,
                    **common,
                )
            ]
        case VerificationLink():
            return [
                VerificationLinkRow(
                    id=record.id,
                    test_case_id=record.test_case_id,
                    decision_id=record.decision_id,
                    symbol_id=record.symbol_id,
                    created_at=record.created_at,
                    **common,
                )
            ]
        case EnvironmentSnapshot():
            return [
                EnvironmentSnapshotRow(
                    id=record.id,
                    python_version=record.python_version,
                    implementation=record.implementation,
                    platform=record.platform,
                    packages=[
                        {"name": pin.name, "version": pin.version} for pin in record.packages
                    ],
                    **common,
                )
            ]
        case ValidationRun():
            run: list[Base] = [
                ValidationRunRow(
                    id=record.id,
                    revision_id=record.revision_id,
                    environment_id=record.environment_id,
                    origin=record.origin,
                    started_at=record.started_at,
                    finished_at=record.finished_at,
                    **common,
                )
            ]
            run.extend(
                ValidationResultRow(
                    run_id=record.id,
                    test_case_id=result.test_case_id,
                    outcome=result.outcome,
                    duration_seconds=result.duration_seconds,
                    message=result.message,
                    **common,
                )
                for result in record.results
            )
            return run
        case Approval():
            return [
                ApprovalRow(
                    id=record.id,
                    decision_id=record.decision_id,
                    sequence=record.sequence,
                    verdict=record.verdict,
                    reviewer=record.reviewer,
                    rationale=record.rationale,
                    conflict_resolution=record.conflict_resolution,
                    support_fingerprint=record.support_fingerprint,
                    reviewed_at=record.reviewed_at,
                    **common,
                )
            ]
    assert_never(record)


# ---------------------------------------------------------------------- rows to records


def row_to_project(row: ProjectRow) -> Project:
    return Project(
        id=ProjectId(row.id),
        title=row.title,
        is_synthetic=row.is_synthetic,
        created_at=row.created_at,
    )


def _locator(parts: Any) -> Locator:
    if not isinstance(parts, list):
        raise TypeError("locator must be a list")
    return Locator(tuple(LocatorPart(LocatorKind(part["kind"]), part["value"]) for part in parts))


def _alternatives(items: Any) -> tuple[Alternative, ...]:
    if not isinstance(items, list):
        raise TypeError("alternatives must be a list")
    return tuple(
        Alternative(item["label"], item["description"], item["reason_not_chosen"]) for item in items
    )


def _assumptions(items: Any) -> tuple[Assumption, ...]:
    if not isinstance(items, list):
        raise TypeError("assumptions must be a list")
    return tuple(Assumption(item["statement"], item["justification"]) for item in items)


def _packages(items: Any) -> tuple[PackagePin, ...]:
    if not isinstance(items, list):
        raise TypeError("packages must be a list")
    return tuple(PackagePin(item["name"], item["version"]) for item in items)


_FILE_ISSUE_KEYS = frozenset({"file_path", "kind"})


def _file_issues(items: Any) -> tuple[FileIssue, ...]:
    """Stored file issues; anything but ``[{"file_path": str, "kind": str}, ...]`` fails."""
    if not isinstance(items, list):
        raise TypeError("file_issues must be a list")
    issues: list[FileIssue] = []
    for item in items:
        if not isinstance(item, dict) or item.keys() != _FILE_ISSUE_KEYS:
            raise TypeError("a file issue must have exactly file_path and kind")
        file_path, kind = item["file_path"], item["kind"]
        if not isinstance(file_path, str) or not isinstance(kind, str):
            raise TypeError("file issue fields must be strings")
        issues.append(FileIssue(file_path, FileIssueKind(kind)))
    return tuple(issues)


def _span(start: int | None, end: int | None) -> SourceSpan | None:
    if start is None and end is None:
        return None
    return SourceSpan(start, end)  # type: ignore[arg-type]


def _results(rows: tuple[ValidationResultRow, ...]) -> dict[str, list[TestResult]]:
    grouped: dict[str, list[TestResult]] = defaultdict(list)
    for row in rows:
        grouped[row.run_id].append(
            TestResult(
                test_case_id=TestCaseId(row.test_case_id),
                outcome=row.outcome,
                duration_seconds=row.duration_seconds,
                message=row.message,
            )
        )
    return grouped


def rows_to_graph(project_row: ProjectRow, rows: LoadedRows) -> ProvenanceGraph:
    """Rebuild a project graph at the stored revision through the domain constructors."""
    project = row_to_project(project_row)
    results = _results(rows.results)
    if not set(results) <= {row.id for row in rows.runs}:
        raise KeyError("validation result of a run outside the project")
    return ProvenanceGraph(
        project=project,
        revision=project_row.revision,
        sources=tuple(
            Source(
                id=SourceId(row.id),
                project_id=ProjectId(row.project_id),
                title=row.title,
                persistent_id=PersistentIdentifier(row.pid_scheme, row.pid_value),
                created_at=row.created_at,
            )
            for row in rows.sources
        ),
        versions=tuple(
            SourceVersion(
                id=SourceVersionId(row.id),
                project_id=ProjectId(row.project_id),
                source_id=SourceId(row.source_id),
                version_label=row.version_label,
                authority=row.authority,
                access_class=row.access_class,
                access_conditions=row.access_conditions,
                authority_basis=row.authority_basis,
                content_sha256=row.content_sha256,
                retrieved_at=row.retrieved_at,
                published_on=row.published_on,
                recorded_at=row.recorded_at,
            )
            for row in rows.versions
        ),
        supersessions=tuple(
            SupersessionNotice(
                id=SupersessionId(row.id),
                project_id=ProjectId(row.project_id),
                superseded_version_id=SourceVersionId(row.superseded_version_id),
                superseding_version_id=(
                    None
                    if row.superseding_version_id is None
                    else SourceVersionId(row.superseding_version_id)
                ),
                dimension=row.dimension,
                reason=row.reason,
                recorded_at=row.recorded_at,
            )
            for row in rows.supersessions
        ),
        claims=tuple(
            Claim(
                id=ClaimId(row.id),
                project_id=ProjectId(row.project_id),
                source_version_id=SourceVersionId(row.source_version_id),
                quote=row.quote,
                locator=_locator(row.locator),
                statement=row.statement,
                extracted_by=row.extracted_by,
                recorded_at=row.recorded_at,
            )
            for row in rows.claims
        ),
        checks=tuple(
            ClaimCheck(
                id=ClaimCheckId(row.id),
                project_id=ProjectId(row.project_id),
                claim_id=ClaimId(row.claim_id),
                sequence=row.sequence,
                outcome=row.outcome,
                method=row.method,
                content_sha256=row.content_sha256,
                detail=row.detail,
                checked_at=row.checked_at,
            )
            for row in rows.checks
        ),
        decisions=tuple(
            ScientificDecision(
                id=DecisionId(row.id),
                project_id=ProjectId(row.project_id),
                title=row.title,
                statement=row.statement,
                rationale=row.rationale,
                alternatives=_alternatives(row.alternatives),
                assumptions=_assumptions(row.assumptions),
                access_floor=row.access_floor,
                supersedes_id=None if row.supersedes_id is None else DecisionId(row.supersedes_id),
                created_at=row.created_at,
            )
            for row in rows.decisions
        ),
        evidence_links=tuple(
            EvidenceLink(
                id=EvidenceLinkId(row.id),
                project_id=ProjectId(row.project_id),
                decision_id=DecisionId(row.decision_id),
                claim_id=ClaimId(row.claim_id),
                stance=row.stance,
                asserted_by=row.asserted_by,
                note=row.note,
                created_at=row.created_at,
            )
            for row in rows.evidence_links
        ),
        revisions=tuple(
            WorkspaceRevision(
                id=RevisionId(row.id),
                project_id=ProjectId(row.project_id),
                sequence=row.sequence,
                vcs_ref=row.vcs_ref,
                symbols_indexed=row.symbols_indexed,
                recorded_at=row.recorded_at,
                file_issues=_file_issues(row.file_issues),
                source_digest=row.source_digest,
            )
            for row in rows.revisions
        ),
        symbols=tuple(
            CodeSymbol(
                id=SymbolId(row.id),
                project_id=ProjectId(row.project_id),
                revision_id=RevisionId(row.revision_id),
                language=row.language,
                kind=row.kind,
                qualified_name=row.qualified_name,
                file_path=row.file_path,
                span=_span(row.span_start, row.span_end),
                fingerprint=row.fingerprint,
                fingerprint_algorithm=row.fingerprint_algorithm,
            )
            for row in rows.symbols
        ),
        implementation_links=tuple(
            ImplementationLink(
                id=ImplementationLinkId(row.id),
                project_id=ProjectId(row.project_id),
                decision_id=DecisionId(row.decision_id),
                symbol_id=SymbolId(row.symbol_id),
                created_at=row.created_at,
            )
            for row in rows.implementation_links
        ),
        test_cases=tuple(
            TestCase(
                id=TestCaseId(row.id),
                project_id=ProjectId(row.project_id),
                node_id=row.node_id,
                kind=row.kind,
                description=row.description,
                created_at=row.created_at,
            )
            for row in rows.test_cases
        ),
        verification_links=tuple(
            VerificationLink(
                id=VerificationLinkId(row.id),
                project_id=ProjectId(row.project_id),
                test_case_id=TestCaseId(row.test_case_id),
                decision_id=None if row.decision_id is None else DecisionId(row.decision_id),
                symbol_id=None if row.symbol_id is None else SymbolId(row.symbol_id),
                created_at=row.created_at,
            )
            for row in rows.verification_links
        ),
        environments=tuple(
            EnvironmentSnapshot(
                id=EnvironmentId(row.id),
                project_id=ProjectId(row.project_id),
                python_version=row.python_version,
                implementation=row.implementation,
                platform=row.platform,
                packages=_packages(row.packages),
            )
            for row in rows.environments
        ),
        runs=tuple(
            ValidationRun(
                id=RunId(row.id),
                project_id=ProjectId(row.project_id),
                revision_id=RevisionId(row.revision_id),
                environment_id=EnvironmentId(row.environment_id),
                origin=row.origin,
                started_at=row.started_at,
                finished_at=row.finished_at,
                results=tuple(results.get(row.id, ())),
            )
            for row in rows.runs
        ),
        approvals=tuple(
            Approval(
                id=ApprovalId(row.id),
                project_id=ProjectId(row.project_id),
                decision_id=DecisionId(row.decision_id),
                sequence=row.sequence,
                verdict=row.verdict,
                reviewer=row.reviewer,
                rationale=row.rationale,
                conflict_resolution=row.conflict_resolution,
                support_fingerprint=row.support_fingerprint,
                reviewed_at=row.reviewed_at,
            )
            for row in rows.approvals
        ),
    )
