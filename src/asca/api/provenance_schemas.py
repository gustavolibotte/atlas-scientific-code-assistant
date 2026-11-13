"""Transport models of the read-only provenance inspection API.

Built explicitly by ``asca.api.presenters``; enum fields reuse the domain StrEnums.
"""

from datetime import date, datetime

from asca.api.schemas import StrictModel
from asca.application.inspection import InspectionWarning
from asca.domain.provenance import (
    AccessClass,
    ApprovalVerdict,
    AssertionOrigin,
    CheckMethod,
    ClaimCheckOutcome,
    ClaimVerificationState,
    Currency,
    DecisionStatus,
    FileIssueKind,
    FingerprintAlgorithm,
    FreshnessReason,
    Language,
    LinkFreshness,
    LocatorKind,
    PidScheme,
    RunOrigin,
    SourceAuthority,
    Stance,
    StatusReason,
    SupersessionDimension,
    SymbolKind,
    TestKind,
    TestOutcome,
)


class ProjectSummaryDTO(StrictModel):
    id: str
    title: str
    is_synthetic: bool
    revision: int
    created_at: datetime


class ProjectListResponse(StrictModel):
    items: list[ProjectSummaryDTO]


class RevisionDTO(StrictModel):
    id: str
    sequence: int
    vcs_ref: str | None
    symbols_indexed: bool
    source_digest: str | None
    file_issue_count: int


class SpanDTO(StrictModel):
    start_line: int
    end_line: int


class CodeSymbolDTO(StrictModel):
    id: str
    qualified_name: str
    file_path: str
    kind: SymbolKind
    language: Language
    span: SpanDTO | None
    fingerprint: str | None
    fingerprint_algorithm: FingerprintAlgorithm | None
    revision: RevisionDTO


class SymbolSummaryDTO(StrictModel):
    id: str
    qualified_name: str
    file_path: str
    kind: SymbolKind
    language: Language
    decision_count: int
    worst_freshness: LinkFreshness | None


class FileIssueDTO(StrictModel):
    file_path: str
    kind: FileIssueKind


class SymbolLocationDTO(StrictModel):
    symbol_id: str
    qualified_name: str
    file_path: str
    kind: SymbolKind
    span: SpanDTO | None
    revision_sequence: int


class LinkHealthDTO(StrictModel):
    link_id: str
    decision_id: str
    decision_title: str
    freshness: LinkFreshness
    freshness_reason: FreshnessReason
    linked_symbol: SymbolLocationDTO
    current_symbol: SymbolLocationDTO | None
    created_at: datetime


class SymbolListResponse(StrictModel):
    project: ProjectSummaryDTO
    revision: RevisionDTO | None
    items: list[SymbolSummaryDTO]
    file_issues: list[FileIssueDTO]
    links: list[LinkHealthDTO]


class LocatorPartDTO(StrictModel):
    kind: LocatorKind
    value: str


class PersistentIdDTO(StrictModel):
    scheme: PidScheme
    value: str


class SourceRefDTO(StrictModel):
    id: str
    title: str
    persistent_id: PersistentIdDTO
    is_synthetic: bool


class SupersessionDTO(StrictModel):
    dimension: SupersessionDimension
    superseding_version_id: str | None
    reason: str
    recorded_at: datetime


class SourceVersionDTO(StrictModel):
    id: str
    version_label: str
    authority: SourceAuthority
    authority_letter: str
    access_class: AccessClass
    access_conditions: str | None
    authority_basis: str | None
    content_sha256: str | None
    retrieved_at: datetime | None
    published_on: date | None
    scientific_currency: Currency
    technical_currency: Currency
    superseded_by: list[SupersessionDTO]


class ClaimCheckDTO(StrictModel):
    sequence: int
    outcome: ClaimCheckOutcome
    method: CheckMethod
    checked_at: datetime
    detail: str | None


class ClaimDTO(StrictModel):
    id: str
    quote: str
    locator: list[LocatorPartDTO]
    statement: str | None
    extracted_by: AssertionOrigin
    state: ClaimVerificationState
    last_check: ClaimCheckDTO | None


class EvidenceItemDTO(StrictModel):
    link_id: str
    stance: Stance
    asserted_by: AssertionOrigin
    note: str | None
    counts_as_support: bool
    claim: ClaimDTO
    source: SourceRefDTO
    version: SourceVersionDTO


class AlternativeDTO(StrictModel):
    label: str
    description: str
    reason_not_chosen: str


class AssumptionDTO(StrictModel):
    statement: str
    justification: str | None


class ImplementationDTO(StrictModel):
    link_id: str
    freshness: LinkFreshness
    created_at: datetime
    freshness_reason: FreshnessReason
    linked_symbol: SymbolLocationDTO
    current_symbol: SymbolLocationDTO | None
    last_seen_symbol: SymbolLocationDTO
    lost_in_revision_sequence: int | None
    candidates: list[SymbolLocationDTO]
    file_issue: FileIssueKind | None


class TestRunRefDTO(StrictModel):
    __test__ = False

    run_id: str
    origin: RunOrigin
    outcome: TestOutcome
    finished_at: datetime
    revision_sequence: int
    environment_id: str
    is_latest_revision: bool


class TestStatusDTO(StrictModel):
    __test__ = False

    id: str
    node_id: str
    kind: TestKind
    description: str
    latest: TestRunRefDTO | None


class ReviewDTO(StrictModel):
    id: str
    sequence: int
    verdict: ApprovalVerdict
    reviewer: str
    rationale: str
    conflict_resolution: str | None
    reviewed_at: datetime
    is_current: bool


class DecisionViewDTO(StrictModel):
    id: str
    title: str
    statement: str
    rationale: str
    alternatives: list[AlternativeDTO]
    assumptions: list[AssumptionDTO]
    access_floor: AccessClass
    effective_access_class: AccessClass
    status: DecisionStatus
    evidential_status: DecisionStatus
    status_reasons: list[StatusReason]
    approval_stale: bool
    supersedes: str | None
    superseded_by: str | None
    implementation: ImplementationDTO
    evidence: list[EvidenceItemDTO]
    tests: list[TestStatusDTO]
    reviews: list[ReviewDTO]
    warnings: list[InspectionWarning]


class FunctionInspectionResponse(StrictModel):
    project: ProjectSummaryDTO
    disclaimer: str | None
    policy_note: str
    review_note: str
    symbol: CodeSymbolDTO
    decisions: list[DecisionViewDTO]
    direct_tests: list[TestStatusDTO]
    warnings: list[InspectionWarning]
    file_issue: FileIssueKind | None
