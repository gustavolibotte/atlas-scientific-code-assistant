"""Scientific decisions, evidence links, recorded reviews and status vocabulary."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from asca.domain.provenance.claims import AssertionOrigin
from asca.domain.provenance.errors import ProvenanceInvariantError
from asca.domain.provenance.ids import (
    ApprovalId,
    ClaimId,
    DecisionId,
    EvidenceLinkId,
    IdKind,
    ProjectId,
    optional_id,
    require_id,
)
from asca.domain.provenance.values import (
    LONG_MAX,
    SHORT_MAX,
    STATEMENT_MAX,
    TITLE_MAX,
    AccessClass,
    optional_text,
    require_enum,
    require_int,
    require_sha256,
    require_text,
    require_utc,
)

ALTERNATIVES_MAX = 20
ASSUMPTIONS_MAX = 50


class Stance(StrEnum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    CONTEXT = "context"


COUNTED_STANCES = frozenset({Stance.SUPPORTS, Stance.CONTRADICTS})


@dataclass(frozen=True, slots=True)
class Alternative:
    label: str
    description: str
    reason_not_chosen: str

    def __post_init__(self) -> None:
        require_text("alternative.label", self.label, max_len=SHORT_MAX)
        require_text(
            "alternative.description", self.description, max_len=STATEMENT_MAX, multiline=True
        )
        require_text(
            "alternative.reason_not_chosen",
            self.reason_not_chosen,
            max_len=STATEMENT_MAX,
            multiline=True,
        )


@dataclass(frozen=True, slots=True)
class Assumption:
    statement: str
    justification: str | None

    def __post_init__(self) -> None:
        require_text("assumption.statement", self.statement, max_len=STATEMENT_MAX, multiline=True)
        optional_text(
            "assumption.justification", self.justification, max_len=STATEMENT_MAX, multiline=True
        )


@dataclass(frozen=True, slots=True)
class ScientificDecision:
    id: DecisionId
    project_id: ProjectId
    title: str
    statement: str
    rationale: str
    alternatives: tuple[Alternative, ...]
    assumptions: tuple[Assumption, ...]
    access_floor: AccessClass
    supersedes_id: DecisionId | None
    created_at: datetime

    def __post_init__(self) -> None:
        require_id(IdKind.DECISION, self.id, "decision.id")
        require_id(IdKind.PROJECT, self.project_id, "decision.project_id")
        require_text("decision.title", self.title, max_len=TITLE_MAX)
        require_text("decision.statement", self.statement, max_len=STATEMENT_MAX, multiline=True)
        require_text("decision.rationale", self.rationale, max_len=LONG_MAX, multiline=True)
        if (
            not isinstance(self.alternatives, tuple)
            or not all(isinstance(item, Alternative) for item in self.alternatives)
            or len(self.alternatives) > ALTERNATIVES_MAX
            or len({item.label.casefold() for item in self.alternatives}) != len(self.alternatives)
        ):
            raise ProvenanceInvariantError(
                "R.decision.alternatives",
                f"at most {ALTERNATIVES_MAX} alternatives with unique labels",
            )
        if (
            not isinstance(self.assumptions, tuple)
            or not all(isinstance(item, Assumption) for item in self.assumptions)
            or len(self.assumptions) > ASSUMPTIONS_MAX
            or len({item.statement for item in self.assumptions}) != len(self.assumptions)
        ):
            raise ProvenanceInvariantError(
                "R.decision.assumptions",
                f"at most {ASSUMPTIONS_MAX} assumptions with unique statements",
            )
        require_enum(AccessClass, "decision.access_floor", self.access_floor)
        optional_id(IdKind.DECISION, self.supersedes_id, "decision.supersedes_id")
        if self.supersedes_id == self.id:
            raise ProvenanceInvariantError(
                "R.decision.supersedes_self", "a decision cannot supersede itself"
            )
        require_utc("decision.created_at", self.created_at)


@dataclass(frozen=True, slots=True)
class EvidenceLink:
    id: EvidenceLinkId
    project_id: ProjectId
    decision_id: DecisionId
    claim_id: ClaimId
    stance: Stance
    asserted_by: AssertionOrigin
    note: str | None
    created_at: datetime

    def __post_init__(self) -> None:
        require_id(IdKind.EVIDENCE_LINK, self.id, "evidence_link.id")
        require_id(IdKind.PROJECT, self.project_id, "evidence_link.project_id")
        require_id(IdKind.DECISION, self.decision_id, "evidence_link.decision_id")
        require_id(IdKind.CLAIM, self.claim_id, "evidence_link.claim_id")
        require_enum(Stance, "evidence_link.stance", self.stance)
        require_enum(AssertionOrigin, "evidence_link.asserted_by", self.asserted_by)
        optional_text("evidence_link.note", self.note, max_len=STATEMENT_MAX, multiline=True)
        require_utc("evidence_link.created_at", self.created_at)


class ApprovalVerdict(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class Approval:
    """A review recorded inside ASCA; not an ATLAS collaboration approval."""

    id: ApprovalId
    project_id: ProjectId
    decision_id: DecisionId
    sequence: int
    verdict: ApprovalVerdict
    reviewer: str
    rationale: str
    conflict_resolution: str | None
    support_fingerprint: str
    reviewed_at: datetime

    def __post_init__(self) -> None:
        require_id(IdKind.APPROVAL, self.id, "approval.id")
        require_id(IdKind.PROJECT, self.project_id, "approval.project_id")
        require_id(IdKind.DECISION, self.decision_id, "approval.decision_id")
        require_int("approval.sequence", self.sequence, minimum=1)
        require_enum(ApprovalVerdict, "approval.verdict", self.verdict)
        require_text("approval.reviewer", self.reviewer, max_len=SHORT_MAX)
        require_text("approval.rationale", self.rationale, max_len=LONG_MAX, multiline=True)
        optional_text(
            "approval.conflict_resolution",
            self.conflict_resolution,
            max_len=LONG_MAX,
            multiline=True,
        )
        require_sha256("approval.support_fingerprint", self.support_fingerprint)
        require_utc("approval.reviewed_at", self.reviewed_at)
        if self.verdict is ApprovalVerdict.REJECTED and self.conflict_resolution is not None:
            raise ProvenanceInvariantError(
                "R.approval.resolution", "a rejection carries no conflict_resolution"
            )


class DecisionStatus(StrEnum):
    PROPOSED = "proposed"
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    CONFLICTING = "conflicting"
    APPROVED = "approved"
    REJECTED = "rejected"


EVIDENTIAL_STATUSES = frozenset(
    {
        DecisionStatus.PROPOSED,
        DecisionStatus.SUPPORTED,
        DecisionStatus.UNSUPPORTED,
        DecisionStatus.CONFLICTING,
    }
)


class StatusReason(StrEnum):
    NO_EVIDENCE_LINKS = "no_evidence_links"
    CHECKED_SUPPORT = "checked_support"
    CHECKED_CONTRADICTION = "checked_contradiction"
    UNCHECKED_SUPPORT_ONLY = "unchecked_support_only"
    SUPPORT_FAILED_CHECK = "support_failed_check"
    AUTOMATED_INFERENCE_IGNORED = "automated_inference_ignored"
    APPROVAL_CURRENT = "approval_current"
    APPROVAL_STALE = "approval_stale"
    REJECTED_BY_REVIEW = "rejected_by_review"
    SUPPORT_SCIENTIFICALLY_SUPERSEDED = "support_scientifically_superseded"
    SUPPORT_TECHNICALLY_SUPERSEDED = "support_technically_superseded"
    DECISION_SUPERSEDED = "decision_superseded"
