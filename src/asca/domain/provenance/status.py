"""Derived decision status, currency, link freshness and latest results.

Every function here is pure, total over valid graphs, and deterministic.
"""

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from asca.domain.provenance.claims import Claim, ClaimVerificationState
from asca.domain.provenance.code import ImplementationLink, LinkFreshness
from asca.domain.provenance.decisions import (
    COUNTED_STANCES,
    Approval,
    ApprovalVerdict,
    DecisionStatus,
    EvidenceLink,
    ScientificDecision,
    Stance,
    StatusReason,
)
from asca.domain.provenance.ids import ApprovalId, DecisionId
from asca.domain.provenance.lineage import SymbolLineage
from asca.domain.provenance.sources import (
    Currency,
    SourceAuthority,
    SourceVersion,
    SupersessionDimension,
)
from asca.domain.provenance.validation import TestResult, ValidationRun
from asca.domain.provenance.values import AccessClass, most_restrictive

if TYPE_CHECKING:
    from asca.domain.provenance.graph import ProvenanceGraph

_REASON_ORDER = {reason: position for position, reason in enumerate(StatusReason)}


@dataclass(frozen=True, slots=True)
class DecisionStatusReport:
    decision_id: DecisionId
    status: DecisionStatus
    evidential_status: DecisionStatus
    reasons: tuple[StatusReason, ...]
    support_fingerprint: str
    current_approval_id: ApprovalId | None
    approval_stale: bool
    superseded_by: DecisionId | None
    effective_access_class: AccessClass


def _version_of(graph: "ProvenanceGraph", link: EvidenceLink) -> SourceVersion:
    claim = graph.get(Claim, link.claim_id)
    return graph.get(SourceVersion, claim.source_version_id)


def _counted_links(graph: "ProvenanceGraph", decision_id: str) -> tuple[EvidenceLink, ...]:
    return tuple(link for link in graph.links_for(decision_id) if link.stance in COUNTED_STANCES)


def is_countable(graph: "ProvenanceGraph", link: EvidenceLink) -> bool:
    """A counted-stance link to a source-text-checked claim on a supporting authority."""
    return (
        link.stance in COUNTED_STANCES
        and graph.claim_state(link.claim_id) is ClaimVerificationState.SOURCE_TEXT_CHECKED
        and _version_of(graph, link).authority.can_support
    )


def support_fingerprint(graph: "ProvenanceGraph", decision_id: str) -> str:
    lines = sorted(
        f"{link.id}|{link.stance}|{link.claim_id}|{graph.claim_state(link.claim_id)}|"
        f"{_version_of(graph, link).authority}"
        for link in _counted_links(graph, decision_id)
    )
    return hashlib.sha256(("fp1\n" + "\n".join(lines)).encode("utf-8")).hexdigest()


def currency(
    graph: "ProvenanceGraph", version_id: str, dimension: SupersessionDimension
) -> Currency:
    if any(notice.dimension is dimension for notice in graph.notices_for(version_id)):
        return Currency.SUPERSEDED
    return Currency.CURRENT


def _ordered(reasons: set[StatusReason]) -> tuple[StatusReason, ...]:
    return tuple(sorted(reasons, key=_REASON_ORDER.__getitem__))


def evidential_status(
    graph: "ProvenanceGraph", decision_id: str
) -> tuple[DecisionStatus, tuple[StatusReason, ...]]:
    counted = _counted_links(graph, decision_id)
    supported = [link for link in counted if link.stance is Stance.SUPPORTS]
    checked_support = [link for link in supported if is_countable(graph, link)]
    checked_contradiction = [
        link for link in counted if link.stance is Stance.CONTRADICTS and is_countable(graph, link)
    ]
    unchecked_support = [
        link
        for link in supported
        if graph.claim_state(link.claim_id) is ClaimVerificationState.NOT_CHECKED
        and _version_of(graph, link).authority.can_support
    ]
    if checked_support and checked_contradiction:
        status = DecisionStatus.CONFLICTING
    elif checked_support:
        status = DecisionStatus.SUPPORTED
    elif unchecked_support:
        status = DecisionStatus.PROPOSED
    else:
        status = DecisionStatus.UNSUPPORTED

    reasons: set[StatusReason] = set()
    if not counted:
        reasons.add(StatusReason.NO_EVIDENCE_LINKS)
    if checked_support:
        reasons.add(StatusReason.CHECKED_SUPPORT)
    if checked_contradiction:
        reasons.add(StatusReason.CHECKED_CONTRADICTION)
    if not checked_support and unchecked_support:
        reasons.add(StatusReason.UNCHECKED_SUPPORT_ONLY)
    if any(
        graph.claim_state(link.claim_id)
        in (ClaimVerificationState.MISMATCH, ClaimVerificationState.UNAVAILABLE)
        for link in supported
    ):
        reasons.add(StatusReason.SUPPORT_FAILED_CHECK)
    if any(
        _version_of(graph, link).authority is SourceAuthority.AUTOMATED_INFERENCE
        for link in counted
    ):
        reasons.add(StatusReason.AUTOMATED_INFERENCE_IGNORED)
    for link in checked_support:
        version_id = _version_of(graph, link).id
        if currency(graph, version_id, SupersessionDimension.SCIENTIFIC) is Currency.SUPERSEDED:
            reasons.add(StatusReason.SUPPORT_SCIENTIFICALLY_SUPERSEDED)
        if currency(graph, version_id, SupersessionDimension.TECHNICAL) is Currency.SUPERSEDED:
            reasons.add(StatusReason.SUPPORT_TECHNICALLY_SUPERSEDED)
    return status, _ordered(reasons)


def derive_status(graph: "ProvenanceGraph", decision_id: str) -> DecisionStatusReport:
    decision = graph.get(ScientificDecision, decision_id)
    evidential, evidential_reasons = evidential_status(graph, decision.id)
    fingerprint = support_fingerprint(graph, decision.id)
    reasons = set(evidential_reasons)
    approvals = graph.approvals_for(decision.id)
    last: Approval | None = approvals[-1] if approvals else None
    status = evidential
    stale = False
    if last is not None and last.verdict is ApprovalVerdict.REJECTED:
        status = DecisionStatus.REJECTED
        reasons.add(StatusReason.REJECTED_BY_REVIEW)
    elif last is not None:
        if last.support_fingerprint == fingerprint and evidential in (
            DecisionStatus.SUPPORTED,
            DecisionStatus.CONFLICTING,
        ):
            status = DecisionStatus.APPROVED
            reasons.add(StatusReason.APPROVAL_CURRENT)
        else:
            stale = True
            reasons.add(StatusReason.APPROVAL_STALE)
    superseded_by = graph.superseded_by(decision.id)
    if superseded_by is not None:
        reasons.add(StatusReason.DECISION_SUPERSEDED)
    linked_classes = [
        _version_of(graph, link).access_class for link in graph.links_for(decision.id)
    ]
    return DecisionStatusReport(
        decision_id=decision.id,
        status=status,
        evidential_status=evidential,
        reasons=_ordered(reasons),
        support_fingerprint=fingerprint,
        current_approval_id=(
            last.id
            if last is not None and status in (DecisionStatus.APPROVED, DecisionStatus.REJECTED)
            else None
        ),
        approval_stale=stale,
        superseded_by=superseded_by,
        effective_access_class=most_restrictive([decision.access_floor, *linked_classes]),
    )


def link_freshness(graph: "ProvenanceGraph", link: ImplementationLink) -> LinkFreshness:
    """Freshness of ``link`` from the lineage of its symbol (see ``lineage.py``)."""
    return SymbolLineage(graph).resolve(link).freshness


def latest_result(
    graph: "ProvenanceGraph", test_case_id: str
) -> tuple[ValidationRun, TestResult] | None:
    best: tuple[ValidationRun, TestResult] | None = None
    for run in graph.runs:
        result = run.result_for(test_case_id)
        if result is None:
            continue
        if best is None or (run.finished_at, run.id) > (best[0].finished_at, best[0].id):
            best = (run, result)
    return best
