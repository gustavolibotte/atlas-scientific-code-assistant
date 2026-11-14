"""Frozen legacy ``/api/v1/demo/trace`` view, now built from a stored provenance graph."""

from asca.api.schemas import (
    DecisionDTO,
    EvidenceAuthority,
    EvidenceDTO,
    SymbolDTO,
    TraceResponse,
    VerificationDTO,
    VerificationState,
)
from asca.domain.provenance import (
    COUNTED_STANCES,
    Claim,
    CodeSymbol,
    ProvenanceGraph,
    RunOrigin,
    ScientificDecision,
    Source,
    SourceAuthority,
    SourceVersion,
    TestCase,
    TestOutcome,
    WorkspaceRevision,
    latest_result,
)

LEGACY_DISCLAIMER = "Synthetic UI demonstration; no CERN source, code, or test was consulted."

_AUTHORITY = {
    SourceAuthority.PUBLISHED: EvidenceAuthority.PUBLISHED,
    SourceAuthority.APPROVED_INTERNAL: EvidenceAuthority.DOCUMENTED,
    SourceAuthority.VERIFIED_IMPLEMENTATION: EvidenceAuthority.IMPLEMENTATION,
    SourceAuthority.WORKING_MATERIAL: EvidenceAuthority.UNVERIFIED,
    SourceAuthority.AUTOMATED_INFERENCE: EvidenceAuthority.UNVERIFIED,
}

_OUTCOME = {
    TestOutcome.PASSED: VerificationState.PASSED,
    TestOutcome.FAILED: VerificationState.FAILED,
    TestOutcome.ERROR: VerificationState.FAILED,
    TestOutcome.SKIPPED: VerificationState.HUMAN_REVIEW_REQUIRED,
    TestOutcome.XFAILED: VerificationState.HUMAN_REVIEW_REQUIRED,
    TestOutcome.XPASSED: VerificationState.HUMAN_REVIEW_REQUIRED,
}


def _evidence(graph: ProvenanceGraph, claim_id: str) -> EvidenceDTO:
    claim = graph.get(Claim, claim_id)
    version = graph.get(SourceVersion, claim.source_version_id)
    source = graph.get(Source, version.source_id)
    parts = "; ".join(f"{part.kind}={part.value}" for part in claim.locator.parts)
    return EvidenceDTO(
        id=claim.id,
        title=source.title,
        locator=f"{source.persistent_id.value} {version.version_label} · {parts}",
        authority=_AUTHORITY[version.authority],
        is_real_source=not source.is_synthetic,
    )


def _symbol(graph: ProvenanceGraph, symbol_id: str) -> SymbolDTO:
    symbol = graph.get(CodeSymbol, symbol_id)
    revision = graph.get(WorkspaceRevision, symbol.revision_id)
    return SymbolDTO(
        id=symbol.id,
        qualified_name=symbol.qualified_name,
        file_path=symbol.file_path,
        revision=revision.vcs_ref or f"rev-{revision.sequence}",
    )


def _verification(graph: ProvenanceGraph, test_case_id: str) -> VerificationDTO:
    test = graph.get(TestCase, test_case_id)
    latest = latest_result(graph, test.id)
    if latest is None or latest[0].origin is RunOrigin.SYNTHETIC:
        state = VerificationState.NOT_RUN
    else:
        state = _OUTCOME[latest[1].outcome]
    return VerificationDTO(id=test.id, label=test.description, state=state)


def legacy_trace_from_graph(graph: ProvenanceGraph, decision_id: str) -> TraceResponse:
    decision = graph.get(ScientificDecision, decision_id)
    evidence_ids = sorted(
        {link.claim_id for link in graph.links_for(decision.id) if link.stance in COUNTED_STANCES}
    )
    symbol_ids = sorted(
        {link.symbol_id for link in graph.implementation_links_for_decision(decision.id)}
    )
    verifying = {link.test_case_id for link in graph.verification_links_for_decision(decision.id)}
    for symbol_id in symbol_ids:
        verifying.update(
            link.test_case_id for link in graph.verification_links_for_symbol(symbol_id)
        )
    verification_ids = sorted(verifying)
    return TraceResponse(
        is_synthetic=graph.project.is_synthetic,
        disclaimer=LEGACY_DISCLAIMER,
        decision=DecisionDTO(
            id=decision.id,
            statement=decision.statement,
            rationale=decision.rationale,
            evidence_ids=tuple(evidence_ids),
            code_symbol_ids=tuple(symbol_ids),
            verification_ids=tuple(verification_ids),
        ),
        evidence=[_evidence(graph, claim_id) for claim_id in evidence_ids],
        symbols=[_symbol(graph, symbol_id) for symbol_id in symbol_ids],
        verifications=[_verification(graph, test_id) for test_id in verification_ids],
    )
