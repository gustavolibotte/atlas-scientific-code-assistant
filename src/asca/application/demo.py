"""Pure synthetic trace used only to demonstrate provenance navigation."""

from asca.domain.provenance import (
    CodeSymbol,
    EvidenceAuthority,
    EvidenceReference,
    ProvenanceTrace,
    ScientificDecision,
    VerificationRecord,
    VerificationState,
)


def create_synthetic_trace() -> ProvenanceTrace:
    """Never use synthetic records as scientific or collaboration evidence."""
    return ProvenanceTrace(
        decision=ScientificDecision(
            id="demo-decision-001",
            statement="Choose an estimator under an illustrative covariance assumption.",
            rationale="Example decision, not an implemented or ATLAS-approved method.",
            evidence_ids=("demo-evidence-001",),
            code_symbol_ids=("demo-symbol-001",),
            verification_ids=("demo-test-001",),
        ),
        evidence=(
            EvidenceReference(
                id="demo-evidence-001",
                title="Synthetic source placeholder — no paper consulted",
                locator="synthetic:demo-only",
                authority=EvidenceAuthority.UNVERIFIED,
                is_real_source=False,
            ),
        ),
        symbols=(
            CodeSymbol(
                id="demo-symbol-001",
                qualified_name="estimate_amplitude",
                file_path="src/reconstruction/estimators.py",
                revision="synthetic-demo",
            ),
        ),
        verifications=(
            VerificationRecord(
                id="demo-test-001",
                label="Numerical validation — illustrative and not executed",
                state=VerificationState.NOT_RUN,
            ),
        ),
        is_synthetic=True,
    )
