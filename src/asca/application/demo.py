"""Deterministic synthetic demonstration project, stored like any other project.

Never use synthetic records as scientific or collaboration evidence.
"""

import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime
from types import MappingProxyType

from asca.application.errors import DuplicateProjectError
from asca.application.ports import ProvenanceRepository
from asca.application.provenance import (
    DecisionDraft,
    ProvenanceService,
    SourceDraft,
    SymbolDraft,
    VersionDraft,
)
from asca.domain.provenance import (
    AccessClass,
    Alternative,
    Assumption,
    DecisionId,
    IdKind,
    Language,
    Locator,
    LocatorKind,
    LocatorPart,
    PersistentIdentifier,
    PidScheme,
    ProjectId,
    SourceAuthority,
    Stance,
    SupersessionDimension,
    SymbolKind,
    TestKind,
)

DEMO_NAMESPACE = "asca-demo"
DEMO_TIME = datetime(2026, 11, 12, tzinfo=UTC)


class FixedClock:
    """A clock that always returns the same instant."""

    def __init__(self, at: datetime) -> None:
        self._at = at

    def now(self) -> datetime:
        return self._at


def deterministic_id(namespace: str, kind: IdKind, counter: int) -> str:
    digest = hashlib.sha256(f"{namespace}/{kind.value}/{counter}".encode()).hexdigest()
    return f"{kind.value}_{digest[:32]}"


class DeterministicIdFactory:
    """Reproducible ids: one counter per kind, starting at 1."""

    def __init__(self, namespace: str) -> None:
        self._namespace = namespace
        self._counters: dict[IdKind, int] = {}

    def new(self, kind: IdKind) -> str:
        counter = self._counters.get(kind, 0) + 1
        self._counters[kind] = counter
        return deterministic_id(self._namespace, kind, counter)


DEMO_PROJECT_ID = ProjectId(deterministic_id(DEMO_NAMESPACE, IdKind.PROJECT, 1))
DEMO_DECISION_ID = DecisionId(deterministic_id(DEMO_NAMESPACE, IdKind.DECISION, 1))

SYNTHETIC_SOURCE_TEXTS: Mapping[str, str] = MappingProxyType(
    {
        "estimator-note-v1": (
            "SYNTHETIC DEMONSTRATION DOCUMENT. Not a real paper, note or ATLAS result.\n"
            "Section 2. Amplitude estimation.\n"
            "For illustration, assume stationary noise with a known covariance matrix. Under "
            "this assumption, weighting the samples with the inverse noise covariance gives the "
            "minimum-variance linear unbiased amplitude estimate.\n"
        ),
        "internal-memo-v1": (
            "SYNTHETIC DEMONSTRATION MEMO (v1). Fictional internal-only example; nothing real "
            "is restricted.\nPedestal values may drift between runs.\n"
        ),
        "internal-memo-v2": (
            "SYNTHETIC DEMONSTRATION MEMO (v2). Fictional internal-only example; nothing real "
            "is restricted.\nPedestal values drift between runs and should be measured per "
            "event.\n"
        ),
    }
)

_FICTIONAL_ACCESS = "Fictional access condition for demonstration; no real document is restricted."


def seed_synthetic_demo(repository: ProvenanceRepository) -> ProjectId:
    """Store the synthetic demonstration project once. The call order fixes the ids."""
    if any(item.project.id == DEMO_PROJECT_ID for item in repository.list_projects()):
        return DEMO_PROJECT_ID
    service = ProvenanceService(
        repository, FixedClock(DEMO_TIME), DeterministicIdFactory(DEMO_NAMESPACE)
    )
    try:
        project = service.create_project("Synthetic demonstration project", is_synthetic=True)
    except DuplicateProjectError:
        return DEMO_PROJECT_ID
    texts = SYNTHETIC_SOURCE_TEXTS

    note = service.register_source(
        project,
        SourceDraft(
            "Synthetic estimator note — no paper consulted",
            PersistentIdentifier(PidScheme.SYNTHETIC, "synthetic:demo-estimator-note"),
        ),
    )
    note_v1 = service.add_source_version(
        project,
        note,
        VersionDraft(
            "v1",
            SourceAuthority.WORKING_MATERIAL,
            AccessClass.PUBLIC,
            content_text=texts["estimator-note-v1"],
        ),
    )
    memo = service.register_source(
        project,
        SourceDraft(
            "Synthetic internal memo — fictional",
            PersistentIdentifier(PidScheme.SYNTHETIC, "synthetic:demo-internal-memo"),
        ),
    )
    memo_v1 = service.add_source_version(
        project,
        memo,
        VersionDraft(
            "v1",
            SourceAuthority.WORKING_MATERIAL,
            AccessClass.INTERNAL,
            access_conditions=_FICTIONAL_ACCESS,
            content_text=texts["internal-memo-v1"],
        ),
    )
    memo_v2 = service.add_source_version(
        project,
        memo,
        VersionDraft(
            "v2",
            SourceAuthority.WORKING_MATERIAL,
            AccessClass.INTERNAL,
            access_conditions=_FICTIONAL_ACCESS,
            content_text=texts["internal-memo-v2"],
        ),
    )
    service.record_supersession(
        project,
        superseded=memo_v1,
        superseding=memo_v2,
        dimension=SupersessionDimension.TECHNICAL,
        reason="Synthetic example of a revised memo.",
    )
    estimator_claim = service.add_claim(
        project,
        note_v1,
        quote=(
            "weighting the samples with the inverse noise covariance gives the "
            "minimum-variance linear unbiased amplitude estimate"
        ),
        locator=Locator((LocatorPart(LocatorKind.SECTION, "2"),)),
        statement="Illustrative claim from synthetic text.",
    )
    pedestal_claim = service.add_claim(
        project,
        memo_v2,
        quote="Pedestal values drift between runs and should be measured per event.",
        locator=Locator((LocatorPart(LocatorKind.PARAGRAPH, "2"),)),
    )
    service.check_claim_text(project, estimator_claim, texts["estimator-note-v1"])
    service.check_claim_text(project, pedestal_claim, texts["internal-memo-v2"])
    estimator_decision = service.propose_decision(
        project,
        DecisionDraft(
            title="Illustrative estimator choice",
            statement="Choose an estimator under an illustrative covariance assumption.",
            rationale="Example decision, not an implemented or ATLAS-approved method.",
            alternatives=(
                Alternative(
                    "Unweighted mean",
                    "Average the samples with equal weights.",
                    "Ignores the assumed noise correlations in this illustration.",
                ),
            ),
            assumptions=(
                Assumption(
                    "Noise is stationary with a known covariance matrix.",
                    "Stated as an assumption in the synthetic note; not validated.",
                ),
            ),
        ),
    )
    pedestal_decision = service.propose_decision(
        project,
        DecisionDraft(
            title="Illustrative pedestal handling",
            statement="Subtract a per-event pedestal before amplitude estimation.",
            rationale="Synthetic example of a decision recorded without supporting evidence.",
            assumptions=(Assumption("Pedestal can be estimated from pre-samples.", None),),
        ),
    )
    service.link_evidence(project, estimator_decision, estimator_claim, Stance.SUPPORTS)
    service.link_evidence(project, pedestal_decision, pedestal_claim, Stance.CONTEXT)
    revision = service.record_workspace_revision(
        project,
        vcs_ref="synthetic-demo",
        symbols=[
            SymbolDraft(
                Language.PYTHON,
                SymbolKind.FUNCTION,
                "estimate_amplitude",
                "src/reconstruction/estimators.py",
            ),
            SymbolDraft(
                Language.PYTHON,
                SymbolKind.FUNCTION,
                "subtract_pedestal",
                "src/reconstruction/estimators.py",
            ),
        ],
        symbols_indexed=False,
    )
    estimate_symbol, pedestal_symbol = revision.symbol_ids
    service.link_implementation(project, estimator_decision, estimate_symbol)
    service.link_implementation(project, pedestal_decision, pedestal_symbol)
    test = service.register_test_case(
        project,
        node_id="tests/test_estimators.py::test_illustrative",
        kind=TestKind.NUMERICAL,
        description="Numerical validation — illustrative and not executed",
    )
    service.link_verification(project, test, decision_id=estimator_decision)
    return project
