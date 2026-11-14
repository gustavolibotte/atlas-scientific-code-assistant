"""Deterministic synthetic demonstration project, stored like any other project.

Never use synthetic records as scientific or collaboration evidence.
"""

import hashlib
from collections.abc import Mapping, Sequence
from contextlib import suppress
from datetime import UTC, datetime
from types import MappingProxyType

from asca.application.errors import (
    ConcurrentModificationError,
    DuplicateProjectError,
    ProjectNotFoundError,
)
from asca.application.ports import ProjectSummary, ProvenanceRepository
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
    Project,
    ProjectId,
    ProvenanceGraph,
    ProvenanceRecord,
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


class DemoSeedError(RuntimeError):
    """The stored project with the demonstration id is not a prefix of the demo."""

    def __init__(self) -> None:
        super().__init__("stored demonstration project does not match the synthetic demo")


class _StagingRepository:
    """Records the demo in memory: every revision's graph and the batch that made it."""

    def __init__(self) -> None:
        self.graphs: list[ProvenanceGraph] = []
        self.batches: list[tuple[ProvenanceRecord, ...]] = []

    def create_project(self, project: Project) -> None:
        self.graphs = [ProvenanceGraph.empty(project)]

    def list_projects(self) -> list[ProjectSummary]:
        return [ProjectSummary(self.graphs[-1].project, self.graphs[-1].revision)]

    def load(self, project_id: ProjectId) -> ProvenanceGraph:
        return self.graphs[-1]

    def append(
        self,
        project_id: ProjectId,
        expected_revision: int,
        records: Sequence[ProvenanceRecord],
    ) -> int:
        graph = self.graphs[-1].append(records)
        self.graphs.append(graph)
        self.batches.append(tuple(records))
        return graph.revision


def _load_or_none(repository: ProvenanceRepository) -> ProvenanceGraph | None:
    try:
        return repository.load(DEMO_PROJECT_ID)
    except ProjectNotFoundError:
        return None


def seed_synthetic_demo(repository: ProvenanceRepository) -> ProjectId:
    """Store the synthetic demonstration project, completing an interrupted seed.

    The demo is first recorded in memory, revision by revision. The stored project is
    then brought to the final revision by appending the missing batches, so a seed
    interrupted after any committed step is resumed on the next start, and concurrent
    seeders converge (a lost compare-and-set reloads and continues). A stored project
    with the demo id that is not exactly a prefix of the demo raises ``DemoSeedError``.
    """
    staging = _StagingRepository()
    _record_demo(staging)
    final = staging.graphs[-1]
    # Every pass creates the project or advances its revision (ours or a rival's), so a
    # consistent repository finishes within the creation, each batch and a last check.
    for _ in range(final.revision + 3):
        stored = _load_or_none(repository)
        if stored is None:
            # A concurrent seeder may have created it: reload and continue from there.
            with suppress(DuplicateProjectError):
                repository.create_project(final.project)
            continue
        if stored.revision >= final.revision:
            if not _contains(stored, final):
                raise DemoSeedError()
            return DEMO_PROJECT_ID
        if stored != staging.graphs[stored.revision]:
            raise DemoSeedError()
        # A concurrent seeder may have appended this step: reload and continue.
        with suppress(ConcurrentModificationError):
            repository.append(DEMO_PROJECT_ID, stored.revision, staging.batches[stored.revision])
    raise DemoSeedError()


def _contains(stored: ProvenanceGraph, expected: ProvenanceGraph) -> bool:
    return stored.project == expected.project and all(
        stored.find(type(record), record.id) == record for record in expected.records()
    )


def _record_demo(repository: ProvenanceRepository) -> ProjectId:
    """Record the demo through the service. The call order fixes the ids."""
    service = ProvenanceService(
        repository, FixedClock(DEMO_TIME), DeterministicIdFactory(DEMO_NAMESPACE)
    )
    project = service.create_project("Synthetic demonstration project", is_synthetic=True)
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
