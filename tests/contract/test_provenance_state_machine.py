"""Stateful parity: every command runs on the SQLite and the in-memory service alike."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import TypeVar

import pytest
from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    initialize,
    invariant,
    precondition,
    rule,
)
from provenance_builders import assert_status_sound, make_service

from asca.application.provenance import DecisionDraft, ProvenanceService, SourceDraft, VersionDraft
from asca.domain.provenance import (
    AccessClass,
    ApprovalVerdict,
    AssertionOrigin,
    ClaimId,
    DecisionId,
    Locator,
    LocatorKind,
    LocatorPart,
    PersistentIdentifier,
    PidScheme,
    ProjectId,
    ProvenanceGraph,
    ProvenanceInvariantError,
    SourceAuthority,
    SourceId,
    SourceVersionId,
    Stance,
)
from asca.infrastructure.persistence import open_sqlite_store

pytestmark = pytest.mark.contract

T = TypeVar("T")
REF = st.integers(min_value=0, max_value=50)
ABSENT_QUOTE = "Fixture quote that appears in no fixture text."


def _text(variant: int) -> str:
    return f"Fixture machine text {variant}.\nThe calibrated value is {variant} units.\n"


def _pick(items: list[T], ref: int) -> T:
    return items[ref % len(items)]


# ---------------------------------------------------------------------- independent T1/T2


def _claim_state(graph: ProvenanceGraph, claim_id: str) -> str:
    checks = [item for item in graph.checks if item.claim_id == claim_id]
    if not checks:
        return "not_checked"
    return max(checks, key=lambda item: item.sequence).outcome.value


def _authority(graph: ProvenanceGraph, claim_id: str) -> SourceAuthority:
    claim = next(item for item in graph.claims if item.id == claim_id)
    return next(item for item in graph.versions if item.id == claim.source_version_id).authority


def _fingerprint(graph: ProvenanceGraph, decision_id: str) -> str:
    lines = sorted(
        f"{link.id}|{link.stance.value}|{link.claim_id}|{_claim_state(graph, link.claim_id)}|"
        f"{_authority(graph, link.claim_id).value}"
        for link in graph.evidence_links
        if link.decision_id == decision_id and link.stance is not Stance.CONTEXT
    )
    return hashlib.sha256(("fp1\n" + "\n".join(lines)).encode("utf-8")).hexdigest()


def review_allowed(
    graph: ProvenanceGraph, decision_id: str, verdict: ApprovalVerdict, resolution: bool
) -> bool:
    """Restates the approval rules without calling the domain's status functions."""
    if graph.project.is_synthetic:
        return False
    if verdict is ApprovalVerdict.REJECTED and resolution:
        return False
    history = sorted(
        (item for item in graph.approvals if item.decision_id == decision_id),
        key=lambda item: item.sequence,
    )
    if history and history[-1].verdict is ApprovalVerdict.REJECTED:
        return False
    if any(item.supersedes_id == decision_id for item in graph.decisions):
        return False
    if verdict is ApprovalVerdict.REJECTED:
        return True

    def countable(stance: Stance) -> bool:
        return any(
            link.decision_id == decision_id
            and link.stance is stance
            and _claim_state(graph, link.claim_id) == "source_text_checked"
            and _authority(graph, link.claim_id) is not SourceAuthority.AUTOMATED_INFERENCE
            for link in graph.evidence_links
        )

    if not countable(Stance.SUPPORTS):
        return False
    if (
        history
        and history[-1].verdict is ApprovalVerdict.APPROVED
        and history[-1].support_fingerprint == _fingerprint(graph, decision_id)
    ):
        return False
    return resolution or not countable(Stance.CONTRADICTS)


# ---------------------------------------------------------------------- machine


class PersistenceParityMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.store = open_sqlite_store("sqlite+pysqlite:///:memory:")
        self.sqlite = make_service(self.store.repository)
        self.memory = make_service()
        self.project: ProjectId | None = None
        self.synthetic = False
        self.successes = 0
        self.sources: list[SourceId] = []
        self.versions: list[SourceVersionId] = []
        self.texts: dict[str, str] = {}
        self.claims: list[ClaimId] = []
        self.claim_versions: dict[str, SourceVersionId] = {}
        self.decisions: list[DecisionId] = []

    def teardown(self) -> None:
        self.store.dispose()

    @property
    def pid(self) -> ProjectId:
        assert self.project is not None
        return self.project

    def _both(self, action: Callable[[ProvenanceService], T]) -> T | None:
        outcomes: list[tuple[str, object]] = []
        values: list[T] = []
        for service in (self.sqlite, self.memory):
            try:
                value = action(service)
            except ProvenanceInvariantError as error:
                outcomes.append(("rejected", error.rule))
            else:
                values.append(value)
                outcomes.append(("applied", value))
        assert outcomes[0] == outcomes[1]
        if not values:
            return None
        self.successes += 1
        return values[0]

    @initialize(synthetic=st.sampled_from([False, False, False, True]))
    def create_project(self, synthetic: bool) -> None:
        """Create the project plus a baseline version, claim and decision on both services."""
        title = "Fixture machine project"
        created = self.sqlite.create_project(title, is_synthetic=synthetic)
        assert self.memory.create_project(title, is_synthetic=synthetic) == created
        self.project = created
        self.synthetic = synthetic
        self.register_source(n=0, git=False)
        self.add_version(
            source=0,
            label=0,
            authority=(
                SourceAuthority.WORKING_MATERIAL if synthetic else SourceAuthority.PUBLISHED
            ),
            access=AccessClass.PUBLIC,
            text=0,
        )
        self.add_claim(version=0, in_text=True, with_path=False)
        self.propose_decision(access=AccessClass.PUBLIC, supersedes=None)
        assert self.successes == 4

    @rule(n=st.integers(0, 5), git=st.booleans())
    def register_source(self, n: int, git: bool) -> None:
        if self.synthetic:
            pid = PersistentIdentifier(PidScheme.SYNTHETIC, f"synthetic:fixture-{n}")
        elif git:
            pid = PersistentIdentifier(
                PidScheme.GIT_REPOSITORY, f"https://example.org/asca-test/repo-{n}.git"
            )
        else:
            pid = PersistentIdentifier(PidScheme.DOI, f"10.5555/asca-test.{n}")
        draft = SourceDraft(f"Fixture source {n}", pid)
        source = self._both(lambda service: service.register_source(self.pid, draft))
        if source is not None:
            self.sources.append(source)

    @precondition(lambda self: bool(self.sources))
    @rule(
        source=REF,
        label=st.integers(0, 3),
        authority=st.sampled_from(SourceAuthority),
        access=st.sampled_from(AccessClass),
        text=st.one_of(st.none(), st.integers(0, 3), st.integers(0, 3), st.integers(0, 3)),
    )
    def add_version(
        self,
        source: int,
        label: int,
        authority: SourceAuthority,
        access: AccessClass,
        text: int | None,
    ) -> None:
        implementation = authority is SourceAuthority.VERIFIED_IMPLEMENTATION
        content = None if text is None else _text(text)
        draft = VersionDraft(
            f"{label:040x}" if implementation else f"v{label}",
            authority,
            access,
            access_conditions=None if access is AccessClass.PUBLIC else "Fixture condition.",
            authority_basis=(
                "Fixture basis." if authority is SourceAuthority.APPROVED_INTERNAL else None
            ),
            content_text=content,
        )
        source_id = _pick(self.sources, source)
        version = self._both(lambda service: service.add_source_version(self.pid, source_id, draft))
        if version is not None:
            self.versions.append(version)
            if content is not None:
                self.texts[version] = content

    @precondition(lambda self: bool(self.versions))
    @rule(version=REF, in_text=st.integers(0, 3).map(bool), with_path=st.booleans())
    def add_claim(self, version: int, in_text: bool, with_path: bool) -> None:
        version_id = _pick(self.versions, version)
        text = self.texts.get(version_id)
        quote = text.splitlines()[1] if in_text and text is not None else ABSENT_QUOTE
        parts = [LocatorPart(LocatorKind.PAGE, "1")]
        if with_path:
            parts.append(LocatorPart(LocatorKind.PATH, "src/reco/estimate.py"))
        locator = Locator(tuple(parts))
        claim = self._both(
            lambda service: service.add_claim(self.pid, version_id, quote=quote, locator=locator)
        )
        if claim is not None:
            self.claims.append(claim)
            self.claim_versions[claim] = version_id

    @precondition(lambda self: bool(self.claims))
    @rule(claim=REF, correct=st.integers(0, 4).map(bool))
    def check_claim(self, claim: int, correct: bool) -> None:
        claim_id = _pick(self.claims, claim)
        stored = self.texts.get(self.claim_versions[claim_id])
        text = stored if correct and stored is not None else "Wrong fixture text.\n"
        self._both(lambda service: service.check_claim_text(self.pid, claim_id, text))

    @precondition(lambda self: bool(self.claims))
    @rule(claim=REF)
    def mark_unavailable(self, claim: int) -> None:
        claim_id = _pick(self.claims, claim)
        self._both(
            lambda service: service.mark_claim_unavailable(
                self.pid, claim_id, reason="Fixture source offline."
            )
        )

    @rule(access=st.sampled_from(AccessClass), supersedes=st.one_of(st.none(), st.none(), REF))
    def propose_decision(self, access: AccessClass, supersedes: int | None) -> None:
        supersedes_id = (
            None if supersedes is None or not self.decisions else _pick(self.decisions, supersedes)
        )
        draft = DecisionDraft(
            title=f"Fixture decision {len(self.decisions) + 1}",
            statement="Use the fixture estimator.",
            rationale="Fixture rationale.",
            access_floor=access,
            supersedes_id=supersedes_id,
        )
        decision = self._both(lambda service: service.propose_decision(self.pid, draft))
        if decision is not None:
            self.decisions.append(decision)

    @precondition(lambda self: bool(self.decisions) and bool(self.claims))
    @rule(
        decision=REF,
        claim=REF,
        stance=st.sampled_from([Stance.SUPPORTS, Stance.SUPPORTS, *Stance]),
        automated=st.booleans(),
    )
    def link_evidence(self, decision: int, claim: int, stance: Stance, automated: bool) -> None:
        decision_id = _pick(self.decisions, decision)
        claim_id = _pick(self.claims, claim)
        origin = AssertionOrigin.AUTOMATED if automated else AssertionOrigin.HUMAN
        self._both(
            lambda service: service.link_evidence(
                self.pid, decision_id, claim_id, stance, asserted_by=origin
            )
        )

    @precondition(lambda self: bool(self.decisions))
    @rule(
        decision=REF,
        verdict=st.sampled_from(
            [ApprovalVerdict.APPROVED, ApprovalVerdict.APPROVED, ApprovalVerdict.REJECTED]
        ),
        resolution=st.booleans(),
    )
    def review(self, decision: int, verdict: ApprovalVerdict, resolution: bool) -> None:
        decision_id = _pick(self.decisions, decision)
        expected = review_allowed(self.memory.load(self.pid), decision_id, verdict, resolution)
        approval = self._both(
            lambda service: service.review_decision(
                self.pid,
                decision_id,
                verdict,
                reviewer="Fixture reviewer",
                rationale="Fixture review.",
                conflict_resolution="Fixture resolution." if resolution else None,
            )
        )
        assert (approval is not None) == expected

    @invariant()
    def sqlite_and_memory_agree(self) -> None:
        if self.project is None:
            return
        stored = self.sqlite.load(self.project)
        assert stored == self.memory.load(self.project)
        assert stored.revision == self.successes
        assert_status_sound(stored)


PersistenceParityMachine.TestCase.settings = settings(
    stateful_step_count=30, max_examples=15, deadline=None
)
TestPersistenceParity = PersistenceParityMachine.TestCase


def test_machine_rules_follow_a_known_approval_path() -> None:
    """A fixed walk through the rules where the review outcomes are known in advance."""
    machine = PersistenceParityMachine()
    try:
        machine.create_project(synthetic=False)
        machine.check_claim(claim=0, correct=True)
        machine.link_evidence(decision=0, claim=0, stance=Stance.SUPPORTS, automated=False)
        machine.sqlite_and_memory_agree()
        steps = [
            (ApprovalVerdict.APPROVED, False, True),
            (ApprovalVerdict.APPROVED, False, False),
            (ApprovalVerdict.REJECTED, True, False),
            (ApprovalVerdict.REJECTED, False, True),
            (ApprovalVerdict.APPROVED, True, False),
        ]
        for verdict, resolution, expected in steps:
            before = machine.successes
            machine.review(decision=0, verdict=verdict, resolution=resolution)
            assert machine.successes == before + int(expected)
            machine.sqlite_and_memory_agree()
        assert len(machine.sqlite.load(machine.pid).approvals) == 2
    finally:
        machine.teardown()
