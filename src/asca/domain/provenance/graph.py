"""The immutable per-project provenance graph: the single consistency boundary."""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import TypeVar

from asca.domain.provenance.claims import (
    Claim,
    ClaimCheck,
    ClaimCheckOutcome,
    ClaimVerificationState,
)
from asca.domain.provenance.code import (
    CodeSymbol,
    ImplementationLink,
    SymbolKey,
    WorkspaceRevision,
)
from asca.domain.provenance.decisions import (
    Approval,
    ApprovalVerdict,
    DecisionStatus,
    EvidenceLink,
    ScientificDecision,
)
from asca.domain.provenance.errors import ProvenanceInvariantError, RecordNotFoundError
from asca.domain.provenance.ids import ClaimId, DecisionId
from asca.domain.provenance.sources import (
    SYNTHETIC_ALLOWED_AUTHORITIES,
    Project,
    Source,
    SourceAuthority,
    SourceVersion,
    SupersessionNotice,
)
from asca.domain.provenance.status import derive_status, support_fingerprint
from asca.domain.provenance.validation import (
    EnvironmentSnapshot,
    RunOrigin,
    TestCase,
    ValidationRun,
    VerificationLink,
)
from asca.domain.provenance.values import (
    PUBLISHED_PID_SCHEMES,
    LocatorKind,
    PidScheme,
    require_int,
)

ProvenanceRecord = (
    Source
    | SourceVersion
    | SupersessionNotice
    | Claim
    | ClaimCheck
    | ScientificDecision
    | EvidenceLink
    | WorkspaceRevision
    | CodeSymbol
    | ImplementationLink
    | TestCase
    | VerificationLink
    | EnvironmentSnapshot
    | ValidationRun
    | Approval
)

R = TypeVar("R")

#: Graph field name for each record type, in field declaration order.
RECORD_FIELDS: dict[type[object], str] = {
    Source: "sources",
    SourceVersion: "versions",
    SupersessionNotice: "supersessions",
    Claim: "claims",
    ClaimCheck: "checks",
    ScientificDecision: "decisions",
    EvidenceLink: "evidence_links",
    WorkspaceRevision: "revisions",
    CodeSymbol: "symbols",
    ImplementationLink: "implementation_links",
    TestCase: "test_cases",
    VerificationLink: "verification_links",
    EnvironmentSnapshot: "environments",
    ValidationRun: "runs",
    Approval: "approvals",
}


def _fail(rule: str, detail: str) -> ProvenanceInvariantError:
    return ProvenanceInvariantError(rule, detail)


def _require_unique(rule: str, keys: Iterable[object], what: str) -> None:
    seen: set[object] = set()
    for key in keys:
        if key in seen:
            raise _fail(rule, f"duplicate {what}")
        seen.add(key)


def _require_sequence(rule: str, groups: dict[str, list[int]], what: str) -> None:
    for owner, sequences in groups.items():
        if sorted(sequences) != list(range(1, len(sequences) + 1)):
            raise _fail(rule, f"{what} sequences of {owner} must be exactly 1..n")


@dataclass(frozen=True, slots=True)
class ProvenanceGraph:
    """All provenance records of one project at one revision.

    State invariants (``G.*``) are checked on every construction, including reloads.
    Transition rules (``T.*``) are checked only by :meth:`append`.
    """

    project: Project
    revision: int
    sources: tuple[Source, ...] = ()
    versions: tuple[SourceVersion, ...] = ()
    supersessions: tuple[SupersessionNotice, ...] = ()
    claims: tuple[Claim, ...] = ()
    checks: tuple[ClaimCheck, ...] = ()
    decisions: tuple[ScientificDecision, ...] = ()
    evidence_links: tuple[EvidenceLink, ...] = ()
    revisions: tuple[WorkspaceRevision, ...] = ()
    symbols: tuple[CodeSymbol, ...] = ()
    implementation_links: tuple[ImplementationLink, ...] = ()
    test_cases: tuple[TestCase, ...] = ()
    verification_links: tuple[VerificationLink, ...] = ()
    environments: tuple[EnvironmentSnapshot, ...] = ()
    runs: tuple[ValidationRun, ...] = ()
    approvals: tuple[Approval, ...] = ()
    _index: dict[str, ProvenanceRecord] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.project, Project):
            raise _fail("G.record_type", "project must be a Project")
        require_int("graph.revision", self.revision, minimum=0)
        for record_type, name in RECORD_FIELDS.items():
            values = getattr(self, name)
            if not isinstance(values, tuple | list) or not all(
                type(item) is record_type for item in values
            ):
                raise _fail("G.record_type", f"{name} must hold only {record_type.__name__}")
            object.__setattr__(self, name, tuple(sorted(values, key=lambda item: item.id)))
        index: dict[str, ProvenanceRecord] = {}
        for record in self.records():
            if record.id in index:
                raise _fail("G.duplicate_id", f"duplicate id {record.id}")
            index[record.id] = record
        object.__setattr__(self, "_index", index)
        self._check_state()

    # ------------------------------------------------------------------ factories

    @classmethod
    def empty(cls, project: Project) -> "ProvenanceGraph":
        return cls(project=project, revision=0)

    def records(self) -> tuple[ProvenanceRecord, ...]:
        """Every record, grouped by kind in field order, each group sorted by id."""
        result: list[ProvenanceRecord] = []
        for name in RECORD_FIELDS.values():
            result.extend(getattr(self, name))
        return tuple(result)

    def _with(self, records: Sequence[ProvenanceRecord], revision: int) -> "ProvenanceGraph":
        groups: dict[str, list[ProvenanceRecord]] = {
            name: list(getattr(self, name)) for name in RECORD_FIELDS.values()
        }
        for record in records:
            groups[RECORD_FIELDS[type(record)]].append(record)
        return ProvenanceGraph(
            self.project,
            revision,
            **{name: tuple(values) for name, values in groups.items()},  # type: ignore[arg-type]
        )

    def append(self, records: Sequence[ProvenanceRecord]) -> "ProvenanceGraph":
        """Return the next revision after checking transition rules for ``records``."""
        batch = tuple(records)
        if not batch:
            raise _fail("T.append.empty", "an append needs at least one record")
        for position, record in enumerate(batch):
            if type(record) not in RECORD_FIELDS:
                raise _fail("G.record_type", f"record {position} is not a provenance record")
            self._check_transition(record, batch[:position])
        return self._with(batch, self.revision + 1)

    # ------------------------------------------------------------------ lookups

    def get(self, kind: type[R], record_id: str) -> R:
        record = self.find(kind, record_id)
        if record is None:
            raise RecordNotFoundError(kind.__name__, str(record_id))
        return record

    def find(self, kind: type[R], record_id: str) -> R | None:
        record = self._index.get(record_id) if isinstance(record_id, str) else None
        return record if isinstance(record, kind) else None

    def checks_for(self, claim_id: str) -> tuple[ClaimCheck, ...]:
        return tuple(
            sorted(
                (check for check in self.checks if check.claim_id == claim_id),
                key=lambda check: check.sequence,
            )
        )

    def latest_check(self, claim_id: str) -> ClaimCheck | None:
        checks = self.checks_for(claim_id)
        return checks[-1] if checks else None

    def claim_state(self, claim_id: str) -> ClaimVerificationState:
        latest = self.latest_check(claim_id)
        if latest is None:
            return ClaimVerificationState.NOT_CHECKED
        return ClaimVerificationState(latest.outcome.value)

    def links_for(self, decision_id: str) -> tuple[EvidenceLink, ...]:
        return tuple(link for link in self.evidence_links if link.decision_id == decision_id)

    def approvals_for(self, decision_id: str) -> tuple[Approval, ...]:
        return tuple(
            sorted(
                (item for item in self.approvals if item.decision_id == decision_id),
                key=lambda item: item.sequence,
            )
        )

    def superseded_by(self, decision_id: str) -> DecisionId | None:
        return next((item.id for item in self.decisions if item.supersedes_id == decision_id), None)

    def notices_for(self, version_id: str) -> tuple[SupersessionNotice, ...]:
        return tuple(
            notice for notice in self.supersessions if notice.superseded_version_id == version_id
        )

    def latest_revision(self, *, indexed_only: bool = False) -> WorkspaceRevision | None:
        candidates = [
            revision for revision in self.revisions if revision.symbols_indexed or not indexed_only
        ]
        return max(candidates, key=lambda revision: revision.sequence, default=None)

    def symbols_in(self, revision_id: str) -> tuple[CodeSymbol, ...]:
        return tuple(symbol for symbol in self.symbols if symbol.revision_id == revision_id)

    def implementation_links_for_key(self, key: SymbolKey) -> tuple[ImplementationLink, ...]:
        return tuple(
            link
            for link in self.implementation_links
            if self.get(CodeSymbol, link.symbol_id).key == key
        )

    def implementation_links_for_decision(self, decision_id: str) -> tuple[ImplementationLink, ...]:
        return tuple(link for link in self.implementation_links if link.decision_id == decision_id)

    def verification_links_for_decision(self, decision_id: str) -> tuple[VerificationLink, ...]:
        return tuple(link for link in self.verification_links if link.decision_id == decision_id)

    def verification_links_for_symbol(self, symbol_id: str) -> tuple[VerificationLink, ...]:
        return tuple(link for link in self.verification_links if link.symbol_id == symbol_id)

    def next_check_sequence(self, claim_id: ClaimId) -> int:
        return len(self.checks_for(claim_id)) + 1

    def next_approval_sequence(self, decision_id: DecisionId) -> int:
        return len(self.approvals_for(decision_id)) + 1

    def next_revision_sequence(self) -> int:
        return len(self.revisions) + 1

    # ------------------------------------------------------------------ state rules

    def _resolves(self, kind: type[object], record_id: str | None) -> bool:
        return record_id is None or isinstance(self._index.get(record_id), kind)

    def _check_state(self) -> None:
        project_id = self.project.id
        for record in self.records():
            if record.project_id != project_id:
                raise _fail("G.project_scope", f"{record.id} belongs to another project")
        self._check_dangling()
        self._check_synthetic()
        self._check_authority()
        self._check_claims()
        self._check_uniqueness()
        self._check_decision_supersession()
        approvals: dict[str, list[int]] = {}
        for approval in self.approvals:
            approvals.setdefault(approval.decision_id, []).append(approval.sequence)
        _require_sequence("G.approval.sequence", approvals, "approval")
        _require_sequence(
            "G.revision.sequence",
            {"project": [revision.sequence for revision in self.revisions]},
            "workspace revision",
        )

    def _check_dangling(self) -> None:
        references: list[tuple[str, type[object], str | None]] = []
        references += [(v.id, Source, v.source_id) for v in self.versions]
        for notice in self.supersessions:
            references.append((notice.id, SourceVersion, notice.superseded_version_id))
            references.append((notice.id, SourceVersion, notice.superseding_version_id))
        references += [(c.id, SourceVersion, c.source_version_id) for c in self.claims]
        references += [(c.id, Claim, c.claim_id) for c in self.checks]
        references += [(d.id, ScientificDecision, d.supersedes_id) for d in self.decisions]
        for link in self.evidence_links:
            references.append((link.id, ScientificDecision, link.decision_id))
            references.append((link.id, Claim, link.claim_id))
        references += [(s.id, WorkspaceRevision, s.revision_id) for s in self.symbols]
        for impl in self.implementation_links:
            references.append((impl.id, ScientificDecision, impl.decision_id))
            references.append((impl.id, CodeSymbol, impl.symbol_id))
        for ver in self.verification_links:
            references.append((ver.id, TestCase, ver.test_case_id))
            references.append((ver.id, ScientificDecision, ver.decision_id))
            references.append((ver.id, CodeSymbol, ver.symbol_id))
        for run in self.runs:
            references.append((run.id, WorkspaceRevision, run.revision_id))
            references.append((run.id, EnvironmentSnapshot, run.environment_id))
            references += [(run.id, TestCase, result.test_case_id) for result in run.results]
        references += [(a.id, ScientificDecision, a.decision_id) for a in self.approvals]
        for owner, kind, target in references:
            if not self._resolves(kind, target):
                raise _fail("G.dangling", f"{owner} references unknown {kind.__name__} {target}")

    def _check_synthetic(self) -> None:
        synthetic = self.project.is_synthetic
        for source in self.sources:
            if source.is_synthetic != synthetic:
                raise _fail(
                    "G.synthetic.sources",
                    f"source {source.id} synthetic={source.is_synthetic} in a project with "
                    f"is_synthetic={synthetic}",
                )
        for run in self.runs:
            if (run.origin is RunOrigin.SYNTHETIC) != synthetic:
                raise _fail(
                    "G.synthetic.runs", f"run {run.id} origin {run.origin.value} is not allowed"
                )
        if synthetic and self.approvals:
            raise _fail("G.synthetic.approvals", "a synthetic project cannot record approvals")

    def _check_authority(self) -> None:
        for version in self.versions:
            source = self.get(Source, version.source_id)
            scheme = source.persistent_id.scheme
            if (
                version.authority is SourceAuthority.PUBLISHED
                and scheme not in PUBLISHED_PID_SCHEMES
            ):
                raise _fail(
                    "G.authority.published_pid",
                    f"published version {version.id} needs a published identifier, "
                    f"not {scheme.value}",
                )
            if (
                version.authority is SourceAuthority.VERIFIED_IMPLEMENTATION
                and scheme is not PidScheme.GIT_REPOSITORY
            ):
                raise _fail(
                    "G.authority.implementation_pid",
                    f"verified_implementation version {version.id} needs a git_repository",
                )
            if source.is_synthetic and version.authority not in SYNTHETIC_ALLOWED_AUTHORITIES:
                raise _fail(
                    "G.authority.synthetic",
                    f"synthetic version {version.id} cannot have authority "
                    f"{version.authority.value}",
                )

    def _check_claims(self) -> None:
        sequences: dict[str, list[int]] = {}
        for check in self.checks:
            sequences.setdefault(check.claim_id, []).append(check.sequence)
            version = self.get(SourceVersion, self.get(Claim, check.claim_id).source_version_id)
            if version.content_sha256 is None:
                if check.outcome is not ClaimCheckOutcome.UNAVAILABLE:
                    raise _fail(
                        "G.check.no_content",
                        f"check {check.id} on version {version.id} without content",
                    )
            elif check.content_sha256 is not None and (
                check.content_sha256 != version.content_sha256
            ):
                raise _fail("G.check.hash", f"check {check.id} hash differs from {version.id}")
        _require_sequence("G.check.sequence", sequences, "check")
        for claim in self.claims:
            version = self.get(SourceVersion, claim.source_version_id)
            if version.authority is SourceAuthority.VERIFIED_IMPLEMENTATION and not (
                claim.locator.has(LocatorKind.PATH)
            ):
                raise _fail(
                    "G.claim.implementation_path",
                    f"claim {claim.id} on an implementation version needs a path locator",
                )

    def _check_uniqueness(self) -> None:
        unique: list[tuple[str, Iterable[object], str]] = [
            (
                "G.unique.evidence_link",
                ((link.decision_id, link.claim_id) for link in self.evidence_links),
                "evidence link (decision, claim)",
            ),
            (
                "G.unique.implementation_link",
                ((link.decision_id, link.symbol_id) for link in self.implementation_links),
                "implementation link (decision, symbol)",
            ),
            (
                "G.unique.verification_link",
                ((link.test_case_id, link.target) for link in self.verification_links),
                "verification link (test, target)",
            ),
            (
                "G.unique.source_pid",
                (
                    (source.persistent_id.scheme, source.persistent_id.value)
                    for source in self.sources
                ),
                "source persistent identifier",
            ),
            (
                "G.unique.version_label",
                ((version.source_id, version.version_label) for version in self.versions),
                "version label",
            ),
            (
                "G.unique.supersession",
                ((notice.superseded_version_id, notice.dimension) for notice in self.supersessions),
                "supersession (version, dimension)",
            ),
            (
                "G.unique.symbol",
                (
                    (symbol.revision_id, symbol.file_path, symbol.qualified_name)
                    for symbol in self.symbols
                ),
                "symbol (revision, path, name)",
            ),
            (
                "G.unique.test_node_id",
                (test.node_id for test in self.test_cases),
                "test node id",
            ),
        ]
        for rule, keys, what in unique:
            _require_unique(rule, keys, what)

    def _check_decision_supersession(self) -> None:
        targets = [d.supersedes_id for d in self.decisions if d.supersedes_id is not None]
        _require_unique("G.decision.supersession", targets, "superseded decision")
        successor_of = {d.id: d.supersedes_id for d in self.decisions}
        for start in successor_of:
            seen = {start}
            current = successor_of[start]
            while current is not None:
                if current in seen:
                    raise _fail("G.decision.supersession", f"supersession cycle at {start}")
                seen.add(current)
                current = successor_of.get(current)

    # ------------------------------------------------------------------ transition rules

    def _check_transition(
        self, record: ProvenanceRecord, earlier: Sequence[ProvenanceRecord]
    ) -> None:
        decision_id: str | None = None
        if isinstance(record, EvidenceLink | ImplementationLink | Approval | VerificationLink):
            decision_id = record.decision_id
        if isinstance(record, Approval):
            verdicts = [
                (item.sequence, item.verdict)
                for item in (*self.approvals, *earlier)
                if isinstance(item, Approval) and item.decision_id == record.decision_id
            ]
            if verdicts and max(verdicts)[1] is ApprovalVerdict.REJECTED:
                raise _fail(
                    "T.approval.after_rejection",
                    f"decision {record.decision_id} was rejected; supersede it instead",
                )
        if decision_id is not None and any(
            isinstance(item, ScientificDecision) and item.supersedes_id == decision_id
            for item in (*self.decisions, *earlier)
        ):
            raise _fail("T.decision.frozen", f"decision {decision_id} is superseded")
        if isinstance(record, Approval) and record.verdict is ApprovalVerdict.APPROVED:
            interim = self._with(earlier, self.revision) if earlier else self
            if interim.find(ScientificDecision, record.decision_id) is not None:
                _check_approval(interim, record)


def _check_approval(graph: ProvenanceGraph, approval: Approval) -> None:
    report = derive_status(graph, approval.decision_id)
    if report.status is DecisionStatus.APPROVED:
        raise _fail(
            "T.approval.redundant",
            f"decision {approval.decision_id} is already approved with the current evidence",
        )
    if approval.support_fingerprint != support_fingerprint(graph, approval.decision_id):
        raise _fail(
            "T.approval.fingerprint",
            f"approval fingerprint does not match the evidence of {approval.decision_id}",
        )
    if report.evidential_status in (DecisionStatus.PROPOSED, DecisionStatus.UNSUPPORTED):
        raise _fail(
            "T.approval.requires_support",
            f"decision {approval.decision_id} is {report.evidential_status.value}",
        )
    if (
        report.evidential_status is DecisionStatus.CONFLICTING
        and approval.conflict_resolution is None
    ):
        raise _fail(
            "T.approval.conflict_resolution",
            f"approving conflicting decision {approval.decision_id} needs a conflict_resolution",
        )
