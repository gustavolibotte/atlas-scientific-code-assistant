"""Provenance write and load use cases.

The service only writes and loads. Every write loads the project graph, builds new
records, lets the domain check them with ``ProvenanceGraph.append`` and then stores them
with a compare-and-set on the loaded revision. Statuses, sequences, fingerprints and
hashes are always computed here, never taken from the caller.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta

from asca.application.ports import Clock, IdFactory, ProjectSummary, ProvenanceRepository
from asca.domain.provenance import (
    AccessClass,
    Alternative,
    Approval,
    ApprovalId,
    ApprovalVerdict,
    AssertionOrigin,
    Assumption,
    Claim,
    ClaimCheckId,
    ClaimId,
    ClaimVerificationState,
    CodeSymbol,
    DecisionId,
    EnvironmentSnapshot,
    EvidenceLink,
    EvidenceLinkId,
    FileIssue,
    FingerprintAlgorithm,
    IdKind,
    ImplementationLink,
    ImplementationLinkId,
    Language,
    Locator,
    PackagePin,
    PersistentIdentifier,
    Project,
    ProjectId,
    ProvenanceGraph,
    ProvenanceInvariantError,
    ProvenanceRecord,
    RevisionId,
    RunId,
    RunOrigin,
    ScientificDecision,
    Source,
    SourceAuthority,
    SourceId,
    SourceSpan,
    SourceVersion,
    SourceVersionId,
    Stance,
    SupersessionDimension,
    SupersessionId,
    SupersessionNotice,
    SymbolId,
    SymbolKind,
    TestCase,
    TestCaseId,
    TestKind,
    TestResult,
    ValidationRun,
    VerificationLink,
    VerificationLinkId,
    WorkspaceRevision,
    check_quote,
    environment_id_for,
    sha256_text,
    support_fingerprint,
    unavailable_check,
)


@dataclass(frozen=True, slots=True)
class SourceDraft:
    title: str
    persistent_id: PersistentIdentifier


@dataclass(frozen=True, slots=True)
class VersionDraft:
    version_label: str
    authority: SourceAuthority
    access_class: AccessClass
    access_conditions: str | None = None
    authority_basis: str | None = None
    content_text: str | None = None
    """Hashed only; never persisted in M1."""
    published_on: date | None = None
    retrieved_at: datetime | None = None
    """When ``content_text`` was retrieved; requires it; an aware UTC time not in the future."""


@dataclass(frozen=True, slots=True)
class DecisionDraft:
    title: str
    statement: str
    rationale: str
    alternatives: tuple[Alternative, ...] = ()
    assumptions: tuple[Assumption, ...] = ()
    access_floor: AccessClass = AccessClass.PUBLIC
    supersedes_id: DecisionId | None = None


@dataclass(frozen=True, slots=True)
class SymbolDraft:
    language: Language
    kind: SymbolKind
    qualified_name: str
    file_path: str
    span: SourceSpan | None = None
    fingerprint: str | None = None
    fingerprint_algorithm: FingerprintAlgorithm | None = None


@dataclass(frozen=True, slots=True)
class EnvironmentDraft:
    python_version: str
    implementation: str
    platform: str
    packages: tuple[PackagePin, ...]


@dataclass(frozen=True, slots=True)
class RunDraft:
    revision_id: RevisionId
    environment: EnvironmentDraft
    origin: RunOrigin
    started_at: datetime
    finished_at: datetime
    results: tuple[TestResult, ...]


@dataclass(frozen=True, slots=True)
class RecordedRevision:
    revision_id: RevisionId
    symbol_ids: tuple[SymbolId, ...]
    sequence: int


class ProvenanceService:
    def __init__(self, repository: ProvenanceRepository, clock: Clock, ids: IdFactory) -> None:
        self._repository = repository
        self._clock = clock
        self._ids = ids

    # ------------------------------------------------------------------ helpers

    def _commit(self, graph: ProvenanceGraph, records: Sequence[ProvenanceRecord]) -> None:
        graph.append(records)
        self._repository.append(graph.project.id, graph.revision, records)

    def _new(self, kind: IdKind) -> str:
        return self._ids.new(kind)

    # ------------------------------------------------------------------ reads

    def load(self, project_id: ProjectId) -> ProvenanceGraph:
        return self._repository.load(project_id)

    def list_projects(self) -> list[ProjectSummary]:
        return self._repository.list_projects()

    # ------------------------------------------------------------------ writes

    def create_project(self, title: str, *, is_synthetic: bool) -> ProjectId:
        project = Project(
            id=ProjectId(self._new(IdKind.PROJECT)),
            title=title,
            is_synthetic=is_synthetic,
            created_at=self._clock.now(),
        )
        self._repository.create_project(project)
        return project.id

    def register_source(self, project_id: ProjectId, draft: SourceDraft) -> SourceId:
        graph = self.load(project_id)
        source = Source(
            id=SourceId(self._new(IdKind.SOURCE)),
            project_id=project_id,
            title=draft.title,
            persistent_id=draft.persistent_id,
            created_at=self._clock.now(),
        )
        self._commit(graph, [source])
        return source.id

    def _version(
        self, project_id: ProjectId, source_id: SourceId, draft: VersionDraft, now: datetime
    ) -> SourceVersion:
        retrieved_at: datetime | None = None
        if draft.content_text is not None:
            retrieved_at = now if draft.retrieved_at is None else draft.retrieved_at
        if draft.retrieved_at is not None and (
            draft.content_text is None
            or not isinstance(draft.retrieved_at, datetime)
            or draft.retrieved_at.tzinfo is None
            or draft.retrieved_at.utcoffset() != timedelta(0)
            or draft.retrieved_at > now
        ):
            raise ProvenanceInvariantError(
                "R.draft.retrieved_at",
                "retrieved_at requires content_text and must be a past UTC time",
            )
        return SourceVersion(
            id=SourceVersionId(self._new(IdKind.SOURCE_VERSION)),
            project_id=project_id,
            source_id=source_id,
            version_label=draft.version_label,
            authority=draft.authority,
            access_class=draft.access_class,
            access_conditions=draft.access_conditions,
            authority_basis=draft.authority_basis,
            content_sha256=(
                sha256_text(draft.content_text) if draft.content_text is not None else None
            ),
            retrieved_at=retrieved_at,
            published_on=draft.published_on,
            recorded_at=now,
        )

    def add_source_version(
        self, project_id: ProjectId, source_id: SourceId, draft: VersionDraft
    ) -> SourceVersionId:
        graph = self.load(project_id)
        version = self._version(project_id, source_id, draft, self._clock.now())
        self._commit(graph, [version])
        return version.id

    def record_source_version(
        self,
        project_id: ProjectId,
        source: SourceDraft | SourceId,
        version: VersionDraft,
    ) -> tuple[SourceId, SourceVersionId]:
        """Create or reuse a source and append the version, all in one commit."""
        graph = self.load(project_id)
        now = self._clock.now()
        records: list[ProvenanceRecord] = []
        if isinstance(source, SourceDraft):
            created = Source(
                id=SourceId(self._new(IdKind.SOURCE)),
                project_id=project_id,
                title=source.title,
                persistent_id=source.persistent_id,
                created_at=now,
            )
            records.append(created)
            source_id = created.id
        else:
            source_id = source
        record = self._version(project_id, source_id, version, now)
        records.append(record)
        self._commit(graph, records)
        return source_id, record.id

    def record_supersession(
        self,
        project_id: ProjectId,
        *,
        superseded: SourceVersionId,
        superseding: SourceVersionId | None,
        dimension: SupersessionDimension,
        reason: str,
    ) -> SupersessionId:
        graph = self.load(project_id)
        notice = SupersessionNotice(
            id=SupersessionId(self._new(IdKind.SUPERSESSION)),
            project_id=project_id,
            superseded_version_id=superseded,
            superseding_version_id=superseding,
            dimension=dimension,
            reason=reason,
            recorded_at=self._clock.now(),
        )
        self._commit(graph, [notice])
        return notice.id

    def add_claim(
        self,
        project_id: ProjectId,
        version_id: SourceVersionId,
        *,
        quote: str,
        locator: Locator,
        statement: str | None = None,
        extracted_by: AssertionOrigin = AssertionOrigin.HUMAN,
    ) -> ClaimId:
        graph = self.load(project_id)
        claim = Claim(
            id=ClaimId(self._new(IdKind.CLAIM)),
            project_id=project_id,
            source_version_id=version_id,
            quote=quote,
            locator=locator,
            statement=statement,
            extracted_by=extracted_by,
            recorded_at=self._clock.now(),
        )
        self._commit(graph, [claim])
        return claim.id

    def check_claim_text(
        self, project_id: ProjectId, claim_id: ClaimId, text: str
    ) -> ClaimVerificationState:
        """Check the quote against caller-supplied text whose hash matches the version."""
        graph = self.load(project_id)
        claim = graph.get(Claim, claim_id)
        version = graph.get(SourceVersion, claim.source_version_id)
        check = check_quote(
            claim,
            version,
            text,
            check_id=ClaimCheckId(self._new(IdKind.CLAIM_CHECK)),
            sequence=graph.next_check_sequence(claim.id),
            checked_at=self._clock.now(),
        )
        self._commit(graph, [check])
        return check.state

    def mark_claim_unavailable(
        self, project_id: ProjectId, claim_id: ClaimId, *, reason: str
    ) -> ClaimVerificationState:
        graph = self.load(project_id)
        claim = graph.get(Claim, claim_id)
        check = unavailable_check(
            claim.id,
            reason=reason,
            check_id=ClaimCheckId(self._new(IdKind.CLAIM_CHECK)),
            sequence=graph.next_check_sequence(claim.id),
            checked_at=self._clock.now(),
            project_id=project_id,
        )
        self._commit(graph, [check])
        return check.state

    def propose_decision(self, project_id: ProjectId, draft: DecisionDraft) -> DecisionId:
        graph = self.load(project_id)
        decision = ScientificDecision(
            id=DecisionId(self._new(IdKind.DECISION)),
            project_id=project_id,
            title=draft.title,
            statement=draft.statement,
            rationale=draft.rationale,
            alternatives=draft.alternatives,
            assumptions=draft.assumptions,
            access_floor=draft.access_floor,
            supersedes_id=draft.supersedes_id,
            created_at=self._clock.now(),
        )
        self._commit(graph, [decision])
        return decision.id

    def link_evidence(
        self,
        project_id: ProjectId,
        decision_id: DecisionId,
        claim_id: ClaimId,
        stance: Stance,
        *,
        asserted_by: AssertionOrigin = AssertionOrigin.HUMAN,
        note: str | None = None,
    ) -> EvidenceLinkId:
        graph = self.load(project_id)
        link = EvidenceLink(
            id=EvidenceLinkId(self._new(IdKind.EVIDENCE_LINK)),
            project_id=project_id,
            decision_id=decision_id,
            claim_id=claim_id,
            stance=stance,
            asserted_by=asserted_by,
            note=note,
            created_at=self._clock.now(),
        )
        self._commit(graph, [link])
        return link.id

    def record_workspace_revision(
        self,
        project_id: ProjectId,
        *,
        vcs_ref: str | None,
        symbols: Sequence[SymbolDraft],
        symbols_indexed: bool,
        file_issues: Sequence[FileIssue] = (),
        source_digest: str | None = None,
    ) -> RecordedRevision:
        """Record a revision, its file issues and all its symbols in one batch."""
        graph = self.load(project_id)
        revision = WorkspaceRevision(
            id=RevisionId(self._new(IdKind.WORKSPACE_REVISION)),
            project_id=project_id,
            sequence=graph.next_revision_sequence(),
            vcs_ref=vcs_ref,
            symbols_indexed=symbols_indexed,
            recorded_at=self._clock.now(),
            file_issues=tuple(sorted(file_issues, key=lambda issue: issue.file_path)),
            source_digest=source_digest,
        )
        records: list[ProvenanceRecord] = [revision]
        for draft in symbols:
            records.append(
                CodeSymbol(
                    id=SymbolId(self._new(IdKind.SYMBOL)),
                    project_id=project_id,
                    revision_id=revision.id,
                    language=draft.language,
                    kind=draft.kind,
                    qualified_name=draft.qualified_name,
                    file_path=draft.file_path,
                    span=draft.span,
                    fingerprint=draft.fingerprint,
                    fingerprint_algorithm=draft.fingerprint_algorithm,
                )
            )
        self._commit(graph, records)
        return RecordedRevision(
            revision_id=revision.id,
            symbol_ids=tuple(record.id for record in records if isinstance(record, CodeSymbol)),
            sequence=revision.sequence,
        )

    def link_implementation(
        self, project_id: ProjectId, decision_id: DecisionId, symbol_id: SymbolId
    ) -> ImplementationLinkId:
        graph = self.load(project_id)
        link = ImplementationLink(
            id=ImplementationLinkId(self._new(IdKind.IMPLEMENTATION_LINK)),
            project_id=project_id,
            decision_id=decision_id,
            symbol_id=symbol_id,
            created_at=self._clock.now(),
        )
        self._commit(graph, [link])
        return link.id

    def register_test_case(
        self, project_id: ProjectId, *, node_id: str, kind: TestKind, description: str
    ) -> TestCaseId:
        graph = self.load(project_id)
        test = TestCase(
            id=TestCaseId(self._new(IdKind.TEST_CASE)),
            project_id=project_id,
            node_id=node_id,
            kind=kind,
            description=description,
            created_at=self._clock.now(),
        )
        self._commit(graph, [test])
        return test.id

    def link_verification(
        self,
        project_id: ProjectId,
        test_case_id: TestCaseId,
        *,
        decision_id: DecisionId | None = None,
        symbol_id: SymbolId | None = None,
    ) -> VerificationLinkId:
        graph = self.load(project_id)
        link = VerificationLink(
            id=VerificationLinkId(self._new(IdKind.VERIFICATION_LINK)),
            project_id=project_id,
            test_case_id=test_case_id,
            decision_id=decision_id,
            symbol_id=symbol_id,
            created_at=self._clock.now(),
        )
        self._commit(graph, [link])
        return link.id

    def record_validation_run(self, project_id: ProjectId, draft: RunDraft) -> RunId:
        """Record a run; its environment snapshot is added only when it is new."""
        graph = self.load(project_id)
        env = draft.environment
        environment_id = environment_id_for(
            project_id, env.python_version, env.implementation, env.platform, env.packages
        )
        records: list[ProvenanceRecord] = []
        if graph.find(EnvironmentSnapshot, environment_id) is None:
            records.append(
                EnvironmentSnapshot(
                    id=environment_id,
                    project_id=project_id,
                    python_version=env.python_version,
                    implementation=env.implementation,
                    platform=env.platform,
                    packages=env.packages,
                )
            )
        run = ValidationRun(
            id=RunId(self._new(IdKind.RUN)),
            project_id=project_id,
            revision_id=draft.revision_id,
            environment_id=environment_id,
            origin=draft.origin,
            started_at=draft.started_at,
            finished_at=draft.finished_at,
            results=draft.results,
        )
        records.append(run)
        self._commit(graph, records)
        return run.id

    def review_decision(
        self,
        project_id: ProjectId,
        decision_id: DecisionId,
        verdict: ApprovalVerdict,
        *,
        reviewer: str,
        rationale: str,
        conflict_resolution: str | None = None,
    ) -> ApprovalId:
        """Record a review; sequence and fingerprint come from the loaded graph."""
        graph = self.load(project_id)
        approval = Approval(
            id=ApprovalId(self._new(IdKind.APPROVAL)),
            project_id=project_id,
            decision_id=decision_id,
            sequence=graph.next_approval_sequence(decision_id),
            verdict=verdict,
            reviewer=reviewer,
            rationale=rationale,
            conflict_resolution=conflict_resolution,
            support_fingerprint=support_fingerprint(graph, decision_id),
            reviewed_at=self._clock.now(),
        )
        self._commit(graph, [approval])
        return approval.id
