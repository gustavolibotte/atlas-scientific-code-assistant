"""Hypothesis strategies and a replayable command language for provenance tests.

A command script is ``(is_synthetic, commands)``. Commands refer to earlier records by
index (taken modulo the number of records of that kind that exist in the replay), so the
same script can be replayed on any repository. Some generated commands are illegal on
purpose; ``replay`` requires that each illegal command raises
``ProvenanceInvariantError`` and leaves the project revision unchanged.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import timedelta

from hypothesis import strategies as st
from provenance_builders import make_service

from asca.application.demo import DEMO_TIME
from asca.application.provenance import (
    DecisionDraft,
    EnvironmentDraft,
    ProvenanceService,
    RunDraft,
    SourceDraft,
    SymbolDraft,
    VersionDraft,
)
from asca.domain.provenance import (
    AccessClass,
    Alternative,
    ApprovalVerdict,
    AssertionOrigin,
    Assumption,
    Claim,
    ClaimId,
    DecisionId,
    IdKind,
    Language,
    Locator,
    LocatorKind,
    LocatorPart,
    PackagePin,
    PersistentIdentifier,
    PidScheme,
    ProjectId,
    ProvenanceGraph,
    ProvenanceInvariantError,
    RevisionId,
    RunOrigin,
    SourceAuthority,
    SourceId,
    SourceVersionId,
    Stance,
    SupersessionDimension,
    SymbolId,
    SymbolKind,
    TestCaseId,
    TestKind,
    TestOutcome,
    TestResult,
)

# ---------------------------------------------------------------------- value strategies

_HEX = "0123456789abcdef"
_SLUG = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=12)


def ids(kind: IdKind) -> st.SearchStrategy[str]:
    return st.text(alphabet=_HEX, min_size=32, max_size=32).map(lambda body: f"{kind}_{body}")


def pid_value(scheme: PidScheme, n: int) -> str:
    """A deterministic, clearly fictional identifier value for ``scheme``."""
    values = {
        PidScheme.DOI: f"10.5555/asca-test.{n}",
        PidScheme.ARXIV: f"9912.{n % 100000:05d}",
        PidScheme.INSPIRE: str(900000000 + n),
        PidScheme.CDS_REPORT: f"ASCA-TEST-{n:04d}",
        PidScheme.CDS_RECORD: str(900000000 + n),
        PidScheme.GIT_REPOSITORY: f"https://example.org/asca-test/repo-{n}.git",
        PidScheme.URL: f"https://example.org/asca-test/doc-{n}",
        PidScheme.LOCAL_DOCUMENT: f"docs/asca-test/doc-{n}.md",
        PidScheme.SYNTHETIC: f"synthetic:asca-test-{n}",
    }
    return values[scheme]


def pids(scheme: PidScheme) -> st.SearchStrategy[PersistentIdentifier]:
    return st.integers(min_value=1, max_value=10**6).map(
        lambda n: PersistentIdentifier(scheme, pid_value(scheme, n))
    )


def single_line_text(max_size: int = 40) -> st.SearchStrategy[str]:
    return st.text(
        alphabet=st.characters(blacklist_categories=("Cs", "Cc", "Zl", "Zp")),
        min_size=1,
        max_size=max_size,
    ).filter(lambda value: value.strip() != "")


def multiline_text(max_size: int = 80) -> st.SearchStrategy[str]:
    return st.text(
        alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
        min_size=1,
        max_size=max_size,
    ).filter(lambda value: value.strip() != "")


def _locator_value(kind: LocatorKind) -> st.SearchStrategy[str]:
    if kind in (LocatorKind.PAGE, LocatorKind.LINE_RANGE):
        return st.tuples(
            st.integers(min_value=1, max_value=999), st.integers(min_value=0, max_value=50)
        ).map(lambda pair: f"{pair[0]}-{pair[0] + pair[1]}" if pair[1] else str(pair[0]))
    if kind is LocatorKind.PATH:
        return st.lists(_SLUG, min_size=1, max_size=3).map(lambda parts: "/".join(parts) + ".py")
    return single_line_text(20)


@st.composite
def locators(draw: st.DrawFn) -> Locator:
    kinds = draw(st.lists(st.sampled_from(LocatorKind), min_size=1, max_size=6, unique=True))
    return Locator(tuple(LocatorPart(kind, draw(_locator_value(kind))) for kind in kinds))


# ---------------------------------------------------------------------- command language


@dataclass(frozen=True)
class AddSource:
    scheme: PidScheme
    n: int


@dataclass(frozen=True)
class AddVersion:
    source: int
    label: int
    authority: SourceAuthority
    access: AccessClass
    text: int | None


@dataclass(frozen=True)
class Supersede:
    superseded: int
    superseding: int | None
    dimension: SupersessionDimension


@dataclass(frozen=True)
class AddClaim:
    version: int
    in_text: bool
    with_path: bool
    automated: bool


@dataclass(frozen=True)
class CheckClaim:
    claim: int
    correct_text: bool


@dataclass(frozen=True)
class MarkUnavailable:
    claim: int


@dataclass(frozen=True)
class ProposeDecision:
    access_floor: AccessClass
    supersedes: int | None
    details: bool = False


@dataclass(frozen=True)
class LinkEvidence:
    decision: int
    claim: int
    stance: Stance
    automated: bool


@dataclass(frozen=True)
class RecordRevision:
    indexed: bool
    symbols: tuple[tuple[int, int, int | None], ...]


@dataclass(frozen=True)
class LinkImplementation:
    decision: int
    symbol: int


@dataclass(frozen=True)
class RegisterTest:
    n: int
    kind: TestKind


@dataclass(frozen=True)
class LinkVerification:
    test: int
    target: int
    to_decision: bool


@dataclass(frozen=True)
class RecordRun:
    revision: int
    origin: RunOrigin
    environment: int
    start_minutes: int
    results: tuple[tuple[int, TestOutcome], ...]
    duration_minutes: int = 1


@dataclass(frozen=True)
class Review:
    decision: int
    verdict: ApprovalVerdict
    resolution: bool


Command = (
    AddSource
    | AddVersion
    | Supersede
    | AddClaim
    | CheckClaim
    | MarkUnavailable
    | ProposeDecision
    | LinkEvidence
    | RecordRevision
    | LinkImplementation
    | RegisterTest
    | LinkVerification
    | RecordRun
    | Review
)
Script = tuple[bool, tuple[Command, ...]]

_REF = st.integers(min_value=0, max_value=50)
_REAL_SCHEMES = st.sampled_from(
    [
        PidScheme.DOI,
        PidScheme.ARXIV,
        PidScheme.CDS_REPORT,
        PidScheme.GIT_REPOSITORY,
        PidScheme.URL,
        PidScheme.LOCAL_DOCUMENT,
    ]
)
_SYMBOL_NAMES = ("estimate", "subtract_pedestal", "Fitter.fit", "calibrate")
_SYMBOL_FILES = ("src/reco/a.py", "src/reco/b.py")


def _command_kinds(is_synthetic: bool) -> list[st.SearchStrategy[Command]]:
    """One strategy per command type, in a natural creation order."""
    scheme = (
        st.sampled_from([PidScheme.SYNTHETIC, PidScheme.SYNTHETIC, PidScheme.URL])
        if is_synthetic
        else _REAL_SCHEMES
    )
    authority = (
        st.sampled_from(
            [
                SourceAuthority.WORKING_MATERIAL,
                SourceAuthority.AUTOMATED_INFERENCE,
                SourceAuthority.PUBLISHED,
            ]
        )
        if is_synthetic
        else st.sampled_from(SourceAuthority)
    )
    origin = (
        st.sampled_from([RunOrigin.SYNTHETIC, RunOrigin.SYNTHETIC, RunOrigin.EXECUTED])
        if is_synthetic
        else st.sampled_from([RunOrigin.EXECUTED, RunOrigin.IMPORTED, RunOrigin.SYNTHETIC])
    )
    small = st.integers(min_value=0, max_value=6)
    return [
        st.builds(AddSource, scheme, small),
        st.builds(
            AddVersion,
            _REF,
            st.integers(min_value=0, max_value=3),
            authority,
            st.sampled_from(AccessClass),
            st.one_of(st.none(), small, small),
        ),
        st.builds(
            Supersede, _REF, st.one_of(st.none(), _REF), st.sampled_from(SupersessionDimension)
        ),
        st.builds(
            AddClaim, _REF, st.integers(0, 4).map(lambda n: n > 0), st.booleans(), st.booleans()
        ),
        st.builds(CheckClaim, _REF, st.integers(0, 5).map(lambda n: n > 0)),
        st.builds(MarkUnavailable, _REF),
        st.builds(
            ProposeDecision,
            st.sampled_from(AccessClass),
            st.one_of(st.none(), st.none(), _REF),
            st.booleans(),
        ),
        st.builds(LinkEvidence, _REF, _REF, st.sampled_from(Stance), st.booleans()),
        st.builds(
            RecordRevision,
            st.booleans(),
            st.lists(
                st.tuples(
                    st.integers(0, len(_SYMBOL_NAMES) - 1),
                    st.integers(0, len(_SYMBOL_FILES) - 1),
                    st.one_of(st.none(), st.integers(1, 4)),
                ),
                max_size=4,
            ).map(tuple),
        ),
        st.builds(LinkImplementation, _REF, _REF),
        st.builds(RegisterTest, small, st.sampled_from(TestKind)),
        st.builds(LinkVerification, _REF, _REF, st.booleans()),
        st.builds(
            RecordRun,
            _REF,
            origin,
            st.integers(0, 1),
            st.integers(0, 600),
            st.lists(st.tuples(_REF, st.sampled_from(TestOutcome)), min_size=1, max_size=3).map(
                tuple
            ),
            st.integers(0, 600),
        ),
        st.builds(Review, _REF, st.sampled_from(ApprovalVerdict), st.booleans()),
    ]


@st.composite
def evidence_chains(draw: st.DrawFn, is_synthetic: bool) -> tuple[Command, ...]:
    """An optional, legal evidence chain that reaches the interesting statuses.

    Random commands almost never line up a source, a version with text, an in-text
    claim, a correct check, a decision and a supporting link. The chain does, then may
    add a checked contradicting claim and a review, so supported, conflicting, approved
    and rejected decisions are generated. It comes first, so its records are index 0.
    """
    shape = draw(st.sampled_from(["none", "supported", "conflicting", "conflicting"]))
    if shape == "none":
        return ()
    scheme = PidScheme.SYNTHETIC if is_synthetic else draw(_REAL_SCHEMES)
    authority = draw(
        st.sampled_from(
            [SourceAuthority.WORKING_MATERIAL]
            if is_synthetic
            else [SourceAuthority.WORKING_MATERIAL, SourceAuthority.APPROVED_INTERNAL]
        )
    )
    chain: list[Command] = [
        AddSource(scheme, draw(st.integers(0, 6))),
        AddVersion(0, 0, authority, draw(st.sampled_from(AccessClass)), draw(st.integers(0, 6))),
        AddClaim(0, True, False, draw(st.booleans())),
        CheckClaim(0, True),
        ProposeDecision(AccessClass.PUBLIC, None, draw(st.booleans())),
        LinkEvidence(0, 0, Stance.SUPPORTS, draw(st.booleans())),
    ]
    if shape == "conflicting":
        chain += [
            AddClaim(0, True, False, False),
            CheckClaim(1, True),
            LinkEvidence(0, 1, Stance.CONTRADICTS, False),
        ]
    if is_synthetic:
        # A synthetic project cannot record approvals (G.synthetic.approvals).
        return tuple(chain)
    verdict = draw(
        st.sampled_from(
            [None, ApprovalVerdict.APPROVED, ApprovalVerdict.APPROVED, ApprovalVerdict.REJECTED]
        )
    )
    if verdict is ApprovalVerdict.APPROVED:
        # Approving a conflict needs a resolution (T.approval.conflict_resolution);
        # unresolved approvals still come from the random tail.
        chain.append(Review(0, verdict, shape == "conflicting" or draw(st.booleans())))
    elif verdict is ApprovalVerdict.REJECTED:
        # A rejection cannot carry a resolution (R.approval.resolution).
        chain.append(Review(0, verdict, False))
    return tuple(chain)


@st.composite
def command_scripts(draw: st.DrawFn, max_size: int = 20) -> Script:
    """An optional evidence chain, a creation-ordered prelude (0-2 commands per type)
    and a random tail."""
    is_synthetic = draw(st.booleans())
    kinds = _command_kinds(is_synthetic)
    commands: list[Command] = list(draw(evidence_chains(is_synthetic)))
    for kind in kinds:
        commands.extend(draw(st.lists(kind, max_size=2)))
    commands.extend(draw(st.lists(st.one_of(kinds), max_size=max_size)))
    return is_synthetic, tuple(commands)


# ---------------------------------------------------------------------- replay


@dataclass
class ReplayResult:
    project_id: ProjectId
    applied: int = 0
    skipped: int = 0
    rejected: list[str] = field(default_factory=list)
    sources: list[SourceId] = field(default_factory=list)
    versions: list[SourceVersionId] = field(default_factory=list)
    texts: dict[str, str] = field(default_factory=dict)
    claims: list[ClaimId] = field(default_factory=list)
    decisions: list[DecisionId] = field(default_factory=list)
    revisions: list[RevisionId] = field(default_factory=list)
    symbols: list[SymbolId] = field(default_factory=list)
    tests: list[TestCaseId] = field(default_factory=list)


class _SkipCommandError(Exception):
    """The command refers to a kind of record that does not exist yet."""


def _pick(items: Sequence[str], ref: int) -> str:
    if not items:
        raise _SkipCommandError
    return items[ref % len(items)]


def source_text(variant: int) -> str:
    return f"Fixture source text {variant}.\nThe measured value is {variant} units.\n"


def _environment(variant: int) -> EnvironmentDraft:
    return EnvironmentDraft(
        python_version="3.12.3",
        implementation="CPython",
        platform="Linux-x86_64",
        packages=(PackagePin("asca-fixture", f"0.{variant}.0"),),
    )


def _apply(command: Command, service: ProvenanceService, state: ReplayResult) -> None:
    pid = state.project_id
    if isinstance(command, AddSource):
        pid_obj = PersistentIdentifier(command.scheme, pid_value(command.scheme, command.n))
        state.sources.append(
            service.register_source(pid, SourceDraft(f"Fixture source {command.n}", pid_obj))
        )
    elif isinstance(command, AddVersion):
        source = SourceId(_pick(state.sources, command.source))
        label = (
            f"{command.label:040x}"
            if command.authority is SourceAuthority.VERIFIED_IMPLEMENTATION
            else f"v{command.label}"
        )
        text = None if command.text is None else source_text(command.text)
        version = service.add_source_version(
            pid,
            source,
            VersionDraft(
                label,
                command.authority,
                command.access,
                access_conditions=(
                    None if command.access is AccessClass.PUBLIC else "Fixture condition."
                ),
                authority_basis=(
                    "Fixture basis."
                    if command.authority is SourceAuthority.APPROVED_INTERNAL
                    else None
                ),
                content_text=text,
            ),
        )
        state.versions.append(version)
        if text is not None:
            state.texts[version] = text
    elif isinstance(command, Supersede):
        superseded = SourceVersionId(_pick(state.versions, command.superseded))
        superseding = (
            None
            if command.superseding is None
            else SourceVersionId(_pick(state.versions, command.superseding))
        )
        service.record_supersession(
            pid,
            superseded=superseded,
            superseding=superseding,
            dimension=command.dimension,
            reason="Fixture supersession.",
        )
    elif isinstance(command, AddClaim):
        version = SourceVersionId(_pick(state.versions, command.version))
        parts = [LocatorPart(LocatorKind.PARAGRAPH, "2")]
        if command.with_path:
            parts.append(LocatorPart(LocatorKind.PATH, "src/reco/a.py"))
        state.claims.append(
            service.add_claim(
                pid,
                version,
                quote="The measured value is" if command.in_text else "An absent sentence.",
                locator=Locator(tuple(parts)),
                extracted_by=(
                    AssertionOrigin.AUTOMATED if command.automated else AssertionOrigin.HUMAN
                ),
            )
        )
    elif isinstance(command, CheckClaim):
        claim = ClaimId(_pick(state.claims, command.claim))
        version_id = service.load(pid).get(Claim, claim).source_version_id
        text = state.texts.get(version_id, "No content.")
        service.check_claim_text(pid, claim, text if command.correct_text else text + " Tampered")
    elif isinstance(command, MarkUnavailable):
        claim = ClaimId(_pick(state.claims, command.claim))
        service.mark_claim_unavailable(pid, claim, reason="Fixture: text not retrievable.")
    elif isinstance(command, ProposeDecision):
        supersedes = (
            None
            if command.supersedes is None
            else DecisionId(_pick(state.decisions, command.supersedes))
        )
        n = len(state.decisions) + 1
        state.decisions.append(
            service.propose_decision(
                pid,
                DecisionDraft(
                    title=f"Fixture decision {n}",
                    statement=f"Fixture statement {n}.",
                    rationale="Fixture rationale.",
                    access_floor=command.access_floor,
                    supersedes_id=supersedes,
                    alternatives=(
                        (
                            Alternative(
                                f"Alternative {n}",
                                f"Fixture alternative {n}.",
                                f"Fixture reason not chosen {n}.",
                            ),
                        )
                        if command.details
                        else ()
                    ),
                    assumptions=(
                        (
                            Assumption(f"Fixture assumption {n}.", f"Fixture justification {n}."),
                            Assumption(f"Unjustified fixture assumption {n}.", None),
                        )
                        if command.details
                        else ()
                    ),
                ),
            )
        )
    elif isinstance(command, LinkEvidence):
        decision = DecisionId(_pick(state.decisions, command.decision))
        claim = ClaimId(_pick(state.claims, command.claim))
        service.link_evidence(
            pid,
            decision,
            claim,
            command.stance,
            asserted_by=AssertionOrigin.AUTOMATED if command.automated else AssertionOrigin.HUMAN,
        )
    elif isinstance(command, RecordRevision):
        recorded = service.record_workspace_revision(
            pid,
            vcs_ref=None,
            symbols=[
                SymbolDraft(
                    Language.PYTHON,
                    SymbolKind.FUNCTION,
                    _SYMBOL_NAMES[name],
                    _SYMBOL_FILES[path],
                    None,
                    None if fp is None else f"{fp:064x}",
                )
                for name, path, fp in command.symbols
            ],
            symbols_indexed=command.indexed,
        )
        state.revisions.append(recorded.revision_id)
        state.symbols.extend(recorded.symbol_ids)
    elif isinstance(command, LinkImplementation):
        decision = DecisionId(_pick(state.decisions, command.decision))
        symbol = SymbolId(_pick(state.symbols, command.symbol))
        service.link_implementation(pid, decision, symbol)
    elif isinstance(command, RegisterTest):
        state.tests.append(
            service.register_test_case(
                pid,
                node_id=f"tests/test_fixture_{command.n}.py::test_case",
                kind=command.kind,
                description="Fixture test.",
            )
        )
    elif isinstance(command, LinkVerification):
        test = TestCaseId(_pick(state.tests, command.test))
        if command.to_decision:
            target = DecisionId(_pick(state.decisions, command.target))
            service.link_verification(pid, test, decision_id=target)
        else:
            symbol = SymbolId(_pick(state.symbols, command.target))
            service.link_verification(pid, test, symbol_id=symbol)
    elif isinstance(command, RecordRun):
        revision = RevisionId(_pick(state.revisions, command.revision))
        results: dict[str, TestOutcome] = {}
        for ref, outcome in command.results:
            results[_pick(state.tests, ref)] = outcome
        start = DEMO_TIME + timedelta(minutes=command.start_minutes)
        service.record_validation_run(
            pid,
            RunDraft(
                revision_id=revision,
                environment=_environment(command.environment),
                origin=command.origin,
                started_at=start,
                finished_at=start + timedelta(minutes=command.duration_minutes),
                results=tuple(
                    TestResult(TestCaseId(test), outcome, 0.1, None)
                    for test, outcome in results.items()
                ),
            ),
        )
    else:
        decision = DecisionId(_pick(state.decisions, command.decision))
        service.review_decision(
            pid,
            decision,
            command.verdict,
            reviewer="Fixture reviewer",
            rationale="Fixture review.",
            conflict_resolution="Fixture resolution." if command.resolution else None,
        )


def replay(script: Script, service: ProvenanceService) -> ReplayResult:
    """Replay ``script``; illegal commands must raise and leave the revision unchanged."""
    is_synthetic, commands = script
    project_id = service.create_project("Fixture replay project", is_synthetic=is_synthetic)
    state = ReplayResult(project_id=project_id)
    for command in commands:
        before = service.load(project_id).revision
        try:
            _apply(command, service, state)
        except _SkipCommandError:
            state.skipped += 1
        except ProvenanceInvariantError as error:
            assert service.load(project_id).revision == before, error.rule
            state.rejected.append(error.rule)
        else:
            state.applied += 1
            assert service.load(project_id).revision == before + 1
    return state


@st.composite
def valid_graphs(draw: st.DrawFn, max_size: int = 20) -> ProvenanceGraph:
    """A graph produced by replaying a random script on the in-memory repository."""
    script = draw(command_scripts(max_size=max_size))
    service = make_service()
    result = replay(script, service)
    return service.load(result.project_id)
