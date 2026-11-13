"""Graph state invariants (``G.*``) and transition rules (``T.*``)."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from provenance_builders import (
    CompleteProject,
    build_complete_real_project,
    make_service,
    with_records,
)
from provenance_strategies import ids, pid_value

from asca.application.demo import DEMO_PROJECT_ID, DEMO_TIME, seed_synthetic_demo
from asca.domain.provenance import (
    PUBLISHED_PID_SCHEMES,
    RECORD_FIELDS,
    AccessClass,
    Approval,
    ApprovalId,
    ApprovalVerdict,
    AssertionOrigin,
    CheckMethod,
    Claim,
    ClaimCheck,
    ClaimCheckOutcome,
    CodeSymbol,
    DecisionStatus,
    EnvironmentSnapshot,
    EvidenceLink,
    FileIssue,
    FileIssueKind,
    IdKind,
    ImplementationLink,
    Locator,
    LocatorKind,
    LocatorPart,
    PersistentIdentifier,
    PidScheme,
    Project,
    ProjectId,
    ProvenanceGraph,
    ProvenanceInvariantError,
    RecordNotFoundError,
    RunOrigin,
    ScientificDecision,
    Source,
    SourceAuthority,
    SourceVersion,
    Stance,
    SupersessionNotice,
    TestCase,
    TestOutcome,
    TestResult,
    ValidationRun,
    VerificationLink,
    WorkspaceRevision,
    derive_status,
    environment_id_for,
    make_id,
    support_fingerprint,
)
from asca.infrastructure.memory_provenance import InMemoryProvenanceRepository

pytestmark = pytest.mark.unit


def fresh(kind: IdKind, n: int) -> str:
    return make_id(kind, f"{0xFEED0000 + n:032x}")


def _rule(call: object) -> str:
    assert callable(call)
    with pytest.raises(ProvenanceInvariantError) as error:
        call()
    return error.value.rule


@pytest.fixture(scope="module")
def complete() -> tuple[ProvenanceGraph, CompleteProject]:
    service = make_service()
    names = build_complete_real_project(service)
    return service.load(names.project), names


@pytest.fixture(scope="module")
def demo() -> ProvenanceGraph:
    repository = InMemoryProvenanceRepository()
    seed_synthetic_demo(repository)
    return repository.load(DEMO_PROJECT_ID)


def swap(graph: ProvenanceGraph, old: object, new: object) -> ProvenanceGraph:
    name = RECORD_FIELDS[type(old)]
    items = tuple(new if item is old else item for item in getattr(graph, name))
    return replace(graph, **{name: items})


# ---------------------------------------------------------------------- references

REFERENCES: list[tuple[type[object], str, IdKind]] = [
    (SourceVersion, "source_id", IdKind.SOURCE),
    (SupersessionNotice, "superseded_version_id", IdKind.SOURCE_VERSION),
    (SupersessionNotice, "superseding_version_id", IdKind.SOURCE_VERSION),
    (Claim, "source_version_id", IdKind.SOURCE_VERSION),
    (ClaimCheck, "claim_id", IdKind.CLAIM),
    (ScientificDecision, "supersedes_id", IdKind.DECISION),
    (EvidenceLink, "decision_id", IdKind.DECISION),
    (EvidenceLink, "claim_id", IdKind.CLAIM),
    (CodeSymbol, "revision_id", IdKind.WORKSPACE_REVISION),
    (ImplementationLink, "decision_id", IdKind.DECISION),
    (ImplementationLink, "symbol_id", IdKind.SYMBOL),
    (VerificationLink, "test_case_id", IdKind.TEST_CASE),
    (ValidationRun, "revision_id", IdKind.WORKSPACE_REVISION),
    (ValidationRun, "environment_id", IdKind.ENVIRONMENT),
    (Approval, "decision_id", IdKind.DECISION),
]


@settings(max_examples=100, deadline=None)
@given(st.data())
def test_replacing_any_reference_with_a_fresh_id_is_dangling(
    complete: tuple[ProvenanceGraph, CompleteProject], data: st.DataObject
) -> None:
    graph, _ = complete
    record_type, field_name, kind = data.draw(st.sampled_from(REFERENCES))
    records = getattr(graph, RECORD_FIELDS[record_type])
    record = data.draw(st.sampled_from(records))
    new_id = data.draw(ids(kind).filter(lambda value: graph.find(object, value) is None))
    assert _rule(lambda: swap(graph, record, replace(record, **{field_name: new_id}))) == (
        "G.dangling"
    )


@settings(max_examples=100, deadline=None)
@given(st.data())
def test_dangling_nested_and_optional_references(
    complete: tuple[ProvenanceGraph, CompleteProject], data: st.DataObject
) -> None:
    graph, _ = complete
    new_test = data.draw(ids(IdKind.TEST_CASE))
    run = graph.runs[0]
    results = (replace(run.results[0], test_case_id=new_test), *run.results[1:])
    assert _rule(lambda: swap(graph, run, replace(run, results=results))) == "G.dangling"
    link = data.draw(st.sampled_from(graph.verification_links))
    if link.decision_id is not None:
        broken = replace(link, decision_id=data.draw(ids(IdKind.DECISION)))
    else:
        broken = replace(link, symbol_id=data.draw(ids(IdKind.SYMBOL)))
    assert _rule(lambda: swap(graph, link, broken)) == "G.dangling"


def test_duplicate_id_and_project_scope(complete: tuple[ProvenanceGraph, CompleteProject]) -> None:
    graph, _ = complete
    claim = graph.claims[0]
    assert _rule(lambda: with_records(graph, replace(claim, quote="Other."))) == "G.duplicate_id"
    foreign = replace(claim, id=fresh(IdKind.CLAIM, 1), project_id=ProjectId("prj_" + "9" * 32))
    assert _rule(lambda: with_records(graph, foreign)) == "G.project_scope"


def test_record_types_are_checked(complete: tuple[ProvenanceGraph, CompleteProject]) -> None:
    graph, _ = complete
    assert _rule(lambda: replace(graph, claims=(graph.sources[0],))) == "G.record_type"
    assert _rule(lambda: replace(graph, project="project")) == "G.record_type"
    assert _rule(lambda: replace(graph, revision=-1)) == "R.int.range"
    assert _rule(lambda: graph.append(["not a record"])) == "G.record_type"  # type: ignore[list-item]
    assert replace(graph, claims=list(graph.claims)) == graph  # type: ignore[arg-type]


# ---------------------------------------------------------------------- synthetic rules


def test_synthetic_source_rules(
    complete: tuple[ProvenanceGraph, CompleteProject], demo: ProvenanceGraph
) -> None:
    graph, _ = complete
    synthetic_source = replace(
        demo.sources[0], id=fresh(IdKind.SOURCE, 2), project_id=graph.project.id
    )
    assert _rule(lambda: with_records(graph, synthetic_source)) == "G.synthetic.sources"
    real_source = replace(graph.sources[0], id=fresh(IdKind.SOURCE, 3), project_id=demo.project.id)
    assert _rule(lambda: with_records(demo, real_source)) == "G.synthetic.sources"


def _environment(project_id: ProjectId) -> EnvironmentSnapshot:
    env_id = environment_id_for(project_id, "3.12.3", "CPython", "Linux", ())
    return EnvironmentSnapshot(env_id, project_id, "3.12.3", "CPython", "Linux", ())


def test_synthetic_run_rules(
    complete: tuple[ProvenanceGraph, CompleteProject], demo: ProvenanceGraph
) -> None:
    graph, _ = complete
    synthetic_run = replace(graph.runs[0], id=fresh(IdKind.RUN, 4), origin=RunOrigin.SYNTHETIC)
    assert _rule(lambda: with_records(graph, synthetic_run)) == "G.synthetic.runs"
    environment = _environment(demo.project.id)
    run = ValidationRun(
        fresh(IdKind.RUN, 5),
        demo.project.id,
        demo.revisions[0].id,
        environment.id,
        RunOrigin.EXECUTED,
        DEMO_TIME,
        DEMO_TIME,
        (TestResult(demo.test_cases[0].id, TestOutcome.PASSED, None, None),),
    )
    assert _rule(lambda: with_records(demo, environment, run)) == "G.synthetic.runs"
    synthetic = with_records(demo, environment, replace(run, origin=RunOrigin.SYNTHETIC))
    assert len(synthetic.runs) == 1


def test_synthetic_projects_cannot_have_approvals(demo: ProvenanceGraph) -> None:
    decision = demo.decisions[0]
    approval = Approval(
        fresh(IdKind.APPROVAL, 6),
        demo.project.id,
        decision.id,
        1,
        ApprovalVerdict.REJECTED,
        "Fixture reviewer",
        "Fixture.",
        None,
        support_fingerprint(demo, decision.id),
        DEMO_TIME,
    )
    assert _rule(lambda: with_records(demo, approval)) == "G.synthetic.approvals"
    assert _rule(lambda: demo.append([approval])) == "G.synthetic.approvals"


# ---------------------------------------------------------------------- authority rules


def _single_version_graph(
    scheme: PidScheme, authority: SourceAuthority, *, synthetic: bool, n: int = 1
) -> ProvenanceGraph:
    project = Project(ProjectId(fresh(IdKind.PROJECT, 0)), "Fixture", synthetic, DEMO_TIME)
    source = Source(
        fresh(IdKind.SOURCE, 0),
        project.id,
        "Fixture",
        PersistentIdentifier(scheme, pid_value(scheme, n)),
        DEMO_TIME,
    )
    version = SourceVersion(
        fresh(IdKind.SOURCE_VERSION, 0),
        project.id,
        source.id,
        "a" * 40,
        authority,
        AccessClass.PUBLIC,
        None,
        "Fixture basis." if authority is SourceAuthority.APPROVED_INTERNAL else None,
        None,
        None,
        None,
        DEMO_TIME,
    )
    return ProvenanceGraph(project, 2, sources=(source,), versions=(version,))


@settings(max_examples=100)
@given(st.sampled_from(sorted(set(PidScheme) - PUBLISHED_PID_SCHEMES)), st.integers(1, 10**6))
def test_published_needs_a_published_identifier(scheme: PidScheme, n: int) -> None:
    synthetic = scheme is PidScheme.SYNTHETIC
    rule = _rule(
        lambda: _single_version_graph(scheme, SourceAuthority.PUBLISHED, synthetic=synthetic, n=n)
    )
    assert rule == "G.authority.published_pid"


@pytest.mark.parametrize("scheme", sorted(PUBLISHED_PID_SCHEMES))
def test_published_identifier_schemes_are_accepted(scheme: PidScheme) -> None:
    graph = _single_version_graph(scheme, SourceAuthority.PUBLISHED, synthetic=False)
    assert graph.versions[0].authority is SourceAuthority.PUBLISHED


def test_implementation_and_synthetic_authority_rules() -> None:
    assert (
        _rule(
            lambda: _single_version_graph(
                PidScheme.URL, SourceAuthority.VERIFIED_IMPLEMENTATION, synthetic=False
            )
        )
        == "G.authority.implementation_pid"
    )
    assert _single_version_graph(
        PidScheme.GIT_REPOSITORY, SourceAuthority.VERIFIED_IMPLEMENTATION, synthetic=False
    )
    assert (
        _rule(
            lambda: _single_version_graph(
                PidScheme.SYNTHETIC, SourceAuthority.APPROVED_INTERNAL, synthetic=True
            )
        )
        == "G.authority.synthetic"
    )


# ---------------------------------------------------------------------- check and claim rules


def test_check_rules(complete: tuple[ProvenanceGraph, CompleteProject]) -> None:
    graph, names = complete
    check = graph.checks_for(names.journal_claim)[0]
    assert _rule(lambda: swap(graph, check, replace(check, sequence=2))) == "G.check.sequence"
    assert _rule(lambda: swap(graph, check, replace(check, content_sha256="0" * 64))) == (
        "G.check.hash"
    )
    on_empty = ClaimCheck(
        fresh(IdKind.CLAIM_CHECK, 7),
        graph.project.id,
        names.working_claim,
        1,
        ClaimCheckOutcome.SOURCE_TEXT_CHECKED,
        CheckMethod.NORMALIZED_SUBSTRING,
        "0" * 64,
        None,
        DEMO_TIME,
    )
    assert _rule(lambda: with_records(graph, on_empty)) == "G.check.no_content"
    unavailable = replace(
        on_empty,
        outcome=ClaimCheckOutcome.UNAVAILABLE,
        method=CheckMethod.NOT_PERFORMED,
        content_sha256=None,
        detail="Fixture.",
    )
    assert with_records(graph, unavailable).claim_state(names.working_claim).value == (
        "unavailable"
    )


def test_implementation_claims_need_a_path(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    claim = graph.get(Claim, names.implementation_claim)
    pathless = replace(claim, locator=Locator((LocatorPart(LocatorKind.LINE_RANGE, "2"),)))
    assert _rule(lambda: swap(graph, claim, pathless)) == "G.claim.implementation_path"


# ---------------------------------------------------------------------- uniqueness


def test_uniqueness_rules(complete: tuple[ProvenanceGraph, CompleteProject]) -> None:
    graph, _ = complete
    cases: list[tuple[object, str]] = [
        (replace(graph.evidence_links[0], id=fresh(IdKind.EVIDENCE_LINK, 1)), "evidence_link"),
        (
            replace(graph.implementation_links[0], id=fresh(IdKind.IMPLEMENTATION_LINK, 1)),
            "implementation_link",
        ),
        (
            replace(graph.verification_links[0], id=fresh(IdKind.VERIFICATION_LINK, 1)),
            "verification_link",
        ),
        (replace(graph.sources[0], id=fresh(IdKind.SOURCE, 1)), "source_pid"),
        (replace(graph.versions[0], id=fresh(IdKind.SOURCE_VERSION, 1)), "version_label"),
        (replace(graph.supersessions[0], id=fresh(IdKind.SUPERSESSION, 1)), "supersession"),
        (replace(graph.symbols[0], id=fresh(IdKind.SYMBOL, 1)), "symbol"),
        (replace(graph.test_cases[0], id=fresh(IdKind.TEST_CASE, 1)), "test_node_id"),
    ]
    for record, rule in cases:
        assert _rule(lambda record=record: with_records(graph, record)) == f"G.unique.{rule}"


# ---------------------------------------------------------------------- decision supersession


def test_decision_supersession_rules(complete: tuple[ProvenanceGraph, CompleteProject]) -> None:
    graph, names = complete
    df = graph.get(ScientificDecision, names.df)
    double = replace(df, id=fresh(IdKind.DECISION, 1))
    assert _rule(lambda: with_records(graph, double)) == "G.decision.supersession"
    dc = graph.get(ScientificDecision, names.dc)
    assert _rule(lambda: swap(graph, dc, replace(dc, supersedes_id=df.id))) == (
        "G.decision.supersession"
    )
    assert graph.superseded_by(names.dc) == names.df
    assert graph.superseded_by(names.df) is None


def test_sequence_gaps(complete: tuple[ProvenanceGraph, CompleteProject]) -> None:
    graph, names = complete
    approval = graph.get(Approval, names.approval_da)
    assert _rule(lambda: swap(graph, approval, replace(approval, sequence=2))) == (
        "G.approval.sequence"
    )
    revision = graph.get(WorkspaceRevision, names.revision2)
    assert _rule(lambda: swap(graph, revision, replace(revision, sequence=3))) == (
        "G.revision.sequence"
    )


# ---------------------------------------------------------------------- transitions


def _approval(
    graph: ProvenanceGraph,
    decision_id: str,
    verdict: ApprovalVerdict = ApprovalVerdict.APPROVED,
    *,
    fingerprint: str | None = None,
    resolution: str | None = None,
    n: int = 1,
) -> Approval:
    return Approval(
        ApprovalId(fresh(IdKind.APPROVAL, n)),
        graph.project.id,
        decision_id,  # type: ignore[arg-type]
        graph.next_approval_sequence(decision_id),  # type: ignore[arg-type]
        verdict,
        "Fixture reviewer",
        "Fixture rationale.",
        resolution,
        fingerprint if fingerprint is not None else support_fingerprint(graph, decision_id),
        DEMO_TIME,
    )


def _decision(graph: ProvenanceGraph, n: int) -> ScientificDecision:
    return ScientificDecision(
        fresh(IdKind.DECISION, n),
        graph.project.id,
        f"Fixture decision {n}",
        "Fixture statement.",
        "Fixture rationale.",
        (),
        (),
        AccessClass.PUBLIC,
        None,
        DEMO_TIME,
    )


def _link(
    graph: ProvenanceGraph, decision_id: str, claim_id: str, stance: Stance, n: int
) -> EvidenceLink:
    return EvidenceLink(
        fresh(IdKind.EVIDENCE_LINK, n),
        graph.project.id,
        decision_id,  # type: ignore[arg-type]
        claim_id,  # type: ignore[arg-type]
        stance,
        AssertionOrigin.HUMAN,
        None,
        DEMO_TIME,
    )


def test_transition_rules_for_approvals(complete: tuple[ProvenanceGraph, CompleteProject]) -> None:
    graph, names = complete
    assert _rule(lambda: graph.append([_approval(graph, names.de)])) == (
        "T.approval.after_rejection"
    )
    rejection = _approval(graph, names.de, ApprovalVerdict.REJECTED)
    assert _rule(lambda: graph.append([rejection])) == "T.approval.after_rejection"
    assert _rule(lambda: graph.append([_approval(graph, names.da)])) == "T.approval.redundant"
    assert _rule(lambda: graph.append([_approval(graph, names.dd)])) == (
        "T.approval.requires_support"
    )
    assert _rule(lambda: graph.append([_approval(graph, names.dc)])) == "T.decision.frozen"

    supported = _decision(graph, 10)
    support = _link(graph, supported.id, names.journal_claim, Stance.SUPPORTS, 10)
    staged = graph.append([supported, support])
    wrong = _approval(staged, supported.id, fingerprint="0" * 64)
    assert _rule(lambda: staged.append([wrong])) == "T.approval.fingerprint"
    approved = staged.append([_approval(staged, supported.id)])
    assert derive_status(approved, supported.id).status is DecisionStatus.APPROVED

    conflicting = _decision(graph, 11)
    links = [
        _link(graph, conflicting.id, names.journal_claim, Stance.SUPPORTS, 11),
        _link(graph, conflicting.id, names.implementation_claim, Stance.CONTRADICTS, 12),
    ]
    staged = graph.append([conflicting, *links])
    assert _rule(lambda: staged.append([_approval(staged, conflicting.id)])) == (
        "T.approval.conflict_resolution"
    )
    resolved = staged.append([_approval(staged, conflicting.id, resolution="Fixture.")])
    assert derive_status(resolved, conflicting.id).status is DecisionStatus.APPROVED


def test_approval_rules_see_earlier_records_in_the_same_batch(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    decision = _decision(graph, 20)
    link = _link(graph, decision.id, names.journal_claim, Stance.SUPPORTS, 20)
    interim = graph.append([decision, link])
    approval = _approval(interim, decision.id, n=20)
    result = graph.append([decision, link, approval])
    assert result.revision == graph.revision + 1
    assert derive_status(result, decision.id).status is DecisionStatus.APPROVED
    rejection = _approval(interim, decision.id, ApprovalVerdict.REJECTED, n=21)
    second = replace(_approval(interim, decision.id, n=22), sequence=2)
    assert _rule(lambda: graph.append([decision, link, rejection, second])) == (
        "T.approval.after_rejection"
    )
    dangling = _approval(graph, fresh(IdKind.DECISION, 99), n=23)
    assert _rule(lambda: graph.append([dangling])) == "G.dangling"


def test_same_batch_approval_checks_use_the_earlier_records(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    unsupported = _decision(graph, 24)
    staged = graph.append([unsupported])
    approval = _approval(staged, unsupported.id, n=24)
    assert _rule(lambda: graph.append([unsupported, approval])) == ("T.approval.requires_support")

    conflicting = _decision(graph, 25)
    links = [
        _link(graph, conflicting.id, names.journal_claim, Stance.SUPPORTS, 25),
        _link(graph, conflicting.id, names.implementation_claim, Stance.CONTRADICTS, 26),
    ]
    staged = graph.append([conflicting, *links])
    unresolved = _approval(staged, conflicting.id, n=25)
    assert _rule(lambda: graph.append([conflicting, *links, unresolved])) == (
        "T.approval.conflict_resolution"
    )


def test_an_approval_before_its_decision_in_the_batch_is_refused(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    conflicting = _decision(graph, 26)
    links = [
        _link(graph, conflicting.id, names.journal_claim, Stance.SUPPORTS, 27),
        _link(graph, conflicting.id, names.implementation_claim, Stance.CONTRADICTS, 28),
    ]
    staged = graph.append([conflicting, *links])
    unresolved = _approval(staged, conflicting.id, n=26)
    assert _rule(lambda: graph.append([unresolved, conflicting, *links])) == (
        "T.approval.decision_first"
    )
    assert _rule(lambda: graph.append([conflicting, unresolved, *links])) == (
        "T.approval.fingerprint"
    )
    unsupported = _decision(graph, 27)
    early = _approval(graph.append([unsupported]), unsupported.id, n=27)
    assert _rule(lambda: graph.append([early, unsupported])) == "T.approval.decision_first"


def test_batch_order_of_approvals_must_follow_their_sequence(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    decision = _decision(graph, 28)
    link = _link(graph, decision.id, names.journal_claim, Stance.SUPPORTS, 29)
    staged = graph.append([decision, link])
    rejection = _approval(staged, decision.id, ApprovalVerdict.REJECTED, n=28)
    approval = replace(_approval(staged, decision.id, n=29), sequence=2)
    assert _rule(lambda: staged.append([approval, rejection])) == "T.approval.sequence"
    assert _rule(lambda: graph.append([decision, link, approval, rejection])) == (
        "T.approval.sequence"
    )
    assert _rule(lambda: staged.append([rejection, approval])) == "T.approval.after_rejection"
    skipped = replace(_approval(staged, decision.id, n=30), sequence=3)
    assert _rule(lambda: staged.append([skipped])) == "T.approval.sequence"
    rejected = staged.append([rejection])
    assert derive_status(rejected, decision.id).status is DecisionStatus.REJECTED


def test_superseded_decisions_are_frozen(complete: tuple[ProvenanceGraph, CompleteProject]) -> None:
    graph, names = complete
    records = [
        _link(graph, names.dc, names.journal_claim, Stance.SUPPORTS, 30),
        ImplementationLink(
            fresh(IdKind.IMPLEMENTATION_LINK, 30),
            graph.project.id,
            names.dc,
            names.symbol_current,
            DEMO_TIME,
        ),
        VerificationLink(
            fresh(IdKind.VERIFICATION_LINK, 30),
            graph.project.id,
            names.test_unit,
            names.dc,
            None,
            DEMO_TIME,
        ),
        _approval(graph, names.dc, ApprovalVerdict.REJECTED),
    ]
    for record in records:
        assert _rule(lambda record=record: graph.append([record])) == "T.decision.frozen"
    successor = replace(_decision(graph, 31), supersedes_id=names.da)
    late_link = _link(graph, names.da, names.internal_claim, Stance.CONTEXT, 31)
    assert _rule(lambda: graph.append([successor, late_link])) == "T.decision.frozen"
    symbol_link = replace(records[2], decision_id=None, symbol_id=names.symbol_current)
    assert graph.append([symbol_link]).revision == graph.revision + 1


def test_empty_append_is_rejected(complete: tuple[ProvenanceGraph, CompleteProject]) -> None:
    graph, _ = complete
    assert _rule(lambda: graph.append([])) == "T.append.empty"


def test_stale_approval_graph_reloads_through_the_constructor(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    version = graph.get(SourceVersion, names.journal_version)
    mismatch = ClaimCheck(
        fresh(IdKind.CLAIM_CHECK, 40),
        graph.project.id,
        names.journal_claim,
        graph.next_check_sequence(names.journal_claim),
        ClaimCheckOutcome.MISMATCH,
        CheckMethod.NORMALIZED_SUBSTRING,
        version.content_sha256,
        None,
        DEMO_TIME + timedelta(days=1),
    )
    stale = with_records(graph, mismatch)
    report = derive_status(stale, names.da)
    assert report.approval_stale
    assert report.status is DecisionStatus.UNSUPPORTED
    records = {name: getattr(stale, name) for name in RECORD_FIELDS.values()}
    assert ProvenanceGraph(stale.project, stale.revision, **records) == stale
    unsupported_approval = _approval(graph, names.dd, fingerprint="0" * 64)
    reloaded = with_records(graph, unsupported_approval)
    assert derive_status(reloaded, names.dd).approval_stale
    assert _rule(lambda: graph.append([unsupported_approval])) == "T.approval.fingerprint"


@settings(max_examples=100, deadline=None)
@given(st.randoms(use_true_random=False))
def test_permutation_invariance(
    complete: tuple[ProvenanceGraph, CompleteProject], rng: object
) -> None:
    graph, _ = complete
    shuffled = {}
    for name in RECORD_FIELDS.values():
        items = list(getattr(graph, name))
        rng.shuffle(items)  # type: ignore[attr-defined]
        shuffled[name] = tuple(items)
    other = ProvenanceGraph(graph.project, graph.revision, **shuffled)
    assert other == graph
    assert hash(other) == hash(graph)
    assert other.records() == graph.records()


def test_lookups(complete: tuple[ProvenanceGraph, CompleteProject]) -> None:
    graph, names = complete
    with pytest.raises(RecordNotFoundError, match="unknown Claim"):
        graph.get(Claim, names.da)
    with pytest.raises(RecordNotFoundError):
        graph.get(TestCase, "tst_" + "0" * 32)
    assert graph.find(Claim, 42) is None  # type: ignore[arg-type]
    assert graph.latest_revision().id == names.revision2  # type: ignore[union-attr]
    assert graph.latest_revision(indexed_only=True).id == names.revision2  # type: ignore[union-attr]
    assert len(graph.symbols_in(names.revision1)) == 4
    current = graph.get(CodeSymbol, names.symbol_current)
    assert len(graph.implementation_links_for_key(current.key)) == 1
    assert graph.verification_links_for_symbol(names.symbol_moved)
    assert graph.verification_links_for_decision(names.da)
    assert graph.notices_for(names.journal_version)
    assert graph.next_revision_sequence() == 3
    assert graph.next_check_sequence(names.journal_claim) == 2
    assert graph.next_approval_sequence(names.da) == 2
    assert graph.latest_check(names.working_claim) is None
    empty = ProvenanceGraph.empty(graph.project)
    assert empty.revision == 0
    assert empty.latest_revision() is None


def test_symbols_never_lie_in_a_file_their_revision_lists_as_not_indexed(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    revision = graph.get(WorkspaceRevision, names.revision2)
    symbol = next(item for item in graph.symbols_in(revision.id))
    issue = FileIssue(symbol.file_path, FileIssueKind.SYNTAX_ERROR)
    flagged = replace(revision, file_issues=(issue,))
    revisions = tuple(flagged if item.id == revision.id else item for item in graph.revisions)
    with pytest.raises(ProvenanceInvariantError) as error:
        replace(graph, revisions=revisions)
    assert error.value.rule == "G.symbol.issue_file"
    assert symbol.file_path not in str(error.value)
    other = FileIssue("src/reco/unrelated.py", FileIssueKind.SYNTAX_ERROR)
    unrelated = replace(revision, file_issues=(other,))
    revisions = tuple(unrelated if item.id == revision.id else item for item in graph.revisions)
    assert replace(graph, revisions=revisions).revisions


def test_indexed_revisions_are_in_sequence_order(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    assert [item.id for item in graph.indexed_revisions()] == [names.revision1, names.revision2]
    unindexed = replace(graph.get(WorkspaceRevision, names.revision2), symbols_indexed=False)
    revisions = tuple(unindexed if item.id == unindexed.id else item for item in graph.revisions)
    assert [item.id for item in replace(graph, revisions=revisions).indexed_revisions()] == [
        names.revision1
    ]
