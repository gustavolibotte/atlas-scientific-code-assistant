"""Derived status, fingerprints, currency, freshness and latest results."""

from __future__ import annotations

import itertools
from dataclasses import replace
from datetime import timedelta

import pytest
from hypothesis import Phase, find, given, settings
from hypothesis import strategies as st
from provenance_builders import (
    CompleteProject,
    assert_status_sound,
    build_complete_real_project,
    fingerprint,
    make_service,
    with_records,
)
from provenance_strategies import pid_value, valid_graphs

from asca.application.demo import DEMO_TIME
from asca.application.provenance import DecisionDraft, ProvenanceService, SymbolDraft
from asca.domain.provenance import (
    AccessClass,
    Approval,
    ApprovalVerdict,
    AssertionOrigin,
    CheckMethod,
    Claim,
    ClaimCheck,
    ClaimCheckOutcome,
    ClaimVerificationState,
    CodeSymbol,
    Currency,
    DecisionStatus,
    EvidenceLink,
    IdKind,
    ImplementationLink,
    Language,
    LinkFreshness,
    Locator,
    LocatorKind,
    LocatorPart,
    PersistentIdentifier,
    PidScheme,
    Project,
    ProjectId,
    ProvenanceGraph,
    ProvenanceRecord,
    RecordNotFoundError,
    ScientificDecision,
    Source,
    SourceAuthority,
    SourceVersion,
    Stance,
    StatusReason,
    SupersessionDimension,
    SymbolKind,
    TestOutcome,
    ValidationRun,
    WorkspaceRevision,
    currency,
    derive_status,
    evidential_status,
    latest_result,
    link_freshness,
    make_id,
    sha256_text,
    support_fingerprint,
)

pytestmark = pytest.mark.unit

TEXT = "Fixture text: the quoted sentence."
QUOTE = "the quoted sentence"


def fresh(kind: IdKind, n: int) -> str:
    return make_id(kind, f"{0xC0DE0000 + n:032x}")


def _complete() -> tuple[ProvenanceService, ProvenanceGraph, CompleteProject]:
    service = make_service()
    names = build_complete_real_project(service)
    return service, service.load(names.project), names


@pytest.fixture(scope="module")
def complete() -> tuple[ProvenanceGraph, CompleteProject]:
    _, graph, names = _complete()
    return graph, names


# ---------------------------------------------------------------------- exhaustive table

STATES = list(ClaimVerificationState)
LinkSpec = tuple[Stance, ClaimVerificationState, bool]
LINK_SPECS: list[LinkSpec] = list(itertools.product(Stance, STATES, (False, True)))
HISTORIES = ("none", "approved_current", "approved_stale", "rejected")


def _table_base() -> tuple[ProvenanceGraph, SourceVersion, SourceVersion, ScientificDecision]:
    project = Project(ProjectId(fresh(IdKind.PROJECT, 1)), "Table", False, DEMO_TIME)
    sources = [
        Source(
            fresh(IdKind.SOURCE, n),
            project.id,
            "Fixture",
            PersistentIdentifier(PidScheme.URL, pid_value(PidScheme.URL, n)),
            DEMO_TIME,
        )
        for n in (1, 2)
    ]

    def version(n: int, authority: SourceAuthority, access: AccessClass) -> SourceVersion:
        return SourceVersion(
            fresh(IdKind.SOURCE_VERSION, n),
            project.id,
            sources[n - 1].id,
            "v1",
            authority,
            access,
            None if access is AccessClass.PUBLIC else "Fixture condition.",
            None,
            sha256_text(TEXT),
            DEMO_TIME,
            None,
            DEMO_TIME,
        )

    supporting = version(1, SourceAuthority.WORKING_MATERIAL, AccessClass.PUBLIC)
    automated = version(2, SourceAuthority.AUTOMATED_INFERENCE, AccessClass.INTERNAL)
    decision = ScientificDecision(
        fresh(IdKind.DECISION, 1),
        project.id,
        "Table decision",
        "Statement.",
        "Rationale.",
        (),
        (),
        AccessClass.PUBLIC,
        None,
        DEMO_TIME,
    )
    graph = ProvenanceGraph(
        project, 1, sources=tuple(sources), versions=(supporting, automated), decisions=(decision,)
    )
    return graph, supporting, automated, decision


def _table_graph(specs: tuple[LinkSpec, ...], history: str) -> tuple[ProvenanceGraph, str]:
    graph, supporting, automated, decision = _table_base()
    records: list[object] = []
    for n, (stance, state, is_e) in enumerate(specs, start=1):
        version = automated if is_e else supporting
        claim = Claim(
            fresh(IdKind.CLAIM, n),
            graph.project.id,
            version.id,
            QUOTE,
            Locator((LocatorPart(LocatorKind.PAGE, str(n)),)),
            None,
            AssertionOrigin.HUMAN,
            DEMO_TIME,
        )
        records.append(claim)
        if state is not ClaimVerificationState.NOT_CHECKED:
            outcome = ClaimCheckOutcome(state.value)
            unavailable = outcome is ClaimCheckOutcome.UNAVAILABLE
            records.append(
                ClaimCheck(
                    fresh(IdKind.CLAIM_CHECK, n),
                    graph.project.id,
                    claim.id,
                    1,
                    outcome,
                    CheckMethod.NOT_PERFORMED if unavailable else CheckMethod.NORMALIZED_SUBSTRING,
                    None if unavailable else version.content_sha256,
                    "Fixture." if unavailable else None,
                    DEMO_TIME,
                )
            )
        records.append(
            EvidenceLink(
                fresh(IdKind.EVIDENCE_LINK, n),
                graph.project.id,
                decision.id,
                claim.id,
                stance,
                AssertionOrigin.HUMAN,
                None,
                DEMO_TIME,
            )
        )
    graph = with_records(graph, *records)  # type: ignore[arg-type]
    if history != "none":
        verdict = ApprovalVerdict.REJECTED if history == "rejected" else ApprovalVerdict.APPROVED
        graph = with_records(
            graph,
            Approval(
                fresh(IdKind.APPROVAL, 1),
                graph.project.id,
                decision.id,
                1,
                verdict,
                "Fixture reviewer",
                "Fixture.",
                None,
                "0" * 64
                if history == "approved_stale"
                else support_fingerprint(graph, decision.id),
                DEMO_TIME,
            ),
        )
    return graph, decision.id


def _expected(specs: tuple[LinkSpec, ...], history: str) -> tuple[DecisionStatus, bool]:
    def countable(spec: LinkSpec) -> bool:
        return spec[1] is ClaimVerificationState.SOURCE_TEXT_CHECKED and not spec[2]

    checked_support = any(s[0] is Stance.SUPPORTS and countable(s) for s in specs)
    checked_contra = any(s[0] is Stance.CONTRADICTS and countable(s) for s in specs)
    unchecked = any(
        s[0] is Stance.SUPPORTS and s[1] is ClaimVerificationState.NOT_CHECKED and not s[2]
        for s in specs
    )
    if checked_support and checked_contra:
        evidential = DecisionStatus.CONFLICTING
    elif checked_support:
        evidential = DecisionStatus.SUPPORTED
    elif unchecked:
        evidential = DecisionStatus.PROPOSED
    else:
        evidential = DecisionStatus.UNSUPPORTED
    if history == "rejected":
        return DecisionStatus.REJECTED, False
    if history == "approved_current" and evidential in (
        DecisionStatus.SUPPORTED,
        DecisionStatus.CONFLICTING,
    ):
        return DecisionStatus.APPROVED, False
    return evidential, history != "none"


def test_exhaustive_status_table() -> None:
    combinations = (
        [()] + [(a,) for a in LINK_SPECS] + list(itertools.product(LINK_SPECS, LINK_SPECS))
    )
    for specs in combinations:
        for history in HISTORIES:
            graph, decision_id = _table_graph(specs, history)  # type: ignore[arg-type]
            report = derive_status(graph, decision_id)
            status, stale = _expected(specs, history)  # type: ignore[arg-type]
            context = (specs, history)
            assert report.status is status, context
            assert report.approval_stale is stale, context
            counted = [s for s in specs if s[0] is not Stance.CONTEXT]
            reasons = set(report.reasons)
            assert (StatusReason.NO_EVIDENCE_LINKS in reasons) is (not counted), context
            assert (StatusReason.AUTOMATED_INFERENCE_IGNORED in reasons) is any(
                s[2] for s in counted
            ), context
            assert (StatusReason.SUPPORT_FAILED_CHECK in reasons) is any(
                s[0] is Stance.SUPPORTS
                and s[1] in (ClaimVerificationState.MISMATCH, ClaimVerificationState.UNAVAILABLE)
                for s in specs
            ), context
            assert (StatusReason.REJECTED_BY_REVIEW in reasons) is (history == "rejected")
            expected_access = (
                AccessClass.INTERNAL if any(s[2] for s in specs) else AccessClass.PUBLIC
            )
            assert report.effective_access_class is expected_access, context
            approved_or_rejected = report.status in (
                DecisionStatus.APPROVED,
                DecisionStatus.REJECTED,
            )
            assert (report.current_approval_id is not None) is approved_or_rejected
            assert_status_sound(graph)


# ---------------------------------------------------------------------- soundness


def test_complete_project_statuses_are_sound(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, _ = complete
    assert_status_sound(graph)


@settings(max_examples=100, deadline=None)
@given(valid_graphs())
def test_status_soundness_over_valid_graphs(graph: ProvenanceGraph) -> None:
    assert_status_sound(graph)


def _extra_source(
    graph: ProvenanceGraph, authority: SourceAuthority, access: AccessClass
) -> tuple[list[ProvenanceRecord], Claim]:
    scheme = PidScheme.SYNTHETIC if graph.project.is_synthetic else PidScheme.URL
    source = Source(
        fresh(IdKind.SOURCE, 900),
        graph.project.id,
        "Extra fixture source",
        PersistentIdentifier(scheme, pid_value(scheme, 10**7)),
        DEMO_TIME,
    )
    version = SourceVersion(
        fresh(IdKind.SOURCE_VERSION, 900),
        graph.project.id,
        source.id,
        "extra",
        authority,
        access,
        None if access is AccessClass.PUBLIC else "Fixture condition.",
        None,
        sha256_text(TEXT),
        DEMO_TIME,
        None,
        DEMO_TIME,
    )
    claim = Claim(
        fresh(IdKind.CLAIM, 900),
        graph.project.id,
        version.id,
        QUOTE,
        Locator((LocatorPart(LocatorKind.PAGE, "1"),)),
        None,
        AssertionOrigin.AUTOMATED,
        DEMO_TIME,
    )
    check = ClaimCheck(
        fresh(IdKind.CLAIM_CHECK, 900),
        graph.project.id,
        claim.id,
        1,
        ClaimCheckOutcome.SOURCE_TEXT_CHECKED,
        CheckMethod.NORMALIZED_SUBSTRING,
        version.content_sha256,
        None,
        DEMO_TIME,
    )
    return [source, version, claim, check], claim


def _links_to(graph: ProvenanceGraph, claim: Claim, stances: list[Stance]) -> list[EvidenceLink]:
    return [
        EvidenceLink(
            fresh(IdKind.EVIDENCE_LINK, 900 + n),
            graph.project.id,
            decision.id,
            claim.id,
            stance,
            AssertionOrigin.AUTOMATED,
            None,
            DEMO_TIME,
        )
        for n, (decision, stance) in enumerate(zip(graph.decisions, stances, strict=False))
    ]


_REACH_SETTINGS = settings(max_examples=300, database=None, deadline=None, phases=(Phase.generate,))
# An approved conflict needs a non-synthetic graph, a conflicting chain, an approval and a
# tail that leaves both checked claims intact. ``find`` stops at the first hit (typically
# within 100 examples), so the larger budget only removes the rare unlucky run.
_RARE_REACH_SETTINGS = settings(_REACH_SETTINGS, max_examples=2000)


@pytest.mark.parametrize(
    "status",
    [
        DecisionStatus.SUPPORTED,
        DecisionStatus.CONFLICTING,
        DecisionStatus.APPROVED,
        DecisionStatus.REJECTED,
    ],
)
def test_valid_graphs_reach_every_interesting_status(status: DecisionStatus) -> None:
    """The properties over ``valid_graphs()`` are only meaningful if these occur."""
    graph = find(
        valid_graphs(),
        lambda graph: any(
            derive_status(graph, decision.id).status is status for decision in graph.decisions
        ),
        settings=_REACH_SETTINGS,
    )
    assert_status_sound(graph)


def test_valid_graphs_reach_an_approved_conflict_with_a_resolution() -> None:
    graph = find(
        valid_graphs(),
        lambda graph: any(
            approval.conflict_resolution is not None
            and derive_status(graph, approval.decision_id).evidential_status
            is DecisionStatus.CONFLICTING
            for approval in graph.approvals
        ),
        settings=_RARE_REACH_SETTINGS,
    )
    assert_status_sound(graph)


@settings(max_examples=100, deadline=None)
@given(valid_graphs(), st.data())
def test_automated_inference_links_never_change_evidential_status(
    graph: ProvenanceGraph, data: st.DataObject
) -> None:
    extra, claim = _extra_source(graph, SourceAuthority.AUTOMATED_INFERENCE, AccessClass.PUBLIC)
    stances = data.draw(
        st.lists(
            st.sampled_from([Stance.SUPPORTS, Stance.CONTRADICTS]),
            min_size=len(graph.decisions),
            max_size=len(graph.decisions),
        )
    )
    extended = with_records(graph, *extra, *_links_to(graph, claim, stances))
    for decision in graph.decisions:
        before = evidential_status(graph, decision.id)[0]
        assert evidential_status(extended, decision.id)[0] is before
    assert_status_sound(extended)


@settings(max_examples=100, deadline=None)
@given(valid_graphs(), st.sampled_from(SourceAuthority))
def test_context_links_never_change_status_or_fingerprint(
    graph: ProvenanceGraph, authority: SourceAuthority
) -> None:
    if graph.project.is_synthetic or authority in (
        SourceAuthority.PUBLISHED,
        SourceAuthority.VERIFIED_IMPLEMENTATION,
    ):
        authority = SourceAuthority.WORKING_MATERIAL
    if authority is SourceAuthority.APPROVED_INTERNAL:
        authority = SourceAuthority.AUTOMATED_INFERENCE
    extra, claim = _extra_source(graph, authority, AccessClass.RESTRICTED)
    links = _links_to(graph, claim, [Stance.CONTEXT] * len(graph.decisions))
    extended = with_records(graph, *extra, *links)
    for decision in graph.decisions:
        before = derive_status(graph, decision.id)
        after = derive_status(extended, decision.id)
        assert after.status is before.status
        assert after.support_fingerprint == before.support_fingerprint
        assert after.reasons == before.reasons
        assert after.effective_access_class is AccessClass.RESTRICTED


@settings(max_examples=100, deadline=None)
@given(valid_graphs())
def test_effective_access_is_the_high_water_mark(graph: ProvenanceGraph) -> None:
    for decision in graph.decisions:
        ranks = [decision.access_floor.rank]
        for link in graph.links_for(decision.id):
            claim = graph.get(Claim, link.claim_id)
            ranks.append(graph.get(SourceVersion, claim.source_version_id).access_class.rank)
        assert derive_status(graph, decision.id).effective_access_class.rank == max(ranks)


@settings(max_examples=50, deadline=None)
@given(valid_graphs(), st.randoms(use_true_random=False))
def test_derive_status_is_deterministic_over_tuple_order(
    graph: ProvenanceGraph, rng: object
) -> None:
    shuffled = {}
    for name in (
        "claims",
        "checks",
        "decisions",
        "evidence_links",
        "approvals",
        "versions",
        "supersessions",
    ):
        items = list(getattr(graph, name))
        rng.shuffle(items)  # type: ignore[attr-defined]
        shuffled[name] = tuple(items)
    other = replace(graph, **shuffled)
    for decision in graph.decisions:
        assert derive_status(other, decision.id) == derive_status(graph, decision.id)


# ---------------------------------------------------------------------- staleness


def test_mismatch_after_approval_makes_it_stale_and_unsupported() -> None:
    _, graph, names = _complete()
    assert derive_status(graph, names.da).status is DecisionStatus.APPROVED
    version = graph.get(SourceVersion, names.journal_version)
    mismatch = ClaimCheck(
        fresh(IdKind.CLAIM_CHECK, 1),
        graph.project.id,
        names.journal_claim,
        graph.next_check_sequence(names.journal_claim),
        ClaimCheckOutcome.MISMATCH,
        CheckMethod.NORMALIZED_SUBSTRING,
        version.content_sha256,
        None,
        DEMO_TIME + timedelta(days=1),
    )
    stale = graph.append([mismatch])
    report = derive_status(stale, names.da)
    assert report.status is DecisionStatus.UNSUPPORTED
    assert report.approval_stale
    assert StatusReason.APPROVAL_STALE in report.reasons
    assert StatusReason.SUPPORT_FAILED_CHECK in report.reasons
    assert report.current_approval_id is None


def test_checked_contradiction_makes_approval_stale_and_conflicting() -> None:
    service, _, names = _complete()
    service.link_evidence(names.project, names.da, names.internal_claim, Stance.CONTRADICTS)
    report = derive_status(service.load(names.project), names.da)
    assert report.status is DecisionStatus.CONFLICTING
    assert report.approval_stale
    assert report.effective_access_class is AccessClass.INTERNAL


# ---------------------------------------------------------------------- currency and freshness


def test_technical_notice_leaves_scientific_currency_current(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    version = names.journal_version
    assert currency(graph, version, SupersessionDimension.SCIENTIFIC) is Currency.CURRENT
    assert currency(graph, version, SupersessionDimension.TECHNICAL) is Currency.SUPERSEDED
    report = derive_status(graph, names.da)
    assert StatusReason.SUPPORT_TECHNICALLY_SUPERSEDED in report.reasons
    assert StatusReason.SUPPORT_SCIENTIFICALLY_SUPERSEDED not in report.reasons
    assert report.status is DecisionStatus.APPROVED


def test_scientific_supersession_is_reported_but_does_not_change_status() -> None:
    service, _, names = _complete()
    service.record_supersession(
        names.project,
        superseded=names.journal_version,
        superseding=None,
        dimension=SupersessionDimension.SCIENTIFIC,
        reason="Fixture erratum.",
    )
    report = derive_status(service.load(names.project), names.da)
    assert StatusReason.SUPPORT_SCIENTIFICALLY_SUPERSEDED in report.reasons
    assert report.status is DecisionStatus.APPROVED


def test_link_freshness_branches(complete: tuple[ProvenanceGraph, CompleteProject]) -> None:
    graph, names = complete

    def freshness(link_id: str) -> LinkFreshness:
        return link_freshness(graph, graph.get(ImplementationLink, link_id))

    assert freshness(names.link_current) is LinkFreshness.CURRENT
    assert freshness(names.link_stale) is LinkFreshness.STALE
    assert freshness(names.link_moved) is LinkFreshness.MOVED
    assert freshness(names.link_orphaned) is LinkFreshness.ORPHANED


def test_link_freshness_unknown_branches() -> None:
    service, _, names = _complete()
    pid = names.project
    service.record_workspace_revision(
        pid,
        vcs_ref="fixture-rev-3",
        symbols=[
            SymbolDraft(
                Language.PYTHON, SymbolKind.FUNCTION, "estimate_amplitude", "src/reco/estimators.py"
            )
        ],
        symbols_indexed=True,
    )
    graph = service.load(pid)
    link = graph.get(ImplementationLink, names.link_current)
    assert link_freshness(graph, link) is LinkFreshness.UNKNOWN

    unindexed = make_service()
    project = unindexed.create_project("Unindexed", is_synthetic=False)
    decision = unindexed.propose_decision(
        project,
        DecisionDraft("Fixture", "Statement.", "Rationale."),
    )
    recorded = unindexed.record_workspace_revision(
        project,
        vcs_ref=None,
        symbols=[
            SymbolDraft(
                Language.PYTHON, SymbolKind.FUNCTION, "f", "src/f.py", None, fingerprint(1)
            ),
            SymbolDraft(Language.PYTHON, SymbolKind.FUNCTION, "g", "src/f.py"),
        ],
        symbols_indexed=False,
    )
    with_fp = unindexed.link_implementation(project, decision, recorded.symbol_ids[0])
    without_fp = unindexed.link_implementation(project, decision, recorded.symbol_ids[1])
    graph = unindexed.load(project)
    for link_id in (with_fp, without_fp):
        assert link_freshness(graph, graph.get(ImplementationLink, link_id)) is (
            LinkFreshness.UNKNOWN
        )
    assert graph.get(CodeSymbol, recorded.symbol_ids[1]).fingerprint is None


# ---------------------------------------------------------------------- results


def test_latest_result_breaks_ties_by_run_id(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    run2 = graph.get(ValidationRun, names.run2)
    run, result = latest_result(graph, names.test_regression)  # type: ignore[misc]
    assert run.id == names.run2
    assert result.outcome is TestOutcome.FAILED
    run_t, _ = latest_result(graph, names.test_unit)  # type: ignore[misc]
    assert run_t.id == names.run1
    passed = tuple(replace(item, outcome=TestOutcome.PASSED) for item in run2.results)
    low = replace(run2, id=make_id(IdKind.RUN, "0" * 32), results=passed)
    high = replace(run2, id=make_id(IdKind.RUN, "f" * 32), results=passed)
    assert latest_result(with_records(graph, low), names.test_regression)[0].id == run2.id  # type: ignore[index]
    winner = latest_result(with_records(graph, low, high), names.test_regression)
    assert winner is not None and winner[0].id == high.id
    assert latest_result(graph, "tst_" + "0" * 32) is None
    assert graph.get(WorkspaceRevision, run2.revision_id).sequence == 2


def test_derive_status_rejects_unknown_decisions(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, _ = complete
    with pytest.raises(RecordNotFoundError):
        derive_status(graph, "dec_" + "0" * 32)
