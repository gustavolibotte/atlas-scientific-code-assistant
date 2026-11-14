"""Federation: grouping, ordering, reporting, guards and routing."""

import asyncio
import logging
import random
import time
from dataclasses import replace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from knowledge_contract import (
    FakeProvider,
    RaisingProvider,
    SleepingProvider,
    fetch_result,
    identity,
    make_candidate,
    make_descriptor,
    related,
    reranked,
)

from asca.application.knowledge.federation import (
    AssessedCandidate,
    EvidenceGroup,
    FederatedSearchResult,
    FederationPolicy,
    FederationService,
    GroupFlag,
    ProviderReport,
    ProviderStatus,
    group_candidates,
)
from asca.application.knowledge.models import (
    CandidatePid,
    CandidateRef,
    HealthState,
    KnowledgeCandidate,
    KnowledgeQuery,
    PidOrigin,
    ProviderError,
    ProviderErrorKind,
    ProviderHealth,
    ProviderKind,
    SearchResult,
)
from asca.application.knowledge.pids import pid_text
from asca.application.knowledge.policy import suggest_authority
from asca.domain.provenance import AccessClass

pytestmark = pytest.mark.unit

ORDER = {"inspire": 0, "arxiv": 1, "hepdata": 2, "local": 3, "mcp:test": 4, "mcp:other": 5}
DOI_A = "doi:10.5555/asca-test.1"
DOI_B = "doi:10.5555/asca-test.2"
ARXIV = "arxiv:2109.05124"
QUERY = KnowledgeQuery("liquid argon calorimeter", limit=5)


def assess(candidate: KnowledgeCandidate) -> AssessedCandidate:
    return AssessedCandidate(candidate, suggest_authority(candidate))


def group(*candidates: KnowledgeCandidate) -> tuple[EvidenceGroup, ...]:
    return group_candidates([assess(item) for item in candidates], ORDER)


def refs(evidence_group: EvidenceGroup) -> list[str]:
    return [
        f"{m.candidate.ref.provider_id}:{m.candidate.ref.native_id}" for m in evidence_group.members
    ]


def inspire(
    recid: str, *pids: str, rank: int = 0, refereed: bool | None = True
) -> KnowledgeCandidate:
    return make_candidate(
        ProviderKind.INSPIRE,
        recid,
        rank=rank,
        refereed=refereed,
        pids=[identity(f"inspire:{recid}", PidOrigin.NATIVE), *(identity(p) for p in pids)],
    )


def arxiv(native: str, *pids: CandidatePid, rank: int = 0) -> KnowledgeCandidate:
    base = native.rsplit("v", 1)[0]
    return make_candidate(
        ProviderKind.ARXIV,
        native,
        rank=rank,
        pids=[identity(f"arxiv:{base}", PidOrigin.NATIVE), *pids],
    )


def local(
    path: str, *pids: CandidatePid, rank: int = 0, access: AccessClass = AccessClass.INTERNAL
) -> KnowledgeCandidate:
    return make_candidate(
        ProviderKind.LOCAL,
        path,
        rank=rank,
        access_class=access,
        pids=[*pids, related(f"local_document:{path}", PidOrigin.NATIVE)],
    )


# ---------------------------------------------------------------------- grouping


def test_candidates_sharing_an_arxiv_id_merge_without_fusing_fields() -> None:
    groups = group(arxiv("2109.05124v2"), inspire("1920956", DOI_A, ARXIV, rank=2))
    assert len(groups) == 1
    merged = groups[0]
    assert merged.key == DOI_A
    assert [pid_text(p) for p in merged.identity_pids] == [DOI_A, ARXIV, "inspire:1920956"]
    assert refs(merged) == ["inspire:1920956", "arxiv:2109.05124v2"]
    assert merged.best_rank == 0
    assert merged.flags == frozenset()
    titles = {m.candidate.version.label for m in merged.members}
    assert len(titles) == 2


def test_related_pids_never_merge() -> None:
    dataset = make_candidate(
        ProviderKind.HEPDATA,
        "ins1920956",
        pids=[
            identity("doi:10.17182/hepdata.1", PidOrigin.NATIVE),
            related("inspire:1920956"),
            related(DOI_A),
        ],
    )
    mcp = make_candidate(
        ProviderKind.MCP,
        "doc-1",
        access_class=AccessClass.INTERNAL,
        pids=[related(DOI_A, PidOrigin.PROVIDER_ASSERTED)],
    )
    groups = group(inspire("1920956", DOI_A), dataset, mcp)
    assert len(groups) == 3
    assert {g.key for g in groups} == {DOI_A, "doi:10.17182/hepdata.1", "ref:mcp:test:doc-1"}


def test_two_inspire_records_through_one_doi_are_split_and_flagged() -> None:
    other = local("notes/a.md", identity("inspire:2"), identity(DOI_A))
    groups = group(inspire("1", DOI_A), other)
    assert len(groups) == 2
    assert all(GroupFlag.AMBIGUOUS_IDENTITY in g.flags for g in groups)
    assert {g.key for g in groups} == {"ref:inspire:1", "ref:local:notes/a.md"}


def test_same_provider_collision_is_split() -> None:
    groups = group(
        local("notes/a.md", identity(DOI_A), rank=0),
        local("notes/b.md", identity(DOI_A), rank=1),
    )
    assert [g.key for g in groups] == ["ref:local:notes/a.md", "ref:local:notes/b.md"]
    assert all(g.flags == frozenset({GroupFlag.AMBIGUOUS_IDENTITY}) for g in groups)


def test_two_arxiv_identities_split_and_unique_keys_survive() -> None:
    groups = group(
        inspire("1", DOI_A),
        arxiv("2109.05124v2", identity(DOI_A, PidOrigin.PROVIDER_ASSERTED)),
        local("notes/a.md", identity("arxiv:2111.08590"), identity(DOI_A)),
    )
    keys = [g.key for g in groups]
    assert len(set(keys)) == 3
    assert all(GroupFlag.AMBIGUOUS_IDENTITY in g.flags for g in groups)


def test_multiple_dois_flag_keeps_the_merge() -> None:
    groups = group(
        inspire("1", DOI_B, ARXIV),
        arxiv("2109.05124v1", identity(DOI_A, PidOrigin.PROVIDER_ASSERTED)),
    )
    assert len(groups) == 1
    assert groups[0].flags == frozenset({GroupFlag.MULTIPLE_DOIS})
    assert groups[0].key == DOI_A


def test_access_mixed_and_effective_access() -> None:
    groups = group(inspire("1", ARXIV), local("notes/a.md", identity(ARXIV)))
    assert len(groups) == 1
    assert groups[0].flags == frozenset({GroupFlag.ACCESS_MIXED})
    assert groups[0].effective_access_class is AccessClass.INTERNAL


def test_key_precedence() -> None:
    by_arxiv = make_candidate(
        ProviderKind.ARXIV, "2302.07555v2", pids=[identity("arxiv:2302.07555")]
    )
    by_inspire = make_candidate(
        ProviderKind.INSPIRE, "2744105", pids=[identity("inspire:2744105")], rank=1
    )
    by_report = local("notes/r.md", identity("cds_report:ATLAS-CONF-2023-001"), rank=0)
    by_path = local("notes/p.md", rank=1)
    by_url = make_candidate(
        ProviderKind.MCP,
        "doc-u",
        rank=0,
        pids=[related("url:https://example.org/asca-test/u", PidOrigin.PROVIDER_ASSERTED)],
    )
    bare = make_candidate(ProviderKind.MCP, "doc-b", rank=1, provider_id="mcp:other")
    keys = {g.key for g in group(by_arxiv, by_inspire, by_report, by_path, by_url, bare)}
    assert keys == {
        "arxiv:2302.07555",
        "inspire:2744105",
        "cds_report:ATLAS-CONF-2023-001",
        "local_document:notes/p.md",
        "url:https://example.org/asca-test/u",
        "ref:mcp:other:doc-b",
    }


def test_colliding_related_keys_fall_back_to_refs() -> None:
    url = "url:https://example.org/asca-test/same"
    first = make_candidate(ProviderKind.MCP, "doc-1", pids=[related(url)])
    second = make_candidate(ProviderKind.MCP, "doc-1", provider_id="mcp:other", pids=[related(url)])
    assert [g.key for g in group(first, second)] == ["ref:mcp:test:doc-1", "ref:mcp:other:doc-1"]
    duplicate = group(first, first)
    assert [g.key for g in duplicate] == ["ref:mcp:test:doc-1", "ref:mcp:test:doc-1#1"]


def test_groups_are_ordered_by_best_rank_precedence_and_key() -> None:
    groups = group(
        inspire("1", rank=1),
        inspire("2", rank=0),
        arxiv("2302.07555v2", rank=0),
        arxiv("2111.08590v1", rank=1),
        local("notes/a.md", rank=0),
    )
    assert [g.key for g in groups] == [
        "inspire:2",
        "arxiv:2302.07555",
        "local_document:notes/a.md",
        "inspire:1",
        "arxiv:2111.08590",
    ]


# ---------------------------------------------------------------------- properties

POOL = [DOI_A, DOI_B, "cds_report:ATLAS-CONF-2023-001"]


@st.composite
def candidate_sets(draw: st.DrawFn) -> list[AssessedCandidate]:
    result: list[KnowledgeCandidate] = []
    for kind in (ProviderKind.INSPIRE, ProviderKind.ARXIV, ProviderKind.LOCAL, ProviderKind.MCP):
        for index in range(draw(st.integers(min_value=0, max_value=3))):
            texts = draw(st.lists(st.sampled_from(POOL), unique=True, max_size=2))
            inspire_id = draw(st.sampled_from([None, "inspire:1", "inspire:2"]))
            arxiv_id = draw(st.sampled_from([None, "arxiv:2109.05124", "arxiv:2111.08590"]))
            texts += [item for item in (inspire_id, arxiv_id) if item is not None]
            if kind is ProviderKind.MCP:
                pids = [related(text) for text in texts]
                native = f"doc-{index}"
            elif kind is ProviderKind.LOCAL:
                pids = [identity(text) for text in texts]
                native = f"notes/{index}.md"
            elif kind is ProviderKind.ARXIV:
                base = arxiv_id or "arxiv:2302.07555"
                texts = [t for t in texts if t != arxiv_id] + [base]
                pids = [identity(text) for text in texts]
                native = f"{base.removeprefix('arxiv:')}v{index + 1}"
            else:
                pids = [identity(text) for text in texts if text != inspire_id]
                pids.append(identity(f"inspire:{index + 10}"))
                native = str(index + 10)
            result.append(
                make_candidate(
                    kind,
                    native,
                    rank=index,
                    pids=pids,
                    access_class=draw(st.sampled_from([AccessClass.PUBLIC, AccessClass.INTERNAL]))
                    if kind in (ProviderKind.LOCAL, ProviderKind.MCP)
                    else AccessClass.PUBLIC,
                )
            )
    return [assess(item) for item in result]


def _flatten(groups: tuple[EvidenceGroup, ...]) -> list[AssessedCandidate]:
    return [member for g in groups for member in g.members]


@settings(max_examples=150, deadline=None)
@given(candidate_sets(), st.randoms(use_true_random=False))
def test_grouping_is_permutation_invariant_conservative_and_idempotent(
    assessed: list[AssessedCandidate], rng: random.Random
) -> None:
    groups = group_candidates(assessed, ORDER)
    shuffled = list(assessed)
    rng.shuffle(shuffled)
    assert group_candidates(shuffled, ORDER) == groups
    members = _flatten(groups)
    assert sorted(id(m) for m in members) == sorted(id(m) for m in assessed)
    assert group_candidates(members, ORDER) == groups
    keys = [g.key for g in groups]
    assert len(set(keys)) == len(keys)
    seen: set[str] = set()
    for evidence_group in groups:
        if GroupFlag.AMBIGUOUS_IDENTITY in evidence_group.flags:
            assert len(evidence_group.members) == 1
        texts = {pid_text(p) for p in evidence_group.identity_pids}
        if GroupFlag.AMBIGUOUS_IDENTITY not in evidence_group.flags:
            assert not texts & seen
            seen |= texts


# ---------------------------------------------------------------------- policy and reports


def test_policy_validation() -> None:
    assert FederationPolicy(live=True).grace_s == 3.0
    for bad in (
        {"live": 1},
        {"precedence": ["inspire"]},
        {"grace_s": -1},
        {"grace_s": 11},
        {"max_parallel": 0},
        {"max_parallel": 2.5},
        {"max_groups": 201},
    ):
        with pytest.raises(ValueError):
            FederationPolicy(**{"live": True, **bad})  # type: ignore[arg-type]


def test_report_validation() -> None:
    error = ProviderError(ProviderErrorKind.NOT_CONSULTED, "disabled")
    with pytest.raises(ValueError):
        ProviderReport("inspire", ProviderKind.INSPIRE, ProviderStatus.OK, 0, 0, None, error, 0)
    with pytest.raises(ValueError):
        ProviderReport("inspire", ProviderKind.INSPIRE, ProviderStatus.FAILED, 0, 0, None, None, 0)
    with pytest.raises(ValueError):
        ProviderReport("inspire", ProviderKind.INSPIRE, ProviderStatus.OK, -1, 0, None, None, 0)


def test_service_constructor_rules() -> None:
    inspire_p = FakeProvider(make_descriptor(ProviderKind.INSPIRE))
    with pytest.raises(ValueError):
        FederationService([inspire_p, inspire_p], FederationPolicy(live=True))
    with pytest.raises(ValueError):
        FederationService(
            [inspire_p],
            FederationPolicy(live=True),
            disabled=[make_descriptor(ProviderKind.INSPIRE)],
        )
    many = [FakeProvider(make_descriptor(ProviderKind.MCP, f"mcp:s{i}")) for i in range(17)]
    with pytest.raises(ValueError):
        FederationService(many, FederationPolicy(live=True))
    with pytest.raises(ValueError):
        FederationService(
            [inspire_p], FederationPolicy(live=True, precedence=("inspire", "inspire"))
        )
    arxiv_p = FakeProvider(make_descriptor(ProviderKind.ARXIV))
    service = FederationService(
        [inspire_p, arxiv_p],
        FederationPolicy(live=True, precedence=("local", "arxiv")),
        disabled=[make_descriptor(ProviderKind.HEPDATA)],
    )
    assert service.order == ("arxiv", "inspire", "hepdata")
    assert service.descriptor("hepdata") is not None
    assert service.descriptor("nope") is None


def _service(*providers: FakeProvider, live: bool = True, **kwargs: object) -> FederationService:
    return FederationService(providers, FederationPolicy(live=live, **kwargs))  # type: ignore[arg-type]


def test_search_reports_every_provider_and_assesses_members() -> None:
    inspire_p = FakeProvider(
        make_descriptor(ProviderKind.INSPIRE),
        search_outcome=SearchResult(
            reranked([inspire("1920956", DOI_A, ARXIV), inspire("2")]), 17, 0
        ),
    )
    arxiv_p = FakeProvider(
        make_descriptor(ProviderKind.ARXIV),
        search_outcome=SearchResult((arxiv("2109.05124v2"),), None, 1),
    )
    local_p = FakeProvider(
        make_descriptor(ProviderKind.LOCAL),
        search_outcome=SearchResult((local("notes/a.md", identity(ARXIV)),), 1, 0),
    )
    service = FederationService(
        [inspire_p, arxiv_p, local_p],
        FederationPolicy(live=True),
        disabled=[make_descriptor(ProviderKind.HEPDATA)],
    )
    result = asyncio.run(service.search(QUERY))
    assert [(r.provider_id, r.status) for r in result.reports] == [
        ("inspire", ProviderStatus.OK),
        ("arxiv", ProviderStatus.PARTIAL),
        ("local", ProviderStatus.OK),
        ("hepdata", ProviderStatus.SKIPPED),
    ]
    assert result.reports[0].total_reported == 17
    assert result.reports[1].dropped_items == 1
    assert result.reports[3].error == ProviderError(ProviderErrorKind.NOT_CONSULTED, "disabled")
    assert not result.complete
    assert [r.provider_id for r in result.not_consulted] == ["hepdata"]
    first = result.groups[0]
    assert first.key == DOI_A
    assert refs(first) == ["inspire:1920956", "arxiv:2109.05124v2", "local:notes/a.md"]
    assert first.flags == frozenset({GroupFlag.ACCESS_MIXED})
    assert [m.suggestion.authority.letter for m in first.members] == ["A", "D", "D"]
    assert isinstance(result, FederatedSearchResult)


def test_complete_when_every_provider_is_ok() -> None:
    service = _service(FakeProvider(make_descriptor(ProviderKind.INSPIRE)))
    result = asyncio.run(service.search(QUERY))
    assert result.complete and result.not_consulted == () and result.groups == ()


def test_max_groups_cuts_the_ordered_groups() -> None:
    provider = FakeProvider(
        make_descriptor(ProviderKind.INSPIRE),
        search_outcome=SearchResult(reranked(inspire(str(i)) for i in range(1, 6)), None, 0),
    )
    result = asyncio.run(_service(provider, max_groups=2).search(QUERY))
    assert [g.key for g in result.groups] == ["inspire:1", "inspire:2"]


def test_live_disabled_skips_network_providers_without_calling_them() -> None:
    inspire_p = FakeProvider(make_descriptor(ProviderKind.INSPIRE))
    mcp_p = FakeProvider(make_descriptor(ProviderKind.MCP))
    local_p = FakeProvider(make_descriptor(ProviderKind.LOCAL))
    result = asyncio.run(_service(inspire_p, mcp_p, local_p, live=False).search(QUERY))
    assert [(r.status, r.error.code if r.error else None) for r in result.reports] == [
        (ProviderStatus.SKIPPED, "live_disabled"),
        (ProviderStatus.SKIPPED, "live_disabled"),
        (ProviderStatus.OK, None),
    ]
    assert inspire_p.calls == [] and mcp_p.calls == []
    assert local_p.calls == ["search"]


def test_internal_query_never_reaches_public_providers() -> None:
    providers = [
        FakeProvider(make_descriptor(kind))
        for kind in (ProviderKind.INSPIRE, ProviderKind.ARXIV, ProviderKind.HEPDATA)
    ]
    local_p = FakeProvider(make_descriptor(ProviderKind.LOCAL))
    query = KnowledgeQuery("internal topic", access_class=AccessClass.INTERNAL)
    result = asyncio.run(_service(*providers, local_p).search(query))
    for report in result.reports[:3]:
        assert report.status is ProviderStatus.SKIPPED
        assert report.error == ProviderError(ProviderErrorKind.NOT_CONSULTED, "query_access_class")
    assert all(p.calls == [] for p in providers)
    assert result.reports[3].status is ProviderStatus.OK


def test_only_filters_providers_without_reports() -> None:
    inspire_p = FakeProvider(make_descriptor(ProviderKind.INSPIRE))
    arxiv_p = FakeProvider(make_descriptor(ProviderKind.ARXIV))
    result = asyncio.run(_service(inspire_p, arxiv_p).search(QUERY, only=frozenset({"arxiv"})))
    assert [r.provider_id for r in result.reports] == ["arxiv"]
    assert inspire_p.calls == []


def test_slow_provider_hits_the_federation_deadline_and_others_return() -> None:
    slow = SleepingProvider(make_descriptor(ProviderKind.MCP, timeout_s=1.0))
    fast = FakeProvider(
        make_descriptor(ProviderKind.INSPIRE),
        search_outcome=SearchResult((inspire("1"),), 1, 0),
    )
    service = _service(fast, slow, grace_s=0.0)
    started = time.monotonic()
    result = asyncio.run(service.search(QUERY))
    assert time.monotonic() - started < 1.8
    assert result.reports[1].error == ProviderError(
        ProviderErrorKind.TIMEOUT, "federation_deadline"
    )
    assert result.reports[1].status is ProviderStatus.FAILED
    assert result.reports[0].status is ProviderStatus.OK
    assert len(result.groups) == 1


def test_raising_provider_becomes_internal_error_without_leaking_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    raising = RaisingProvider(make_descriptor(ProviderKind.INSPIRE))
    result = asyncio.run(_service(raising).search(QUERY))
    assert result.reports[0].error == ProviderError(
        ProviderErrorKind.INTERNAL_ERROR, "unexpected_exception"
    )
    assert "secret-canary" not in repr(result)
    assert "secret-canary" not in caplog.text


def _tampered(result: SearchResult, candidates: tuple[KnowledgeCandidate, ...]) -> SearchResult:
    object.__setattr__(result, "candidates", candidates)
    return result


@pytest.mark.parametrize(
    "case",
    [
        "wrong_provider",
        "too_many",
        "bad_ranks",
        "lowered",
        "public_kind",
        "not_a_result",
        "wrong_kind",
    ],
)
def test_contract_violations_fail_the_provider(case: str) -> None:
    descriptor = make_descriptor(ProviderKind.INSPIRE)
    outcome: object
    if case == "wrong_provider":
        outcome = SearchResult((arxiv("2109.05124v2"),), None, 0)
    elif case == "too_many":
        outcome = SearchResult(reranked(inspire(str(i)) for i in range(1, 8)), None, 0)
    elif case == "bad_ranks":
        outcome = _tampered(SearchResult((), None, 0), (inspire("1", rank=3),))
    elif case == "lowered":
        descriptor = make_descriptor(ProviderKind.MCP, access_class=AccessClass.INTERNAL)
        outcome = SearchResult((make_candidate(ProviderKind.MCP, "doc"),), None, 0)
    elif case == "public_kind":
        internal = replace(
            inspire("1"), access_class=AccessClass.INTERNAL, access_conditions="Internal."
        )
        outcome = SearchResult((internal,), None, 0)
    elif case == "wrong_kind":
        outcome = SearchResult(
            (make_candidate(ProviderKind.ARXIV, "2109.05124v2", provider_id="inspire"),), None, 0
        )
    else:
        outcome = ["not", "a", "result"]
    provider = FakeProvider(descriptor, search_outcome=outcome)  # type: ignore[arg-type]
    result = asyncio.run(_service(provider).search(QUERY))
    assert result.reports[0].status is ProviderStatus.FAILED
    assert result.reports[0].error == ProviderError(
        ProviderErrorKind.MALFORMED_RESPONSE, "contract_violation"
    )
    assert result.groups == ()


def test_cancellation_propagates() -> None:
    slow = SleepingProvider(make_descriptor(ProviderKind.INSPIRE, timeout_s=30.0))

    async def run() -> None:
        task = asyncio.create_task(_service(slow).search(QUERY))
        await asyncio.sleep(0.05)
        task.cancel()
        await task

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(run())


def test_cancelled_error_raised_by_a_provider_is_not_swallowed() -> None:
    raising = RaisingProvider(make_descriptor(ProviderKind.INSPIRE), error=asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(_service(raising).search(QUERY))


def test_order_independence_with_shuffled_construction() -> None:
    def build(seed: int) -> FederationService:
        providers = [
            FakeProvider(
                make_descriptor(ProviderKind.INSPIRE),
                search_outcome=SearchResult(
                    reranked([inspire("1", DOI_A, ARXIV), inspire("2")]), 2, 0
                ),
            ),
            FakeProvider(
                make_descriptor(ProviderKind.ARXIV),
                search_outcome=SearchResult((arxiv("2109.05124v2"),), 1, 0),
            ),
            FakeProvider(
                make_descriptor(ProviderKind.LOCAL),
                search_outcome=SearchResult((local("notes/a.md", identity(ARXIV)),), 1, 0),
            ),
        ]
        random.Random(seed).shuffle(providers)
        return FederationService(
            providers, FederationPolicy(live=True, precedence=("inspire", "arxiv", "local"))
        )

    results = [asyncio.run(build(seed).search(QUERY)) for seed in range(10)]
    stripped = [(r.groups, tuple(replace(rep, elapsed_ms=0) for rep in r.reports)) for r in results]
    assert all(item == stripped[0] for item in stripped)


# ---------------------------------------------------------------------- fetch and health


def test_fetch_routing() -> None:
    target = arxiv("2109.05124v2")
    arxiv_p = FakeProvider(make_descriptor(ProviderKind.ARXIV), fetch_outcome=fetch_result(target))
    inspire_p = FakeProvider(make_descriptor(ProviderKind.INSPIRE))
    service = FederationService(
        [inspire_p, arxiv_p],
        FederationPolicy(live=True),
        disabled=[make_descriptor(ProviderKind.HEPDATA)],
    )
    outcome = asyncio.run(service.fetch(target.ref))
    assert not isinstance(outcome, ProviderError)
    assert outcome.candidate == target
    assert arxiv_p.calls == ["fetch"] and inspire_p.calls == []
    assert asyncio.run(service.fetch(CandidateRef("cds", "1"))) == ProviderError(
        ProviderErrorKind.NOT_CONFIGURED, "unknown_provider"
    )
    assert asyncio.run(service.fetch(CandidateRef("hepdata", "x"))) == ProviderError(
        ProviderErrorKind.NOT_CONSULTED, "disabled"
    )
    offline = FederationService([arxiv_p], FederationPolicy(live=False))
    assert asyncio.run(offline.fetch(target.ref)) == ProviderError(
        ProviderErrorKind.NOT_CONSULTED, "live_disabled"
    )


def test_fetch_errors_and_contract_violations() -> None:
    target = arxiv("2109.05124v2")
    other = arxiv("2111.08590v1")
    wrong = FakeProvider(make_descriptor(ProviderKind.ARXIV), fetch_outcome=fetch_result(other))
    assert asyncio.run(_service(wrong).fetch(target.ref)) == ProviderError(
        ProviderErrorKind.MALFORMED_RESPONSE, "contract_violation"
    )
    missing = FakeProvider(make_descriptor(ProviderKind.ARXIV))
    assert asyncio.run(_service(missing).fetch(target.ref)) == ProviderError(
        ProviderErrorKind.NOT_FOUND, "not_found"
    )
    raising = RaisingProvider(make_descriptor(ProviderKind.ARXIV))
    assert asyncio.run(_service(raising).fetch(target.ref)) == ProviderError(
        ProviderErrorKind.INTERNAL_ERROR, "unexpected_exception"
    )


def test_health_under_live_false_and_guarded_health() -> None:
    inspire_p = FakeProvider(make_descriptor(ProviderKind.INSPIRE))
    local_p = FakeProvider(make_descriptor(ProviderKind.LOCAL))
    service = FederationService(
        [inspire_p, local_p],
        FederationPolicy(live=False),
        disabled=[make_descriptor(ProviderKind.HEPDATA)],
    )
    health = asyncio.run(service.health())
    assert [(h.provider_id, h.state) for h in health] == [
        ("inspire", HealthState.NOT_CONSULTED),
        ("local", HealthState.AVAILABLE),
        ("hepdata", HealthState.NOT_CONSULTED),
    ]
    assert health[0].error == ProviderError(ProviderErrorKind.NOT_CONSULTED, "live_disabled")
    assert health[2].error == ProviderError(ProviderErrorKind.NOT_CONSULTED, "disabled")
    assert inspire_p.calls == []


def test_health_maps_exceptions_timeouts_and_wrong_ids() -> None:
    raising = RaisingProvider(make_descriptor(ProviderKind.INSPIRE))
    wrong = FakeProvider(
        make_descriptor(ProviderKind.ARXIV),
        health_outcome=ProviderHealth("inspire", HealthState.AVAILABLE, None),
    )
    slow = SleepingProvider(make_descriptor(ProviderKind.MCP, timeout_s=1.0))
    health = asyncio.run(_service(raising, wrong, slow, grace_s=0.0).health(deep=True))
    assert [h.state for h in health] == [HealthState.UNAVAILABLE] * 3
    assert [h.error.code for h in health if h.error] == [
        "unexpected_exception",
        "contract_violation",
        "federation_deadline",
    ]
