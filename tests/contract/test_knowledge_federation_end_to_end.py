"""M3 exit criterion: one query returns normalized, de-duplicated evidence from several
providers through recorded fixtures, and a failing provider is reported, not hidden.

Everything runs offline: the public providers replay recorded exchanges (synthetic
fixtures are refused for the exit run), the local library is synthetic, and the MCP
variant launches a local process that exits at once.

The INSPIRE ranking drifted between the spec's live check and the recording: 1920956 is
rank 1 and the thesis 2744105 rank 3, so the group order below follows the recording.
The properties the spec requires after a re-recording are asserted as well.
"""

from __future__ import annotations

import asyncio
import json
import random
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from http_replay import ReplayTransport, load_fixture, replay_factory
from knowledge_adapters import CLOCK, FIXTURES
from knowledge_contract import SleepingProvider, make_descriptor
from knowledge_exit import (
    EXIT_HOSTS,
    GOLDEN,
    LOCAL_TITLE,
    exit_cli_json,
    exit_query,
    exit_settings,
    exit_transport,
    make_library,
    recorded,
)
from mcp_testing import make_settings, trusted_python
from provenance_builders import CountingIdFactory, StepClock

from asca.application.knowledge.federation import (
    AssessedCandidate,
    EvidenceGroup,
    FederatedSearchResult,
    FederationPolicy,
    FederationService,
    GroupFlag,
    ProviderStatus,
)
from asca.application.knowledge.models import (
    CandidateRef,
    FetchOutcome,
    FetchResult,
    ProviderError,
    ProviderErrorKind,
    ProviderKind,
)
from asca.application.knowledge.pids import pid_text
from asca.application.knowledge.policy import suggest_authority
from asca.application.knowledge.registration import (
    KnowledgeRegistrationService,
    RegistrationChoice,
    RegistrationResult,
)
from asca.application.provenance import ProvenanceService
from asca.domain.provenance import (
    AccessClass,
    ClaimVerificationState,
    Locator,
    LocatorKind,
    LocatorPart,
    SourceAuthority,
    SourceVersion,
)
from asca.infrastructure.knowledge.__main__ import dumps, search_view
from asca.infrastructure.knowledge.config import effective_precedence
from asca.infrastructure.knowledge.factory import build_federation, build_providers
from asca.infrastructure.knowledge.http import USER_AGENT
from asca.infrastructure.memory_provenance import InMemoryProvenanceRepository

pytestmark = pytest.mark.contract

JOURNAL_DOI = "doi:10.1088/1748-0221/17/01/p01002"
PROCEEDINGS_DOI = "doi:10.1088/1748-0221/17/04/c04010"
QUOTE = "Optimal filtering minimises the noise variance of the amplitude estimate."


def search(federation: FederationService) -> FederatedSearchResult:
    return asyncio.run(federation.search(exit_query()))


def exit_federation(library: Path, transport: ReplayTransport) -> FederationService:
    return build_federation(
        exit_settings(library),
        live=True,
        clock=CLOCK,
        client_factory=replay_factory(transport),
        environ={},
    )


def members(group: EvidenceGroup) -> list[tuple[str, str, int, str, str]]:
    return [
        (
            item.candidate.ref.provider_id,
            item.candidate.ref.native_id,
            item.candidate.rank,
            item.suggestion.authority.letter,
            item.suggestion.rule.value,
        )
        for item in group.members
    ]


def group_by_key(result: FederatedSearchResult, key: str) -> EvidenceGroup:
    matches = [group for group in result.groups if group.key == key]
    assert len(matches) == 1
    return matches[0]


def provenance_service() -> ProvenanceService:
    clock = StepClock(datetime(2026, 11, 15, tzinfo=UTC))
    return ProvenanceService(InMemoryProvenanceRepository(), clock, CountingIdFactory())


# ---------------------------------------------------------------------- 16.1


def test_one_query_returns_deduplicated_evidence_from_several_providers_and_reports_the_failure(
    tmp_path: Path,
) -> None:
    library = make_library(tmp_path)
    transport = exit_transport()
    provenance = provenance_service()
    project = provenance.create_project("M3 exit project", is_synthetic=False)
    revision_before = provenance.load(project).revision

    result = search(exit_federation(library, transport))

    # 1. Every provider is reported, in precedence order; the failure is not hidden.
    reports = [
        (report.provider_id, report.status, report.returned, report.total_reported)
        for report in result.reports
    ]
    assert reports == [
        ("inspire", ProviderStatus.OK, 5, 17),
        ("arxiv", ProviderStatus.OK, 4, 4),
        ("hepdata", ProviderStatus.FAILED, 0, None),
        ("local", ProviderStatus.OK, 1, 1),
    ]
    assert result.reports[2].error == ProviderError(ProviderErrorKind.BLOCKED, "bot_challenge", 403)
    assert result.complete is False
    assert [report.provider_id for report in result.not_consulted] == ["hepdata"]

    # 2. The journal article, its preprint and the internal note are one group.
    journal = group_by_key(result, JOURNAL_DOI)
    assert [pid_text(pid) for pid in journal.identity_pids] == [
        JOURNAL_DOI,
        "arxiv:2109.05124",
        "inspire:1920956",
    ]
    assert members(journal) == [
        ("inspire", "1920956", 1, "A", "inspire.refereed/1"),
        ("arxiv", "2109.05124v2", 0, "D", "arxiv.preprint/1"),
        ("local", "notes/optimal-filtering.md", 0, "D", "local.declared/1"),
    ]
    assert journal.members[2].candidate.title == LOCAL_TITLE
    assert journal.flags == frozenset({GroupFlag.ACCESS_MIXED})
    assert journal.effective_access_class is AccessClass.INTERNAL
    # Fields are never fused: each member keeps its own version and access.
    assert [item.candidate.version.label for item in journal.members] == [
        JOURNAL_DOI,
        "arXiv:2109.05124v2",
        "declared:2026-11-01",
    ]
    assert [item.candidate.access_class for item in journal.members] == [
        AccessClass.PUBLIC,
        AccessClass.PUBLIC,
        AccessClass.INTERNAL,
    ]

    # 3. The proceedings and their preprint are one group; refereed is unknown, so D.
    proceedings = group_by_key(result, PROCEEDINGS_DOI)
    assert members(proceedings) == [
        ("inspire", "1969369", 2, "D", "inspire.other/1"),
        ("arxiv", "2111.08590v1", 2, "D", "arxiv.preprint/1"),
    ]
    assert proceedings.members[0].candidate.facts.refereed is None
    assert proceedings.flags == frozenset()

    # 4. Seven groups, no identity pid in two groups, deterministic order.
    assert [[(m[0], m[1]) for m in members(group)] for group in result.groups] == [
        [("inspire", "458161")],
        [
            ("inspire", "1920956"),
            ("arxiv", "2109.05124v2"),
            ("local", "notes/optimal-filtering.md"),
        ],
        [("arxiv", "2302.07555v2")],
        [("inspire", "1969369"), ("arxiv", "2111.08590v1")],
        [("inspire", "2744105")],
        [("arxiv", "2510.11469v3")],
        [("inspire", "2013724")],
    ]
    seen = [pid for group in result.groups for pid in group.identity_pids]
    assert len(seen) == len(set(seen))

    # Properties that must survive a re-recording (spec 16.1).
    usable = [r for r in result.reports if r.status in (ProviderStatus.OK, ProviderStatus.PARTIAL)]
    assert len(usable) >= 2
    assert any(
        {(m.candidate.kind, m.suggestion.authority) for m in group.members}
        >= {
            (ProviderKind.INSPIRE, SourceAuthority.PUBLISHED),
            (ProviderKind.ARXIV, SourceAuthority.WORKING_MATERIAL),
        }
        for group in result.groups
    )

    # 5. The CLI JSON for the same run is byte-identical to the reviewed golden.
    expected = GOLDEN.read_text(encoding="utf-8")
    assert dumps(search_view(result)) == expected
    cli_transport = exit_transport()
    assert exit_cli_json(tmp_path, cli_transport) == expected

    # 6. Only the three public hosts, every request matched and polite.
    for replay in (transport, cli_transport):
        replay.assert_all_used()
        assert {request.url.host for request in replay.requests} == EXIT_HOSTS
        for request in replay.requests:
            assert request.url.scheme == "https"
            assert request.headers["User-Agent"] == USER_AGENT
            assert request.headers["Accept-Encoding"] == "identity"
            assert "cookie" not in request.headers
            assert "authorization" not in request.headers

    # 7. Search never writes provenance.
    assert provenance.load(project).revision == revision_before


def test_the_exit_run_is_deterministic_under_shuffling_and_delays(tmp_path: Path) -> None:
    library = make_library(tmp_path)
    settings = exit_settings(library)
    expected = GOLDEN.read_text(encoding="utf-8")
    for seed in range(20):
        rng = random.Random(seed)
        delays = {host: rng.uniform(0.0, 0.02) for host in sorted(EXIT_HOSTS)}
        transport = exit_transport(delays)
        enabled, disabled = build_providers(
            settings, clock=CLOCK, client_factory=replay_factory(transport), environ={}
        )
        shuffled = list(enabled)
        rng.shuffle(shuffled)
        policy = FederationPolicy(live=True, precedence=effective_precedence(settings))
        result = search(FederationService(shuffled, policy, disabled=disabled))
        assert dumps(search_view(result)) == expected, f"seed {seed}"
        transport.assert_all_used()


def test_the_exit_helper_refuses_synthetic_fixtures() -> None:
    with pytest.raises(AssertionError, match="recorded fixtures only"):
        recorded("arxiv/unavailable_503.json")


def test_without_live_the_exit_run_sends_no_request(tmp_path: Path) -> None:
    library = make_library(tmp_path)
    transport = exit_transport()
    federation = build_federation(
        exit_settings(library),
        live=False,
        clock=CLOCK,
        client_factory=replay_factory(transport),
        environ={},
    )
    result = search(federation)
    assert transport.requests == []
    assert [(r.provider_id, r.status) for r in result.reports] == [
        ("inspire", ProviderStatus.SKIPPED),
        ("arxiv", ProviderStatus.SKIPPED),
        ("hepdata", ProviderStatus.SKIPPED),
        ("local", ProviderStatus.OK),
    ]
    assert {r.error.code for r in result.reports if r.error is not None} == {"live_disabled"}


# ---------------------------------------------------------------------- 16.2


def test_registration_and_claim_check_from_fetched_text(tmp_path: Path) -> None:
    transport = ReplayTransport(
        [recorded("inspire/fetch_1920956.json"), recorded("arxiv/fetch_2109.05124v2.json")]
    )
    federation = exit_federation(make_library(tmp_path), transport)

    async def fetch_both() -> tuple[FetchOutcome, FetchOutcome]:
        inspire = await federation.fetch(CandidateRef("inspire", "1920956"))
        arxiv = await federation.fetch(CandidateRef("arxiv", "2109.05124v2"))
        return inspire, arxiv

    inspire, arxiv = asyncio.run(fetch_both())
    assert isinstance(inspire, FetchResult) and isinstance(arxiv, FetchResult)
    transport.assert_all_used()
    assert QUOTE in inspire.document.text

    provenance = provenance_service()
    project = provenance.create_project("M3 registration project", is_synthetic=False)
    registration = KnowledgeRegistrationService(provenance)

    def register(fetched: FetchResult, authority: SourceAuthority) -> RegistrationResult:
        candidate = fetched.candidate
        descriptor = federation.descriptor(candidate.ref.provider_id)
        assert descriptor is not None
        return registration.register(
            project,
            AssessedCandidate(candidate, suggest_authority(candidate)),
            descriptor,
            fetched.document,
            RegistrationChoice(authority=authority),
        )

    # The INSPIRE member suggests A, so PUBLISHED needs no written basis.
    assert suggest_authority(inspire.candidate).authority is SourceAuthority.PUBLISHED
    published = register(inspire, SourceAuthority.PUBLISHED)
    preprint = register(arxiv, SourceAuthority.WORKING_MATERIAL)
    assert published.created_source and published.created_version
    assert not preprint.created_source and preprint.created_version
    assert preprint.source_id == published.source_id

    graph = provenance.load(project)
    assert len(graph.sources) == 1
    source = graph.sources[0]
    assert source.persistent_id is not None
    assert pid_text(source.persistent_id) == JOURNAL_DOI
    versions = sorted(version.version_label for version in graph.versions)
    assert versions == ["arXiv:2109.05124v2", JOURNAL_DOI]
    journal_version = graph.get(SourceVersion, published.version_id)
    assert journal_version.retrieved_at == inspire.document.retrieved_at
    assert "asca-authority/1" in journal_version.authority_basis

    locator = Locator((LocatorPart(LocatorKind.SECTION, "abstract"),))
    claim = provenance.add_claim(
        project,
        published.version_id,
        quote=QUOTE,
        locator=locator,
    )
    state = provenance.check_claim_text(project, claim, inspire.document.text)
    assert state is ClaimVerificationState.SOURCE_TEXT_CHECKED

    wrong = provenance.add_claim(
        project,
        published.version_id,
        quote="The neural network replaces the calorimeter entirely.",
        locator=locator,
    )
    assert (
        provenance.check_claim_text(project, wrong, inspire.document.text)
        is ClaimVerificationState.MISMATCH
    )

    again = register(inspire, SourceAuthority.PUBLISHED)
    assert again.created_version is False
    assert again.version_id == published.version_id
    assert len(provenance.load(project).versions) == 2


# ---------------------------------------------------------------------- 16.3


def test_unavailable_provider_variants(tmp_path: Path) -> None:
    library = make_library(tmp_path)
    settings = exit_settings(library)

    # arXiv answers 503: evidence still comes from INSPIRE and the local library.
    unavailable = ReplayTransport(
        [
            recorded("inspire/lar_nn_search.json"),
            load_fixture(FIXTURES / "arxiv" / "unavailable_503.json"),
            recorded("hepdata/lar_nn_search_blocked.json"),
        ]
    )
    result = search(exit_federation(library, unavailable))
    unavailable.assert_all_used()
    arxiv = result.reports[1]
    assert (arxiv.provider_id, arxiv.status) == ("arxiv", ProviderStatus.FAILED)
    assert arxiv.error == ProviderError(ProviderErrorKind.HTTP_STATUS, "http_503", 503, 10)
    providers = {
        item.candidate.ref.provider_id for group in result.groups for item in group.members
    }
    assert providers == {"inspire", "local"}
    assert {r.provider_id for r in result.not_consulted} == {"arxiv", "hepdata"}

    # A provider that ignores its own timeout is stopped by the federation deadline.
    transport = exit_transport()
    enabled, disabled = build_providers(
        settings, clock=CLOCK, client_factory=replay_factory(transport), environ={}
    )
    sleepy = SleepingProvider(make_descriptor(ProviderKind.MCP, "mcp:sleepy", timeout_s=1.0))
    federation = FederationService(
        [*enabled, sleepy], FederationPolicy(live=True, grace_s=0.0), disabled=disabled
    )
    result = search(federation)
    timed_out = result.reports[-1]
    assert (timed_out.provider_id, timed_out.status) == ("mcp:sleepy", ProviderStatus.FAILED)
    assert timed_out.error == ProviderError(ProviderErrorKind.TIMEOUT, "federation_deadline")
    assert timed_out.elapsed_ms < 3000
    assert [r.status for r in result.reports[:4]] == [
        ProviderStatus.OK,
        ProviderStatus.OK,
        ProviderStatus.FAILED,
        ProviderStatus.OK,
    ]
    assert len(result.groups) == 7

    # A configured stdio MCP server whose command exits at once is reported as failed.
    broken = make_settings(
        server_id="broken",
        command=trusted_python(),
        args=("-I", "-c", "import sys; sys.exit(3)"),
        timeout_s=5.0,
    )
    transport = exit_transport()
    federation = build_federation(
        replace(settings, mcp=(broken,)),
        live=True,
        clock=CLOCK,
        client_factory=replay_factory(transport),
        environ={},
    )
    result = search(federation)
    assert [r.provider_id for r in result.reports] == [
        "inspire",
        "arxiv",
        "hepdata",
        "local",
        "mcp:broken",
    ]
    mcp = result.reports[-1]
    assert mcp.status is ProviderStatus.FAILED
    assert mcp.error is not None and mcp.error.kind is ProviderErrorKind.PROCESS_FAILED
    assert len(result.groups) == 7
    assert json.loads(dumps(search_view(result)))["complete"] is False
