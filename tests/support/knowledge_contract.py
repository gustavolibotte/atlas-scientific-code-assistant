"""Shared knowledge-provider contract check, fake providers and candidate builders.

Everything here is synthetic. DOIs use the ``10.5555/asca-test.<n>`` test prefix.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime

from asca.application.knowledge.models import (
    PUBLIC_NETWORK_KINDS,
    CandidatePid,
    CandidateRef,
    CandidateVersion,
    ContentAvailability,
    DocumentKind,
    FetchedDocument,
    FetchOutcome,
    FetchResult,
    HealthState,
    KnowledgeCandidate,
    KnowledgeQuery,
    LicenseInfo,
    LicenseScope,
    PartialDate,
    PidOrigin,
    PidRole,
    ProviderDescriptor,
    ProviderError,
    ProviderErrorKind,
    ProviderHealth,
    ProviderKind,
    PublicationFacts,
    SearchOutcome,
    SearchResult,
    VersionKind,
)
from asca.application.knowledge.pids import pid_sort_key
from asca.application.ports import KnowledgeProvider
from asca.domain.provenance import (
    AccessClass,
    PersistentIdentifier,
    PidScheme,
    SourceAuthority,
    sha256_text,
)

RETRIEVED_AT = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)
CREDENTIAL_MARKERS = ("bearer ", "authorization", "cookie", "password", "secret")
INTERNAL_CONDITIONS = "Synthetic internal test material."

_ADAPTERS = {
    ProviderKind.INSPIRE: "inspire/1",
    ProviderKind.ARXIV: "arxiv/1",
    ProviderKind.HEPDATA: "hepdata/1",
    ProviderKind.LOCAL: "local/1",
    ProviderKind.MCP: "mcp/1",
}


def make_descriptor(
    kind: ProviderKind,
    provider_id: str | None = None,
    *,
    access_class: AccessClass = AccessClass.PUBLIC,
    max_query_access: AccessClass | None = None,
    timeout_s: float = 5.0,
    supports_fetch: bool = True,
) -> ProviderDescriptor:
    if provider_id is None:
        provider_id = "mcp:test" if kind is ProviderKind.MCP else kind.value
    if max_query_access is None:
        if kind is ProviderKind.LOCAL:
            max_query_access = AccessClass.RESTRICTED
        elif kind is ProviderKind.MCP:
            max_query_access = access_class
        else:
            max_query_access = AccessClass.PUBLIC
    return ProviderDescriptor(
        id=provider_id,
        kind=kind,
        label=f"Test {kind.value}",
        adapter_version=_ADAPTERS[kind],
        access_class=access_class,
        access_conditions=None if access_class is AccessClass.PUBLIC else INTERNAL_CONDITIONS,
        max_query_access=max_query_access,
        uses_network=kind is not ProviderKind.LOCAL,
        supports_fetch=supports_fetch,
        timeout_s=timeout_s,
    )


def pid(text: str) -> PersistentIdentifier:
    scheme, _, value = text.partition(":")
    return PersistentIdentifier(PidScheme(scheme), value)


def identity(text: str, origin: PidOrigin = PidOrigin.CURATED_LINK) -> CandidatePid:
    return CandidatePid(pid(text), PidRole.IDENTITY, origin)


def related(text: str, origin: PidOrigin = PidOrigin.CURATED_LINK) -> CandidatePid:
    return CandidatePid(pid(text), PidRole.RELATED, origin)


def _default_version(kind: ProviderKind, native_id: str) -> CandidateVersion:
    if kind is ProviderKind.ARXIV:
        return CandidateVersion(VersionKind.ARXIV_VERSION, f"arXiv:{native_id}")
    if kind is ProviderKind.INSPIRE:
        return CandidateVersion(VersionKind.RECORD_SNAPSHOT, f"inspire:{native_id}@2026-11-01")
    if kind in (ProviderKind.LOCAL, ProviderKind.MCP):
        return CandidateVersion(VersionKind.DECLARED, "declared:2026-11-01")
    return CandidateVersion(VersionKind.DATASET_VERSION, "doi:10.17182/hepdata.1.v1")


def make_candidate(
    kind: ProviderKind = ProviderKind.INSPIRE,
    native_id: str = "1",
    *,
    provider_id: str | None = None,
    rank: int = 0,
    pids: Iterable[CandidatePid] = (),
    title: str = "Synthetic candidate",
    version: CandidateVersion | None = None,
    access_class: AccessClass = AccessClass.PUBLIC,
    refereed: bool | None = None,
    generated: bool = False,
    declared_authority: SourceAuthority | None = None,
    issued: PartialDate | None = None,
) -> KnowledgeCandidate:
    if provider_id is None:
        provider_id = "mcp:test" if kind is ProviderKind.MCP else kind.value
    if declared_authority is None and kind in (ProviderKind.LOCAL, ProviderKind.MCP):
        declared_authority = SourceAuthority.WORKING_MATERIAL
    return KnowledgeCandidate(
        ref=CandidateRef(provider_id, native_id),
        kind=kind,
        rank=rank,
        title=title,
        title_truncated=False,
        authors=("A. Author",),
        author_count=1,
        issued=issued,
        version=version or _default_version(kind, native_id),
        pids=tuple(sorted(pids, key=lambda item: pid_sort_key(item.pid))),
        landing_url=None,
        access_class=access_class,
        access_conditions=None if access_class is AccessClass.PUBLIC else INTERNAL_CONDITIONS,
        facts=PublicationFacts(
            refereed=refereed,
            document_types=("article",),
            journal_ref=None,
            collaborations=(),
            generated=generated,
        ),
        declared_authority=declared_authority,
        content=ContentAvailability.ABSTRACT,
        licenses=(LicenseInfo("CC0-1.0", None, LicenseScope.METADATA),),
        snippet="Synthetic snippet.",
        retrieved_at=RETRIEVED_AT,
    )


def make_document(
    candidate: KnowledgeCandidate, text: str = "Synthetic text.\n"
) -> FetchedDocument:
    return FetchedDocument(
        ref=candidate.ref,
        kind=DocumentKind.ABSTRACT_TEXT,
        media_type="text/plain; charset=utf-8",
        text=text,
        text_sha256=sha256_text(text),
        raw_sha256=None,
        retrieved_at=RETRIEVED_AT,
        source_url=None,
        access_class=candidate.access_class,
        access_conditions=candidate.access_conditions,
        licenses=candidate.licenses,
        redactions=0,
    )


def reranked(candidates: Iterable[KnowledgeCandidate]) -> tuple[KnowledgeCandidate, ...]:
    return tuple(replace(item, rank=index) for index, item in enumerate(candidates))


@dataclass
class FakeProvider:
    """A provider returning canned outcomes and recording every call."""

    descriptor: ProviderDescriptor
    search_outcome: SearchOutcome | None = None
    fetch_outcome: FetchOutcome | None = None
    health_outcome: ProviderHealth | None = None
    calls: list[str] = field(default_factory=list)

    async def search(self, query: KnowledgeQuery) -> SearchOutcome:
        self.calls.append("search")
        if query.access_class.rank > self.descriptor.max_query_access.rank:
            return ProviderError(ProviderErrorKind.NOT_CONSULTED, "query_access_class")
        if self.search_outcome is not None:
            return self.search_outcome
        return SearchResult((), 0, 0)

    async def fetch(self, ref: CandidateRef) -> FetchOutcome:
        self.calls.append("fetch")
        if ref.provider_id != self.descriptor.id:
            return ProviderError(ProviderErrorKind.UNSUPPORTED, "invalid_native_id")
        if self.fetch_outcome is not None:
            return self.fetch_outcome
        return ProviderError(ProviderErrorKind.NOT_FOUND, "not_found")

    async def health(self, *, deep: bool = False) -> ProviderHealth:
        self.calls.append("health")
        if self.health_outcome is not None:
            return self.health_outcome
        return ProviderHealth(self.descriptor.id, HealthState.AVAILABLE, None)


@dataclass
class SleepingProvider(FakeProvider):
    """Ignores its own timeout and sleeps; the federation deadline must stop it."""

    delay_s: float = 60.0

    async def search(self, query: KnowledgeQuery) -> SearchOutcome:
        self.calls.append("search")
        await asyncio.sleep(self.delay_s)
        return SearchResult((), 0, 0)  # pragma: no cover - always cancelled in tests

    async def fetch(self, ref: CandidateRef) -> FetchOutcome:
        self.calls.append("fetch")
        await asyncio.sleep(self.delay_s)
        return ProviderError(ProviderErrorKind.NOT_FOUND, "not_found")  # pragma: no cover

    async def health(self, *, deep: bool = False) -> ProviderHealth:
        self.calls.append("health")
        await asyncio.sleep(self.delay_s)
        return ProviderHealth(self.descriptor.id, HealthState.AVAILABLE, None)  # pragma: no cover


@dataclass
class RaisingProvider(FakeProvider):
    """Raises ``error`` from every operation (an adapter bug)."""

    error: BaseException = field(default_factory=lambda: RuntimeError("secret-canary"))

    async def search(self, query: KnowledgeQuery) -> SearchOutcome:
        self.calls.append("search")
        raise self.error

    async def fetch(self, ref: CandidateRef) -> FetchOutcome:
        self.calls.append("fetch")
        raise self.error

    async def health(self, *, deep: bool = False) -> ProviderHealth:
        self.calls.append("health")
        raise self.error


def _assert_no_credentials(value: object) -> None:
    text = repr(value).lower()
    for marker in CREDENTIAL_MARKERS:
        assert marker not in text, f"returned value carries a credential marker: {marker!r}"


def _assert_search_contract(
    outcome: SearchOutcome, descriptor: ProviderDescriptor, query: KnowledgeQuery
) -> None:
    assert isinstance(outcome, SearchResult | ProviderError)
    if isinstance(outcome, ProviderError):
        return
    assert len(outcome.candidates) <= query.limit
    for index, candidate in enumerate(outcome.candidates):
        assert candidate.ref.provider_id == descriptor.id
        assert candidate.kind is descriptor.kind
        assert candidate.rank == index
        assert candidate.access_class.rank >= descriptor.access_class.rank
        if descriptor.kind in PUBLIC_NETWORK_KINDS:
            assert candidate.access_class is AccessClass.PUBLIC


def assert_provider_contract(provider: KnowledgeProvider, query: KnowledgeQuery) -> None:
    """Check the port contract (section 3.6) for one adapter, without network side effects.

    ``query`` must be answerable by the adapter's test transport. Errors are returned as
    values (an exception escaping here fails the test), fetch refuses a foreign ref, a
    query above ``max_query_access`` is refused, and nothing carries credentials.
    """
    descriptor = provider.descriptor

    async def run() -> None:
        outcome = await provider.search(query)
        _assert_search_contract(outcome, descriptor, query)
        _assert_no_credentials(outcome)

        foreign = CandidateRef("other-provider", "x")
        fetched = await provider.fetch(foreign)
        assert isinstance(fetched, ProviderError)
        assert (fetched.kind, fetched.code) == (ProviderErrorKind.UNSUPPORTED, "invalid_native_id")

        if descriptor.max_query_access is not AccessClass.RESTRICTED:
            sensitive = KnowledgeQuery(query.text, query.limit, AccessClass.RESTRICTED)
            refused = await provider.search(sensitive)
            assert isinstance(refused, ProviderError)
            assert (refused.kind, refused.code) == (
                ProviderErrorKind.NOT_CONSULTED,
                "query_access_class",
            )

        health = await provider.health(deep=False)
        assert isinstance(health, ProviderHealth)
        assert health.provider_id == descriptor.id
        _assert_no_credentials(health)

    asyncio.run(run())


def fetch_result(candidate: KnowledgeCandidate, text: str = "Synthetic text.\n") -> FetchResult:
    return FetchResult(candidate, make_document(candidate, text))
