"""arXiv Atom API adapter (``arxiv/1``): search, fetch and health.

XML is parsed only through defusedxml with DTDs, entities and external references
forbidden, after a pre-check that refuses any ``<!DOCTYPE`` or ``<!ENTITY`` in the first
4 KiB. Requests are spaced at least 3 s apart over one connection (arXiv etiquette); the
search query is built from stopword-filtered lowercase terms only, so no query-language
syntax ever reaches arXiv.
"""

import asyncio
import re
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Final, Protocol

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring

from asca.application.knowledge.models import (
    AUTHOR_MAX,
    AUTHORS_MAX,
    JOURNAL_REF_MAX,
    SNIPPET_MAX,
    CandidatePid,
    CandidateRef,
    CandidateVersion,
    ContentAvailability,
    FetchOutcome,
    FetchResult,
    HealthState,
    KnowledgeCandidate,
    KnowledgeQuery,
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
from asca.application.knowledge.pids import normalize_arxiv, normalize_doi
from asca.application.knowledge.text import clean_line, query_terms
from asca.application.ports import Clock
from asca.domain.provenance import TITLE_MAX, AccessClass
from asca.infrastructure.knowledge.adapter_common import (
    ABSTRACT_TEXT_MAX,
    CC0_METADATA,
    assemble_pids,
    block,
    error,
    gated_get,
    has_content_type,
    health_from,
    line,
    public_descriptor,
    refuse_query,
    refuse_ref,
    text_document,
    timed_out,
    unexpected_payload,
    within_timeout,
    wrong_content_type,
)
from asca.infrastructure.knowledge.http import (
    ClientFactory,
    ClientSpec,
    MinIntervalGate,
    RawResponse,
    default_client_factory,
)
from asca.infrastructure.knowledge.settings import (
    ARXIV_MIN_INTERVAL,
    ArxivSettings,
    NetworkSettings,
)


class Element(Protocol):
    """The part of a parsed XML element this adapter reads (no stdlib XML import here)."""

    tag: str

    def findtext(self, path: str) -> str | None: ...
    def findall(self, path: str) -> Sequence["Element"]: ...


ARXIV_API: Final = "https://export.arxiv.org/api/query"
ARXIV_HOST: Final = "export.arxiv.org"
ARXIV_LANDING: Final = "https://arxiv.org/abs/"
ATOM: Final = "http://www.w3.org/2005/Atom"
ARXIV_NS: Final = "http://arxiv.org/schemas/atom"
OPENSEARCH: Final = "http://a9.com/-/spec/opensearch/1.1/"
NATIVE_ID_RE: Final = r"(\d{4}\.\d{4,5}|[a-z][a-z-]*(\.[A-Z]{2})?/\d{7})(v[1-9]\d{0,3})?"
ADAPTER_VERSION: Final = "arxiv/1"
SEARCH_MAX_BYTES: Final = 1_048_576
FETCH_MAX_BYTES: Final = 262_144
QUERY_TERMS_MAX: Final = 8
ENTRIES_MAX: Final = 25
PRECHECK_BYTES: Final = 4_096
ATOM_CONTENT_TYPE: Final = "application/atom+xml"
HEALTH_ID: Final = "0912.2642"
_NATIVE_ID = re.compile(NATIVE_ID_RE)
_ENTRY_ID = re.compile(
    r"https?://arxiv\.org/abs/(?P<id>\d{4}\.\d{4,5}|[a-z][a-z-]*(\.[A-Z]{2})?/\d{7})"
    r"v(?P<v>[1-9]\d{0,3})"
)
_ERROR_ID = re.compile(r"https?://arxiv\.org/api/errors")
_TAG = {
    "entry": f"{{{ATOM}}}entry",
    "id": f"{{{ATOM}}}id",
    "title": f"{{{ATOM}}}title",
    "summary": f"{{{ATOM}}}summary",
    "published": f"{{{ATOM}}}published",
    "author": f"{{{ATOM}}}author",
    "name": f"{{{ATOM}}}name",
    "doi": f"{{{ARXIV_NS}}}doi",
    "journal_ref": f"{{{ARXIV_NS}}}journal_ref",
    "total": f"{{{OPENSEARCH}}}totalResults",
}


# ---------------------------------------------------------------------- request building


def search_params(query: KnowledgeQuery) -> tuple[tuple[str, str], ...] | None:
    """``all:<term>`` clauses joined by AND; ``None`` when no usable term remains."""
    terms = query_terms(query.text, QUERY_TERMS_MAX)
    if not terms:
        return None
    return (
        ("search_query", " AND ".join(f"all:{term}" for term in terms)),
        ("start", "0"),
        ("max_results", str(query.limit)),
        ("sortBy", "relevance"),
        ("sortOrder", "descending"),
    )


def fetch_params(native_id: str) -> tuple[tuple[str, str], ...]:
    return (("id_list", native_id), ("max_results", "1"))


HEALTH_PARAMS: Final = fetch_params(HEALTH_ID)


# ---------------------------------------------------------------------- parsing


@dataclass(frozen=True, slots=True)
class _Feed:
    entries: tuple[Element, ...]
    total: int | None


def _invalid_xml() -> ProviderError:
    return error(ProviderErrorKind.MALFORMED_RESPONSE, "invalid_xml")


def parse_feed(raw: RawResponse) -> _Feed | ProviderError:
    """Content-type check, DTD pre-check, defusedxml parse, error-entry detection."""
    if not has_content_type(raw, ATOM_CONTENT_TYPE):
        return wrong_content_type()
    head = raw.body[:PRECHECK_BYTES]
    if b"<!DOCTYPE" in head or b"<!ENTITY" in head:
        return _invalid_xml()
    try:
        root = fromstring(raw.body, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (DefusedXmlException, ParseError, ValueError):
        return _invalid_xml()
    if root.tag != f"{{{ATOM}}}feed":
        return unexpected_payload()
    entries: tuple[Element, ...] = tuple(root.findall(_TAG["entry"]))[:ENTRIES_MAX]
    for entry in entries:
        if _ERROR_ID.match((entry.findtext(_TAG["id"]) or "").strip()):
            return error(ProviderErrorKind.MALFORMED_RESPONSE, "provider_error_entry")
    total_text = (root.findtext(_TAG["total"]) or "").strip()
    total = int(total_text) if total_text.isdigit() and total_text.isascii() else None
    return _Feed(entries, total)


def _candidate(
    entry: Element, rank: int, clock: Clock, native_id: str | None = None
) -> tuple[KnowledgeCandidate, str | None]:
    """Map one entry; raises ``ValueError`` when it cannot form a valid candidate."""
    match = _ENTRY_ID.fullmatch((entry.findtext(_TAG["id"]) or "").strip())
    if match is None:
        raise ValueError("arxiv entry id is not an abs URL with a version")
    normalized = normalize_arxiv(f"{match['id']}v{match['v']}")
    if normalized is None:
        raise ValueError("arxiv entry id is not a valid arXiv identifier")
    arxiv_pid, version = normalized
    versioned = f"{arxiv_pid.value}v{version}"
    title = clean_line(entry.findtext(_TAG["title"]) or "", TITLE_MAX)
    if title is None:
        raise ValueError("arxiv entry has a blank title")
    items = [CandidatePid(arxiv_pid, PidRole.IDENTITY, PidOrigin.NATIVE)]
    doi = normalize_doi(entry.findtext(_TAG["doi"]) or "")
    if doi is not None:
        items.append(CandidatePid(doi, PidRole.IDENTITY, PidOrigin.PROVIDER_ASSERTED))
    authors = entry.findall(_TAG["author"])
    names = [line(author.findtext(_TAG["name"]), AUTHOR_MAX) for author in authors]
    summary = entry.findtext(_TAG["summary"])
    abstract = block(summary, ABSTRACT_TEXT_MAX)
    published = entry.findtext(_TAG["published"])
    candidate = KnowledgeCandidate(
        ref=CandidateRef(ProviderKind.ARXIV.value, native_id or versioned),
        kind=ProviderKind.ARXIV,
        rank=rank,
        title=title[0],
        title_truncated=title[1],
        authors=tuple(name for name in names if name is not None)[:AUTHORS_MAX],
        author_count=len(authors),
        issued=None if published is None else PartialDate.parse(published),
        version=CandidateVersion(VersionKind.ARXIV_VERSION, f"arXiv:{versioned}"),
        pids=assemble_pids(items),
        landing_url=f"{ARXIV_LANDING}{versioned}",
        access_class=AccessClass.PUBLIC,
        access_conditions=None,
        facts=PublicationFacts(
            refereed=None,
            document_types=("preprint",),
            journal_ref=line(entry.findtext(_TAG["journal_ref"]), JOURNAL_REF_MAX),
            collaborations=(),
            generated=False,
        ),
        declared_authority=None,
        content=ContentAvailability.ABSTRACT if abstract else ContentAvailability.METADATA_ONLY,
        licenses=(CC0_METADATA,),
        snippet=block(summary, SNIPPET_MAX),
        retrieved_at=clock.now(),
    )
    return candidate, abstract


# ---------------------------------------------------------------------- provider


class ArxivProvider:
    """arXiv Atom API (public, at least 3 s between requests, one connection, no retries)."""

    def __init__(
        self,
        settings: ArxivSettings,
        *,
        network: NetworkSettings,
        clock: Clock,
        client_factory: ClientFactory = default_client_factory,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._settings = settings
        self._network = network
        self._clock = clock
        self._client_factory = client_factory
        self._monotonic = monotonic
        interval = max(ARXIV_MIN_INTERVAL, settings.min_interval_s)
        self._gate = MinIntervalGate(interval, monotonic=monotonic, sleep=sleep)
        self._descriptor = public_descriptor(
            ProviderKind.ARXIV,
            "arXiv",
            ADAPTER_VERSION,
            timeout_s=settings.timeout_s,
            supports_fetch=True,
        )

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    def client_spec(self, max_bytes: int) -> ClientSpec:
        return ClientSpec(
            host=ARXIV_HOST,
            timeout_s=self._settings.timeout_s,
            max_response_bytes=max_bytes,
            max_connections=1,
            accept=ATOM_CONTENT_TYPE,
        )

    async def _get(
        self, params: tuple[tuple[str, str], ...], max_bytes: int
    ) -> RawResponse | ProviderError:
        # The gate waits inside the provider timeout: the budget is the time left of it.
        return await gated_get(
            gate=self._gate,
            deadline=self._monotonic() + self._settings.timeout_s,
            monotonic=self._monotonic,
            client_factory=self._client_factory,
            spec=self.client_spec(max_bytes),
            network=self._network,
            url=ARXIV_API,
            params=params,
        )

    async def search(self, query: KnowledgeQuery) -> SearchOutcome:
        refused = refuse_query(query, self._descriptor)
        if refused is not None:
            return refused
        params = search_params(query)
        if params is None:
            return error(ProviderErrorKind.UNSUPPORTED, "empty_query")
        return await within_timeout(
            self._settings.timeout_s, lambda: self._search(query, params), timed_out()
        )

    async def _search(
        self, query: KnowledgeQuery, params: tuple[tuple[str, str], ...]
    ) -> SearchOutcome:
        raw = await self._get(params, SEARCH_MAX_BYTES)
        if isinstance(raw, ProviderError):
            return raw
        feed = parse_feed(raw)
        if isinstance(feed, ProviderError):
            return feed
        candidates: list[KnowledgeCandidate] = []
        dropped = 0
        for entry in feed.entries[: query.limit]:
            try:
                candidates.append(_candidate(entry, len(candidates), self._clock)[0])
            except ValueError:
                dropped += 1
        return SearchResult(tuple(candidates), feed.total, dropped)

    async def fetch(self, ref: CandidateRef) -> FetchOutcome:
        refused = refuse_ref(ref, self._descriptor, _NATIVE_ID)
        if refused is not None:
            return refused
        if normalize_arxiv(ref.native_id) is None:  # month and era digit rules
            return error(ProviderErrorKind.UNSUPPORTED, "invalid_native_id")
        return await within_timeout(self._settings.timeout_s, lambda: self._fetch(ref), timed_out())

    async def _fetch(self, ref: CandidateRef) -> FetchOutcome:
        raw = await self._get(fetch_params(ref.native_id), FETCH_MAX_BYTES)
        if isinstance(raw, ProviderError):
            return raw
        feed = parse_feed(raw)
        if isinstance(feed, ProviderError):
            return feed
        if not feed.entries:
            return error(ProviderErrorKind.NOT_FOUND, "not_found")
        try:
            candidate, abstract = _candidate(feed.entries[0], 0, self._clock, ref.native_id)
        except ValueError:
            return unexpected_payload()
        returned = candidate.version.label.removeprefix("arXiv:")
        if returned != ref.native_id and returned.rsplit("v", 1)[0] != ref.native_id:
            return unexpected_payload()
        document = text_document(
            ref=ref,
            title=candidate.title,
            abstract=abstract,
            raw=raw,
            retrieved_at=candidate.retrieved_at,
            licenses=candidate.licenses,
        )
        return FetchResult(candidate, document)

    async def health(self, *, deep: bool = False) -> ProviderHealth:
        """``NOT_PROBED`` without a request unless ``deep`` (arXiv etiquette)."""
        provider_id = self._descriptor.id
        if not deep:
            return ProviderHealth(provider_id, HealthState.NOT_PROBED, None)
        return await within_timeout(
            self._settings.timeout_s, self._health, health_from(provider_id, timed_out())
        )

    async def _health(self) -> ProviderHealth:
        raw = await self._get(HEALTH_PARAMS, FETCH_MAX_BYTES)
        if isinstance(raw, ProviderError):
            return health_from(self._descriptor.id, raw)
        feed = parse_feed(raw)
        return health_from(self._descriptor.id, feed if isinstance(feed, ProviderError) else None)
