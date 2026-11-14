"""HEPData search adapter (``hepdata/1``), search only, with a provisional parser.

The result field names come from the public hepdata-cli and HEPData sources and must be
confirmed against a recording made on the maintainer's machine (ADR 0040). A Cloudflare
challenge (403/503 with ``cf-mitigated: challenge``) maps to ``BLOCKED/bot_challenge`` and
is never solved, retried or evaded. Record fetch is deferred (``fetch_unsupported``).

A dataset never merges into its paper's group: its identity is the HEPData concept DOI,
and the INSPIRE id, publication DOI and arXiv id are RELATED pids only.
"""

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from asca.application.knowledge.models import (
    AUTHOR_MAX,
    COLLABORATIONS_MAX,
    CandidatePid,
    CandidateRef,
    CandidateVersion,
    ContentAvailability,
    FetchOutcome,
    KnowledgeCandidate,
    KnowledgeQuery,
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
from asca.application.knowledge.pids import (
    HEPDATA_DOI_PREFIX,
    normalize_arxiv,
    normalize_doi,
    normalize_inspire,
    split_hepdata_doi,
)
from asca.application.knowledge.text import clean_line
from asca.application.ports import Clock
from asca.domain.provenance import TITLE_MAX, AccessClass
from asca.infrastructure.knowledge.adapter_common import (
    CC0_METADATA,
    assemble_pids,
    error,
    gated_get,
    has_content_type,
    health_from,
    lines,
    public_descriptor,
    refuse_query,
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
    strict_json,
)
from asca.infrastructure.knowledge.settings import HepdataSettings, NetworkSettings

HEPDATA_SEARCH: Final = "https://www.hepdata.net/search/"
HEPDATA_HOST: Final = "www.hepdata.net"
HEPDATA_LANDING: Final = "https://www.hepdata.net/record/ins"
ADAPTER_VERSION: Final = "hepdata/1"
GATE_INTERVAL_S: Final = 1.0
SEARCH_MAX_BYTES: Final = 2_097_152
RESULTS_USED: Final = 25
JSON_CONTENT_TYPE: Final = "application/json"
HEALTH_QUERY: Final = "higgs"


def search_params(text: str, limit: int) -> tuple[tuple[str, str], ...]:
    return (("q", text), ("format", "json"), ("size", str(limit)), ("page", "1"))


# ---------------------------------------------------------------------- provisional model


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True, frozen=True)


class _Result(_Model):
    inspire_id: int | str | None = Field(default=None)
    title: str | None = Field(default=None, max_length=10_000)
    hepdata_doi: str | None = Field(default=None, max_length=1_000)
    version: int | None = None
    doi: str | None = Field(default=None, max_length=1_000)
    arxiv_id: str | None = Field(default=None, max_length=200)
    collaborations: list[str] = Field(default_factory=list, max_length=100)


class _Response(_Model):
    results: list[Any] = Field(max_length=1_000)
    total: int | None = Field(default=None, ge=0)


def _candidate(result: _Result, rank: int, clock: Clock) -> KnowledgeCandidate:
    """Map one result; raises ``ValueError`` when it cannot form a valid candidate."""
    if result.title is None or result.inspire_id is None or result.hepdata_doi is None:
        raise ValueError("hepdata result lacks a title, an INSPIRE id or a HEPData DOI")
    title = clean_line(result.title, TITLE_MAX)
    inspire = normalize_inspire(result.inspire_id)
    doi = normalize_doi(result.hepdata_doi)
    split = None if doi is None else split_hepdata_doi(doi)
    if title is None or inspire is None or split is None:
        raise ValueError("hepdata result has no usable title, INSPIRE id or HEPData DOI")
    concept, version = split
    items = [
        CandidatePid(concept, PidRole.IDENTITY, PidOrigin.NATIVE),
        CandidatePid(inspire, PidRole.RELATED, PidOrigin.CURATED_LINK),
    ]
    publication = None if result.doi is None else normalize_doi(result.doi)
    if publication is not None and not publication.value.startswith(HEPDATA_DOI_PREFIX):
        items.append(CandidatePid(publication, PidRole.RELATED, PidOrigin.CURATED_LINK))
    arxiv = None if result.arxiv_id is None else normalize_arxiv(result.arxiv_id)
    if arxiv is not None:
        items.append(CandidatePid(arxiv[0], PidRole.RELATED, PidOrigin.CURATED_LINK))
    return KnowledgeCandidate(
        ref=CandidateRef(ProviderKind.HEPDATA.value, f"ins{inspire.value}"),
        kind=ProviderKind.HEPDATA,
        rank=rank,
        title=title[0],
        title_truncated=title[1],
        authors=(),
        author_count=None,
        issued=None,
        version=CandidateVersion(VersionKind.DATASET_VERSION, f"doi:{concept.value}.v{version}"),
        pids=assemble_pids(items),
        landing_url=f"{HEPDATA_LANDING}{inspire.value}",
        access_class=AccessClass.PUBLIC,
        access_conditions=None,
        facts=PublicationFacts(
            refereed=None,
            document_types=("dataset",),
            journal_ref=None,
            collaborations=lines(result.collaborations, AUTHOR_MAX, COLLABORATIONS_MAX),
            generated=False,
        ),
        declared_authority=None,
        content=ContentAvailability.METADATA_ONLY,
        licenses=(CC0_METADATA,),
        snippet=None,
        retrieved_at=clock.now(),
    )


def _parse(raw: RawResponse) -> _Response | ProviderError:
    if not has_content_type(raw, JSON_CONTENT_TYPE):
        return wrong_content_type()
    document = strict_json(raw.body)
    if isinstance(document, ProviderError):
        return document
    try:
        return _Response.model_validate(document)
    except ValidationError:
        return unexpected_payload()


class HepdataProvider:
    """HEPData search (public, rate-gated at 1.0 s, search only, no retries)."""

    def __init__(
        self,
        settings: HepdataSettings,
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
        self._gate = MinIntervalGate(GATE_INTERVAL_S, monotonic=monotonic, sleep=sleep)
        self._descriptor = public_descriptor(
            ProviderKind.HEPDATA,
            "HEPData",
            ADAPTER_VERSION,
            timeout_s=settings.timeout_s,
            supports_fetch=False,
        )

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    async def _get(self, text: str, limit: int) -> RawResponse | ProviderError:
        return await gated_get(
            gate=self._gate,
            deadline=self._monotonic() + self._settings.timeout_s,
            monotonic=self._monotonic,
            client_factory=self._client_factory,
            spec=ClientSpec(
                host=HEPDATA_HOST,
                timeout_s=self._settings.timeout_s,
                max_response_bytes=SEARCH_MAX_BYTES,
            ),
            network=self._network,
            url=HEPDATA_SEARCH,
            params=search_params(text, limit),
        )

    async def search(self, query: KnowledgeQuery) -> SearchOutcome:
        refused = refuse_query(query, self._descriptor)
        if refused is not None:
            return refused
        return await within_timeout(
            self._settings.timeout_s, lambda: self._search(query), timed_out()
        )

    async def _search(self, query: KnowledgeQuery) -> SearchOutcome:
        raw = await self._get(query.text, query.limit)
        if isinstance(raw, ProviderError):
            return raw
        response = _parse(raw)
        if isinstance(response, ProviderError):
            return response
        candidates: list[KnowledgeCandidate] = []
        dropped = 0
        for item in response.results[: min(query.limit, RESULTS_USED)]:
            try:
                result = _Result.model_validate(item)
                candidates.append(_candidate(result, len(candidates), self._clock))
            except (ValidationError, ValueError):
                dropped += 1
        return SearchResult(tuple(candidates), response.total, dropped)

    async def fetch(self, ref: CandidateRef) -> FetchOutcome:
        """Record fetch is deferred until maintainer-recorded fixtures exist."""
        if ref.provider_id != self._descriptor.id:
            return error(ProviderErrorKind.UNSUPPORTED, "invalid_native_id")
        return error(ProviderErrorKind.UNSUPPORTED, "fetch_unsupported")

    async def health(self, *, deep: bool = False) -> ProviderHealth:
        """One small search (``q=higgs``, size 1) in both modes; a challenge is UNAVAILABLE."""
        del deep
        provider_id = self._descriptor.id
        return await within_timeout(
            self._settings.timeout_s, self._health, health_from(provider_id, timed_out())
        )

    async def _health(self) -> ProviderHealth:
        raw = await self._get(HEALTH_QUERY, 1)
        if isinstance(raw, ProviderError):
            return health_from(self._descriptor.id, raw)
        response = _parse(raw)
        failure = response if isinstance(response, ProviderError) else None
        return health_from(self._descriptor.id, failure)
