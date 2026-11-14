"""INSPIRE-HEP literature adapter (``inspire/1``): search, fetch and health.

Requests always go to the fixed literature endpoint with a ``fields`` filter; a fetch uses
``q=control_number:<id>`` because ``/api/literature/<id>`` ignores ``fields``. Provider text
is cleaned before model construction and is data, never instructions.
"""

import asyncio
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from asca.application.knowledge.models import (
    AUTHOR_MAX,
    AUTHORS_MAX,
    COLLABORATIONS_MAX,
    DOCUMENT_TYPE_MAX,
    DOCUMENT_TYPES_MAX,
    JOURNAL_REF_MAX,
    LICENSES_MAX,
    SNIPPET_MAX,
    CandidatePid,
    CandidateRef,
    CandidateVersion,
    ContentAvailability,
    FetchOutcome,
    FetchResult,
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
    license_from_url,
)
from asca.application.knowledge.pids import (
    normalize_arxiv,
    normalize_doi,
    normalize_inspire,
    normalize_report_number,
    pid_sort_key,
)
from asca.application.knowledge.text import clean_line
from asca.application.ports import Clock
from asca.domain.provenance import TITLE_MAX, AccessClass, PersistentIdentifier, PidScheme
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
    lines,
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
    strict_json,
)
from asca.infrastructure.knowledge.settings import InspireSettings, NetworkSettings

INSPIRE_API: Final = "https://inspirehep.net/api/literature"
INSPIRE_HOST: Final = "inspirehep.net"
INSPIRE_LANDING: Final = "https://inspirehep.net/literature/"
INSPIRE_FIELDS: Final = (
    "control_number,titles.title,first_author.full_name,author_count,collaborations.value,"
    "dois,arxiv_eprints.value,report_numbers.value,external_system_identifiers,"
    "publication_info.journal_title,publication_info.journal_volume,publication_info.year,"
    "publication_info.artid,publication_info.page_start,document_type,refereed,earliest_date,"
    "imprints.date,license,abstracts.value,abstracts.source,deleted"
)
NATIVE_ID_RE: Final = r"[1-9]\d{0,9}"
ADAPTER_VERSION: Final = "inspire/1"
GATE_INTERVAL_S: Final = 0.35
SEARCH_MAX_BYTES: Final = 1_048_576
FETCH_MAX_BYTES: Final = 524_288
HEALTH_MAX_BYTES: Final = 65_536
JSON_CONTENT_TYPE: Final = "application/json"
_NATIVE_ID = re.compile(NATIVE_ID_RE)
_PUBLICATION_MATERIALS: Final = frozenset({None, "publication"})


# ---------------------------------------------------------------------- request building


def search_params(query: KnowledgeQuery) -> tuple[tuple[str, str], ...]:
    """Search parameters, in the documented order."""
    return (
        ("q", query.text),
        ("size", str(query.limit)),
        ("page", "1"),
        ("sort", "bestmatch"),
        ("fields", INSPIRE_FIELDS),
    )


def fetch_params(native_id: str) -> tuple[tuple[str, str], ...]:
    return (
        ("q", f"control_number:{native_id}"),
        ("size", "1"),
        ("page", "1"),
        ("fields", INSPIRE_FIELDS),
    )


HEALTH_PARAMS: Final = (("q", "control_number:1"), ("size", "1"), ("fields", "control_number"))


# ---------------------------------------------------------------------- parsing models


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True, frozen=True)


class _Title(_Model):
    title: str = Field(max_length=10_000)


class _Author(_Model):
    full_name: str | None = Field(default=None, max_length=1_000)


class _Value(_Model):
    value: str = Field(max_length=1_000)


class _Doi(_Model):
    value: str = Field(max_length=1_000)
    material: str | None = Field(default=None, max_length=100)


class _ExternalId(_Model):
    schema_name: str = Field(alias="schema", max_length=100)
    value: str = Field(max_length=200)


class _PublicationInfo(_Model):
    journal_title: str | None = Field(default=None, max_length=1_000)
    journal_volume: str | int | None = Field(default=None)
    year: int | str | None = Field(default=None)
    artid: str | int | None = Field(default=None)
    page_start: str | int | None = Field(default=None)


class _License(_Model):
    url: str | None = Field(default=None, max_length=1_000)
    license: str | None = Field(default=None, max_length=1_000)
    imposing: str | None = Field(default=None, max_length=1_000)


class _Abstract(_Model):
    value: str | None = Field(default=None, max_length=200_000)
    source: str | None = Field(default=None, max_length=200)


class _Imprint(_Model):
    date: str | None = Field(default=None, max_length=100)


class _Metadata(_Model):
    control_number: int
    titles: list[_Title] = Field(default_factory=list, max_length=50)
    first_author: _Author | None = None
    author_count: int | None = None
    collaborations: list[_Value] = Field(default_factory=list, max_length=100)
    dois: list[_Doi] = Field(default_factory=list, max_length=100)
    arxiv_eprints: list[_Value] = Field(default_factory=list, max_length=50)
    report_numbers: list[_Value] = Field(default_factory=list, max_length=100)
    external_system_identifiers: list[_ExternalId] = Field(default_factory=list, max_length=100)
    publication_info: list[_PublicationInfo] = Field(default_factory=list, max_length=50)
    document_type: list[str] = Field(default_factory=list, max_length=50)
    refereed: bool | None = None
    earliest_date: str | None = Field(default=None, max_length=100)
    imprints: list[_Imprint] = Field(default_factory=list, max_length=50)
    license: list[_License] = Field(default_factory=list, max_length=50)
    abstracts: list[_Abstract] = Field(default_factory=list, max_length=50)
    deleted: bool | None = None


class _Hit(_Model):
    metadata: _Metadata
    updated: str | None = Field(default=None, max_length=100)


class _Hits(_Model):
    total: int = Field(ge=0)
    hits: list[Any] = Field(max_length=100)


class _Response(_Model):
    hits: _Hits


# ---------------------------------------------------------------------- mapping


def _pids(metadata: _Metadata, recid: PersistentIdentifier) -> tuple[CandidatePid, ...]:
    items = [CandidatePid(recid, PidRole.IDENTITY, PidOrigin.NATIVE)]
    publication: dict[PersistentIdentifier, bool] = {}
    for doi in metadata.dois:
        pid = normalize_doi(doi.value)
        if pid is not None:
            is_publication = doi.material in _PUBLICATION_MATERIALS
            publication[pid] = publication.get(pid, True) and is_publication
    for pid, is_publication in publication.items():
        role = PidRole.IDENTITY if is_publication else PidRole.RELATED
        items.append(CandidatePid(pid, role, PidOrigin.CURATED_LINK))
    for index, eprint in enumerate(metadata.arxiv_eprints):
        arxiv = normalize_arxiv(eprint.value)
        if arxiv is not None:
            role = PidRole.IDENTITY if index == 0 else PidRole.RELATED
            items.append(CandidatePid(arxiv[0], role, PidOrigin.CURATED_LINK))
    for report in metadata.report_numbers:
        normalized = normalize_report_number(report.value)
        if normalized is not None:
            items.append(CandidatePid(normalized[0], normalized[1], PidOrigin.CURATED_LINK))
    for external in metadata.external_system_identifiers:
        if external.schema_name == "CDS":
            try:
                cds = PersistentIdentifier(PidScheme.CDS_RECORD, external.value.strip())
            except ValueError:
                continue
            items.append(CandidatePid(cds, PidRole.RELATED, PidOrigin.CURATED_LINK))
    return assemble_pids(items)


def _part(value: str | int | None) -> str | None:
    return None if value is None else line(str(value), JOURNAL_REF_MAX)


def _journal_ref(metadata: _Metadata) -> str | None:
    """``{journal_title} {journal_volume} ({year}) {artid|page_start}`` from the first
    publication info; ``None`` without a journal title (a bare year is not a reference)."""
    if not metadata.publication_info:
        return None
    info = metadata.publication_info[0]
    journal = _part(info.journal_title)
    if journal is None:
        return None
    year = _part(info.year)
    parts = [
        journal,
        _part(info.journal_volume),
        None if year is None else f"({year})",
        _part(info.artid) or _part(info.page_start),
    ]
    return line(" ".join(part for part in parts if part), JOURNAL_REF_MAX)


def _issued(metadata: _Metadata) -> PartialDate | None:
    if metadata.imprints and metadata.imprints[0].date is not None:
        imprint = PartialDate.parse(metadata.imprints[0].date)
        if imprint is not None:
            return imprint
    return None if metadata.earliest_date is None else PartialDate.parse(metadata.earliest_date)


def _version(
    recid: PersistentIdentifier,
    pids: tuple[CandidatePid, ...],
    updated: str | None,
    retrieved_on: str,
) -> CandidateVersion:
    def identity(scheme: PidScheme) -> list[PersistentIdentifier]:
        found = [p.pid for p in pids if p.role is PidRole.IDENTITY and p.pid.scheme is scheme]
        return sorted(found, key=pid_sort_key)

    for doi in identity(PidScheme.DOI)[:1]:
        label = f"doi:{doi.value}"
        if len(label) <= 100:
            return CandidateVersion(VersionKind.JOURNAL_PUBLICATION, label)
    for report in identity(PidScheme.CDS_REPORT):
        label = f"report:{report.value}"
        if len(label) <= 100:  # the report grammar equals the M1 CDS_REPORT pattern
            return CandidateVersion(VersionKind.REPORT_NUMBER, label)
    snapshot = None if updated is None else PartialDate.parse(updated)
    if snapshot is not None and snapshot.day is not None:
        return CandidateVersion(
            VersionKind.RECORD_SNAPSHOT, f"inspire:{recid.value}@{snapshot.iso()}"
        )
    return CandidateVersion(VersionKind.RECORD_SNAPSHOT, f"retrieved@{retrieved_on}")


def _licenses(metadata: _Metadata) -> tuple[LicenseInfo, ...]:
    found: list[LicenseInfo] = [CC0_METADATA]
    for entry in metadata.license:
        info = (
            None if entry.url is None else license_from_url(entry.url.strip(), LicenseScope.CONTENT)
        )
        if info is None:
            identifier = line(entry.license, 64) or line(entry.imposing, 64)
            if identifier is None:
                continue
            info = LicenseInfo(identifier, None, LicenseScope.CONTENT)
        if info not in found:
            found.append(info)
    return tuple(found[:LICENSES_MAX])


def _chosen_abstract(metadata: _Metadata) -> str | None:
    usable = [a for a in metadata.abstracts if a.value is not None and a.value.strip()]
    arxiv = [a for a in usable if (a.source or "").strip().casefold() == "arxiv"]
    chosen = arxiv or usable
    return chosen[0].value if chosen else None


def _candidate(hit: _Hit, rank: int, clock: Clock) -> tuple[KnowledgeCandidate, str | None]:
    """Map one hit; raises ``ValueError`` when the hit cannot form a valid candidate."""
    metadata = hit.metadata
    recid = normalize_inspire(metadata.control_number)
    if recid is None or not metadata.titles:
        raise ValueError("inspire hit lacks a record id or a title")
    cleaned_title = clean_line(metadata.titles[0].title, TITLE_MAX)
    if cleaned_title is None:
        raise ValueError("inspire hit has a blank title")
    retrieved_at = clock.now()
    pids = _pids(metadata, recid)
    first = metadata.first_author
    author = None if first is None else line(first.full_name, AUTHOR_MAX)
    authors = () if author is None else (author,)
    count = metadata.author_count
    abstract = _chosen_abstract(metadata)
    candidate = KnowledgeCandidate(
        ref=CandidateRef(ProviderKind.INSPIRE.value, recid.value),
        kind=ProviderKind.INSPIRE,
        rank=rank,
        title=cleaned_title[0],
        title_truncated=cleaned_title[1],
        authors=authors[:AUTHORS_MAX],
        author_count=count if count is not None and count >= len(authors) else None,
        issued=_issued(metadata),
        version=_version(recid, pids, hit.updated, retrieved_at.date().isoformat()),
        pids=pids,
        landing_url=f"{INSPIRE_LANDING}{recid.value}",
        access_class=AccessClass.PUBLIC,
        access_conditions=None,
        facts=PublicationFacts(
            refereed=metadata.refereed,
            document_types=tuple(
                item.lower()
                for item in lines(metadata.document_type, DOCUMENT_TYPE_MAX, DOCUMENT_TYPES_MAX)
            ),
            journal_ref=_journal_ref(metadata),
            collaborations=lines(
                (item.value for item in metadata.collaborations), AUTHOR_MAX, COLLABORATIONS_MAX
            ),
            generated=False,
        ),
        declared_authority=None,
        content=ContentAvailability.ABSTRACT if abstract else ContentAvailability.METADATA_ONLY,
        licenses=_licenses(metadata),
        snippet=block(abstract, SNIPPET_MAX),
        retrieved_at=retrieved_at,
    )
    full_abstract = block(abstract, ABSTRACT_TEXT_MAX)
    return candidate, full_abstract


def _parse_hits(raw: RawResponse) -> tuple[_Hits, None] | tuple[None, ProviderError]:
    if not has_content_type(raw, JSON_CONTENT_TYPE):
        return None, wrong_content_type()
    document = strict_json(raw.body)
    if isinstance(document, ProviderError):
        return None, document
    try:
        return _Response.model_validate(document).hits, None
    except ValidationError:
        return None, unexpected_payload()


# ---------------------------------------------------------------------- provider


class InspireProvider:
    """INSPIRE-HEP literature search (public, rate-gated at 0.35 s, no retries)."""

    def __init__(
        self,
        settings: InspireSettings,
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
            ProviderKind.INSPIRE,
            "INSPIRE-HEP",
            ADAPTER_VERSION,
            timeout_s=settings.timeout_s,
            supports_fetch=True,
        )

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    def _spec(self, max_bytes: int) -> ClientSpec:
        return ClientSpec(
            host=INSPIRE_HOST, timeout_s=self._settings.timeout_s, max_response_bytes=max_bytes
        )

    async def _get(
        self, params: tuple[tuple[str, str], ...], max_bytes: int, deadline: float
    ) -> RawResponse | ProviderError:
        return await gated_get(
            gate=self._gate,
            deadline=deadline,
            monotonic=self._monotonic,
            client_factory=self._client_factory,
            spec=self._spec(max_bytes),
            network=self._network,
            url=INSPIRE_API,
            params=params,
        )

    def _deadline(self) -> float:
        return self._monotonic() + self._settings.timeout_s

    async def search(self, query: KnowledgeQuery) -> SearchOutcome:
        refused = refuse_query(query, self._descriptor)
        if refused is not None:
            return refused
        return await within_timeout(
            self._settings.timeout_s, lambda: self._search(query), timed_out()
        )

    async def _search(self, query: KnowledgeQuery) -> SearchOutcome:
        raw = await self._get(search_params(query), SEARCH_MAX_BYTES, self._deadline())
        if isinstance(raw, ProviderError):
            return raw
        hits, failure = _parse_hits(raw)
        if hits is None:
            return failure or unexpected_payload()
        candidates: list[KnowledgeCandidate] = []
        dropped = 0
        for item in hits.hits[: query.limit]:
            try:
                hit = _Hit.model_validate(item)
                if hit.metadata.deleted is True:
                    raise ValueError("deleted record")
                candidates.append(_candidate(hit, len(candidates), self._clock)[0])
            except (ValidationError, ValueError):
                dropped += 1
        return SearchResult(tuple(candidates), hits.total, dropped)

    async def fetch(self, ref: CandidateRef) -> FetchOutcome:
        refused = refuse_ref(ref, self._descriptor, _NATIVE_ID)
        if refused is not None:
            return refused
        return await within_timeout(self._settings.timeout_s, lambda: self._fetch(ref), timed_out())

    async def _fetch(self, ref: CandidateRef) -> FetchOutcome:
        raw = await self._get(fetch_params(ref.native_id), FETCH_MAX_BYTES, self._deadline())
        if isinstance(raw, ProviderError):
            return raw
        hits, failure = _parse_hits(raw)
        if hits is None:
            return failure or unexpected_payload()
        not_found = error(ProviderErrorKind.NOT_FOUND, "not_found")
        if hits.total == 0 or not hits.hits:
            return not_found
        try:
            hit = _Hit.model_validate(hits.hits[0])
            if hit.metadata.deleted is True:
                return not_found
            if str(hit.metadata.control_number) != ref.native_id:
                return unexpected_payload()
            candidate, abstract = _candidate(hit, 0, self._clock)
            document = text_document(
                ref=candidate.ref,
                title=candidate.title,
                abstract=abstract,
                raw=raw,
                retrieved_at=candidate.retrieved_at,
                licenses=candidate.licenses,
            )
            return FetchResult(candidate, document)
        except (ValidationError, ValueError):
            return unexpected_payload()

    async def health(self, *, deep: bool = False) -> ProviderHealth:
        """One small request (``control_number:1``) in both modes."""
        del deep
        provider_id = self._descriptor.id
        return await within_timeout(
            self._settings.timeout_s,
            self._health,
            health_from(provider_id, timed_out()),
        )

    async def _health(self) -> ProviderHealth:
        raw = await self._get(HEALTH_PARAMS, HEALTH_MAX_BYTES, self._deadline())
        return health_from(self._descriptor.id, raw if isinstance(raw, ProviderError) else None)
