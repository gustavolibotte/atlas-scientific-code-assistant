"""Local curated library: a directory of notes listed in a ``manifest.toml``.

The root is read per operation with the M2 ``FilesystemWorkspaceReader`` (fd-relative,
``O_NOFOLLOW``, regular files only, fail-closed); nothing is cached. Only files listed in
the manifest are used, each with the access class and authority hint its curator
declared. Fetched text is the exact decoded file content, so quotes can be checked
verbatim. The library never uses the network and never executes anything it reads.
"""

import asyncio
import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, ValidationError

from asca.application.errors import WorkspaceIndexError
from asca.application.knowledge.models import (
    AUTHOR_MAX,
    AUTHORS_MAX,
    CONDITIONS_MAX,
    LICENSE_ID_MAX,
    NATIVE_ID_MAX,
    SNIPPET_MAX,
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
from asca.application.knowledge.pids import (
    normalize_report_number,
    parse_pid_text,
    pid_sort_key,
)
from asca.application.knowledge.text import clean_block, is_block, is_line, query_terms
from asca.application.ports import Clock, IndexLimits, WorkspaceSnapshot
from asca.domain.provenance import (
    TITLE_MAX,
    AccessClass,
    PersistentIdentifier,
    PidScheme,
    SourceAuthority,
    is_relative_path,
    sha256_text,
)
from asca.infrastructure.indexing.filesystem import FilesystemWorkspaceReader
from asca.infrastructure.knowledge.settings import LocalLibrarySettings

PROVIDER_ID: Final = "local"
ADAPTER_VERSION: Final = "local/1"
LABEL: Final = "Local curated library"
LIBRARY_FORMAT: Final = "asca-library/1"
MANIFEST_NAME: Final = "manifest.toml"
MANIFEST_MAX_BYTES: Final = 262_144
DOCUMENTS_MAX: Final = 500
DOCUMENT_PIDS_MAX: Final = 8
VERSION_MAX: Final = 90
QUERY_TERMS_MAX: Final = 12
TITLE_WEIGHT: Final = 3
READ_SUFFIXES: Final = frozenset({".md", ".txt", ".toml"})
DOCUMENT_SUFFIXES: Final = (".md", ".txt")
LIBRARY_LIMITS: Final = IndexLimits(
    max_files=1001,
    max_file_bytes=2_097_152,
    max_total_bytes=67_108_864,
    max_directory_depth=16,
)
MEDIA_TYPES: Final = {
    ".md": "text/markdown; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
}
_NO_WHITESPACE: Final = re.compile(r"\S+")


# ---------------------------------------------------------------------- manifest schema


class _ManifestDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    path: StrictStr = Field(max_length=NATIVE_ID_MAX)
    title: StrictStr = Field(max_length=TITLE_MAX)
    version: StrictStr = Field(max_length=VERSION_MAX)
    access_class: Literal["public", "internal", "restricted"]
    access_conditions: StrictStr | None = Field(default=None, max_length=CONDITIONS_MAX)
    authority_hint: Literal["published", "working_material", "automated_inference"] = (
        "working_material"
    )
    pids: list[StrictStr] = Field(default_factory=list, max_length=DOCUMENT_PIDS_MAX)
    license: StrictStr | None = Field(default=None, max_length=LICENSE_ID_MAX)
    issued: StrictStr | None = Field(default=None, max_length=40)
    authors: list[StrictStr] = Field(default_factory=list, max_length=AUTHORS_MAX)


class _Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    format: Literal["asca-library/1"]
    documents: list[_ManifestDocument] = Field(default_factory=list, max_length=DOCUMENTS_MAX)


class ManifestInvalid(ValueError):  # noqa: N818 - a refusal code, not an exception family
    """The manifest failed validation. The message never echoes a value."""

    def __init__(self) -> None:
        super().__init__("manifest_invalid")


@dataclass(frozen=True, slots=True)
class LibraryEntry:
    """One validated manifest document (its file not yet read)."""

    path: str
    title: str
    version: CandidateVersion
    access_class: AccessClass
    access_conditions: str | None
    authority: SourceAuthority
    pids: tuple[CandidatePid, ...]
    licenses: tuple[LicenseInfo, ...]
    issued: PartialDate | None
    authors: tuple[str, ...]

    @property
    def media_type(self) -> str:
        return MEDIA_TYPES[os.path.splitext(self.path)[1]]


def _manifest_pid(text: str) -> CandidatePid:
    pid = parse_pid_text(text)
    if pid is None:
        raise ManifestInvalid
    role = PidRole.IDENTITY
    if pid.scheme is PidScheme.CDS_REPORT:
        report = normalize_report_number(pid.value)
        role = PidRole.RELATED if report is None else report[1]
    return CandidatePid(pid, role, PidOrigin.CURATED_LINK)


def _entry(raw: _ManifestDocument) -> LibraryEntry:
    path = raw.path
    if (
        not is_relative_path(path)
        or _NO_WHITESPACE.fullmatch(path) is None
        or not is_line(path)
        or not path.endswith(DOCUMENT_SUFFIXES)
    ):
        raise ManifestInvalid
    if not is_line(raw.title) or raw.title != raw.title.strip():
        raise ManifestInvalid
    if not is_line(raw.version) or raw.version != raw.version.strip():
        raise ManifestInvalid
    access = AccessClass(raw.access_class)
    conditions = raw.access_conditions
    if (access is AccessClass.PUBLIC) != (conditions is None):
        raise ManifestInvalid
    if conditions is not None and not is_block(conditions):
        raise ManifestInvalid
    if raw.license is not None and not is_line(raw.license):
        raise ManifestInvalid
    if any(not is_line(author) or len(author) > AUTHOR_MAX for author in raw.authors):
        raise ManifestInvalid
    issued = None
    if raw.issued is not None:
        issued = PartialDate.parse(raw.issued)
        if issued is None:
            raise ManifestInvalid
    pids = [_manifest_pid(text) for text in raw.pids]
    pids.append(
        CandidatePid(
            PersistentIdentifier(PidScheme.LOCAL_DOCUMENT, path), PidRole.RELATED, PidOrigin.NATIVE
        )
    )
    keys = [pid_sort_key(item.pid) for item in pids]
    if len(set(keys)) != len(keys):
        raise ManifestInvalid
    for scheme in (PidScheme.INSPIRE, PidScheme.ARXIV):
        identity = [
            item for item in pids if item.role is PidRole.IDENTITY and item.pid.scheme is scheme
        ]
        if len(identity) > 1:
            raise ManifestInvalid
    return LibraryEntry(
        path=path,
        title=raw.title,
        version=CandidateVersion(VersionKind.DECLARED, f"declared:{raw.version}"),
        access_class=access,
        access_conditions=conditions,
        authority=SourceAuthority(raw.authority_hint),
        pids=tuple(sorted(pids, key=lambda item: pid_sort_key(item.pid))),
        licenses=()
        if raw.license is None
        else (LicenseInfo(raw.license, None, LicenseScope.CONTENT),),
        issued=issued,
        authors=tuple(raw.authors),
    )


def parse_manifest(data: bytes) -> tuple[LibraryEntry, ...]:
    """Validate a manifest; raise ``ManifestInvalid`` without echoing any value."""
    if len(data) > MANIFEST_MAX_BYTES:
        raise ManifestInvalid
    try:
        document = tomllib.loads(data.decode("utf-8"))
        manifest = _Manifest.model_validate(document)
        entries = tuple(_entry(raw) for raw in manifest.documents)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, ValidationError, ValueError):
        raise ManifestInvalid from None
    paths = [entry.path for entry in entries]
    if len(set(paths)) != len(paths):
        raise ManifestInvalid
    return entries


# ---------------------------------------------------------------------- library snapshot


@dataclass(frozen=True, slots=True)
class _Document:
    entry: LibraryEntry
    text: str
    folded_title: str
    folded_text: str


@dataclass(frozen=True, slots=True)
class _Library:
    documents: Mapping[str, _Document]
    """Usable listed documents by path."""
    dropped: int
    """Listed documents that are missing, unreadable, not strict UTF-8 or contain NUL."""


def _decode(data: bytes | None) -> str | None:
    if data is None:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text or "\x00" in text:
        return None
    return text


def _not_configured(code: str) -> ProviderError:
    return ProviderError(ProviderErrorKind.NOT_CONFIGURED, code)


def _library(snapshot: WorkspaceSnapshot) -> _Library | ProviderError:
    files = {item.path: item for item in snapshot.files}
    manifest = files.get(MANIFEST_NAME)
    if manifest is None:
        return _not_configured("manifest_missing")
    if manifest.data is None:
        return _not_configured("manifest_invalid")
    try:
        entries = parse_manifest(manifest.data)
    except ManifestInvalid:
        return _not_configured("manifest_invalid")
    documents: dict[str, _Document] = {}
    dropped = 0
    for entry in entries:
        found = files.get(entry.path)
        text = _decode(None if found is None else found.data)
        if text is None:
            dropped += 1
            continue
        documents[entry.path] = _Document(entry, text, entry.title.casefold(), text.casefold())
    return _Library(documents, dropped)


class LocalLibraryProvider:
    """``KnowledgeProvider`` over one curated directory; POSIX only, no network."""

    def __init__(self, settings: LocalLibrarySettings, *, clock: Clock) -> None:
        self._root = os.path.expanduser(settings.root)
        self._clock = clock
        self._descriptor = ProviderDescriptor(
            id=PROVIDER_ID,
            kind=ProviderKind.LOCAL,
            label=LABEL,
            adapter_version=ADAPTER_VERSION,
            access_class=AccessClass.PUBLIC,
            access_conditions=None,
            max_query_access=AccessClass.RESTRICTED,
            uses_network=False,
            supports_fetch=True,
            timeout_s=settings.timeout_s,
        )

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    def _load_sync(self) -> _Library | ProviderError:
        try:
            snapshot = FilesystemWorkspaceReader(self._root).read(READ_SUFFIXES, LIBRARY_LIMITS)
        except WorkspaceIndexError:
            return _not_configured("library_unreadable")
        return _library(snapshot)

    async def _load(self) -> _Library | ProviderError:
        try:
            async with asyncio.timeout(self._descriptor.timeout_s):
                return await asyncio.to_thread(self._load_sync)
        except TimeoutError:
            return ProviderError(ProviderErrorKind.TIMEOUT, "provider_timeout")

    def _candidate(self, document: _Document, rank: int) -> KnowledgeCandidate:
        entry = document.entry
        return KnowledgeCandidate(
            ref=CandidateRef(PROVIDER_ID, entry.path),
            kind=ProviderKind.LOCAL,
            rank=rank,
            title=entry.title,
            title_truncated=False,
            authors=entry.authors,
            author_count=len(entry.authors) if entry.authors else None,
            issued=entry.issued,
            version=entry.version,
            pids=entry.pids,
            landing_url=None,
            access_class=entry.access_class,
            access_conditions=entry.access_conditions,
            facts=PublicationFacts(
                refereed=None,
                document_types=(),
                journal_ref=None,
                collaborations=(),
                generated=False,
            ),
            declared_authority=entry.authority,
            content=ContentAvailability.FULL_TEXT,
            licenses=entry.licenses,
            snippet=clean_block(document.text, SNIPPET_MAX),
            retrieved_at=self._clock.now(),
        )

    async def search(self, query: KnowledgeQuery) -> SearchOutcome:
        if query.access_class.rank > self._descriptor.max_query_access.rank:  # pragma: no cover
            return ProviderError(ProviderErrorKind.NOT_CONSULTED, "query_access_class")
        terms = query_terms(query.text, QUERY_TERMS_MAX)
        if not terms:
            return ProviderError(ProviderErrorKind.UNSUPPORTED, "empty_query")
        library = await self._load()
        if isinstance(library, ProviderError):
            return library
        scored: list[tuple[int, str, _Document]] = []
        for path, document in library.documents.items():
            title, text = document.folded_title, document.folded_text
            if all(term in title or term in text for term in terms):
                score = sum(TITLE_WEIGHT * title.count(term) + text.count(term) for term in terms)
                scored.append((-score, path, document))
        scored.sort(key=lambda item: (item[0], item[1]))
        candidates = tuple(
            self._candidate(document, rank)
            for rank, (_, _, document) in enumerate(scored[: query.limit])
        )
        return SearchResult(candidates, len(scored), library.dropped)

    async def fetch(self, ref: CandidateRef) -> FetchOutcome:
        if (
            ref.provider_id != PROVIDER_ID
            or not is_relative_path(ref.native_id)
            or not ref.native_id.endswith(DOCUMENT_SUFFIXES)
        ):
            return ProviderError(ProviderErrorKind.UNSUPPORTED, "invalid_native_id")
        library = await self._load()
        if isinstance(library, ProviderError):
            return library
        document = library.documents.get(ref.native_id)
        if document is None:
            return ProviderError(ProviderErrorKind.NOT_FOUND, "not_found")
        candidate = self._candidate(document, 0)
        entry = document.entry
        return FetchResult(
            candidate,
            FetchedDocument(
                ref=candidate.ref,
                kind=DocumentKind.FULL_TEXT,
                media_type=entry.media_type,
                text=document.text,
                text_sha256=sha256_text(document.text),
                raw_sha256=None,
                retrieved_at=candidate.retrieved_at,
                source_url=None,
                access_class=entry.access_class,
                access_conditions=entry.access_conditions,
                licenses=entry.licenses,
                redactions=0,
            ),
        )

    async def health(self, *, deep: bool = False) -> ProviderHealth:
        library = await self._load()
        if isinstance(library, ProviderError):
            state = (
                HealthState.UNAVAILABLE
                if library.kind is ProviderErrorKind.TIMEOUT
                else HealthState.MISCONFIGURED
            )
            return ProviderHealth(PROVIDER_ID, state, library)
        return ProviderHealth(PROVIDER_ID, HealthState.AVAILABLE, None)
