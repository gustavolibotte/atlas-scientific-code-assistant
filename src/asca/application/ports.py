"""Dependency-inversion boundaries: knowledge, time, ids, provenance storage, indexing."""

from collections.abc import Sequence
from dataclasses import dataclass, fields
from datetime import datetime
from itertools import pairwise
from typing import Final, Protocol

from asca.application.knowledge.models import (
    CandidateRef,
    FetchOutcome,
    ProviderDescriptor,
    ProviderHealth,
    SearchOutcome,
)
from asca.application.knowledge.models import KnowledgeQuery as KnowledgeQuery
from asca.domain.provenance import (
    FileIssueKind,
    FingerprintAlgorithm,
    IdKind,
    Language,
    Project,
    ProjectId,
    ProvenanceGraph,
    ProvenanceRecord,
    SourceSpan,
    SymbolKind,
    is_relative_path,
)


class KnowledgeProvider(Protocol):
    """A knowledge source adapter (INSPIRE, arXiv, HEPData, local library, MCP server).

    Contract: expected failures are returned as ``ProviderError`` and never raised; the
    adapter applies ``asyncio.timeout(descriptor.timeout_s)`` itself; ``fetch`` takes a
    ref, never a URL; nothing in a response triggers another request; no returned value
    carries credentials; queries above ``descriptor.max_query_access`` are refused.
    """

    @property
    def descriptor(self) -> ProviderDescriptor: ...

    async def search(self, query: KnowledgeQuery) -> SearchOutcome: ...

    async def fetch(self, ref: CandidateRef) -> FetchOutcome: ...

    async def health(self, *, deep: bool = False) -> ProviderHealth: ...


class Clock(Protocol):
    """Source of the current time."""

    def now(self) -> datetime:
        """Return an aware UTC datetime."""
        ...


class IdFactory(Protocol):
    """Source of new record identifiers."""

    def new(self, kind: IdKind) -> str: ...


@dataclass(frozen=True, slots=True)
class ProjectSummary:
    project: Project
    revision: int


class ProvenanceRepository(Protocol):
    """Append-only store of per-project provenance graphs. It has no update or delete."""

    def create_project(self, project: Project) -> None:
        """Store a new project at revision 0; raise ``DuplicateProjectError`` if it exists."""
        ...

    def list_projects(self) -> list[ProjectSummary]:
        """Return every project ordered by ``(created_at, id)``."""
        ...

    def load(self, project_id: ProjectId) -> ProvenanceGraph:
        """Raise ``ProjectNotFoundError`` or ``StoredGraphIntegrityError``."""
        ...

    def append(
        self,
        project_id: ProjectId,
        expected_revision: int,
        records: Sequence[ProvenanceRecord],
    ) -> int:
        """Atomically compare-and-set the revision and return the new one.

        Raise ``ProjectNotFoundError`` or ``ConcurrentModificationError``; nothing is
        written on failure.
        """
        ...


# ---------------------------------------------------------------------- workspace indexing


@dataclass(frozen=True, slots=True)
class IndexLimits:
    """Fail-closed resource limits of one indexing run."""

    max_files: int = 5_000
    max_file_bytes: int = 524_288
    max_total_bytes: int = 33_554_432
    max_directory_depth: int = 32
    max_directory_entries: int = 100_000
    max_ast_nodes_per_file: int = 500_000
    max_symbols_per_file: int = 5_000
    max_symbols: int = 20_000

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            if type(value) is not int or value < 1:
                raise ValueError("index limits must be positive integers")


DEFAULT_INDEX_LIMITS: Final = IndexLimits()

READER_ISSUES: Final = frozenset(
    {
        FileIssueKind.SYMLINK,
        FileIssueKind.NOT_REGULAR,
        FileIssueKind.TOO_LARGE,
        FileIssueKind.UNREADABLE,
    }
)
EXTRACTION_ISSUES: Final = frozenset(FileIssueKind) - READER_ISSUES


@dataclass(frozen=True, slots=True)
class WorkspaceFile:
    """One candidate source file: its bytes, or the reason the reader did not read it."""

    path: str
    data: bytes | None
    issue: FileIssueKind | None

    def __post_init__(self) -> None:
        if not is_relative_path(self.path):
            raise ValueError("workspace file path must be a normalized relative path")
        if (self.data is None) == (self.issue is None):
            raise ValueError("a workspace file has exactly one of data and issue")
        if self.issue is not None and self.issue not in READER_ISSUES:
            raise ValueError("a workspace file issue must be a reader issue")
        if self.data is not None and type(self.data) is not bytes:
            raise ValueError("workspace file data must be bytes")


@dataclass(frozen=True, slots=True)
class WorkspaceSnapshot:
    files: tuple[WorkspaceFile, ...]
    skipped_entries: int
    """Entries never offered: unrepresentable names, symlinked directories, other non-files."""

    def __post_init__(self) -> None:
        if not isinstance(self.files, tuple) or not all(
            type(item) is WorkspaceFile for item in self.files
        ):
            raise ValueError("snapshot files must be a tuple of WorkspaceFile")
        if any(left.path >= right.path for left, right in pairwise(self.files)):
            raise ValueError("snapshot files must be strictly increasing by path")
        if type(self.skipped_entries) is not int or self.skipped_entries < 0:
            raise ValueError("skipped_entries must be a non-negative integer")


class WorkspaceReader(Protocol):
    """Reads candidate source files of one workspace."""

    def read(self, suffixes: frozenset[str], limits: IndexLimits) -> WorkspaceSnapshot:
        """Raise WorkspaceIndexError; never follow symlinks; never execute anything."""
        ...


@dataclass(frozen=True, slots=True)
class ExtractedSymbol:
    kind: SymbolKind
    qualified_name: str
    span: SourceSpan
    fingerprint: str
    """sha256 hex digest."""


@dataclass(frozen=True, slots=True)
class FileExtraction:
    """The symbols of one file, or the reason it produced none."""

    issue: FileIssueKind | None
    symbols: tuple[ExtractedSymbol, ...]
    skipped_definitions: int

    def __post_init__(self) -> None:
        if self.issue is not None:
            if self.issue not in EXTRACTION_ISSUES:
                raise ValueError("an extraction issue must not be a reader issue")
            if self.symbols:
                raise ValueError("an extraction with an issue has no symbols")
        names = [item.qualified_name for item in self.symbols]
        if len(set(names)) != len(names):
            raise ValueError("extracted qualified names must be unique")
        if type(self.skipped_definitions) is not int or self.skipped_definitions < 0:
            raise ValueError("skipped_definitions must be a non-negative integer")


class SymbolExtractor(Protocol):
    """Turns the bytes of one file into symbols; it never receives the path."""

    @property
    def language(self) -> Language: ...

    @property
    def algorithm(self) -> FingerprintAlgorithm: ...

    @property
    def suffixes(self) -> frozenset[str]: ...

    def extract(self, data: bytes, limits: IndexLimits) -> FileExtraction: ...
