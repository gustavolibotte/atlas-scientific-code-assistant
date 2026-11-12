"""Dependency-inversion boundaries: knowledge providers, time, ids and provenance storage."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from asca.domain.provenance import (
    IdKind,
    Project,
    ProjectId,
    ProvenanceGraph,
    ProvenanceRecord,
)


@dataclass(frozen=True, slots=True)
class KnowledgeQuery:
    text: str
    limit: int = 5

    def __post_init__(self) -> None:
        if not self.text.strip():
            raise ValueError("Search query cannot be blank")
        if not 1 <= self.limit <= 100:
            raise ValueError("Search limit must be between 1 and 100")


@dataclass(frozen=True, slots=True)
class EvidenceCandidate:
    source_id: str
    title: str
    excerpt: str
    locator: str


class KnowledgeProvider(Protocol):
    """Future chATLAS and document adapters must implement this contract."""

    async def search(self, query: KnowledgeQuery) -> list[EvidenceCandidate]: ...

    async def is_available(self) -> bool: ...


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
