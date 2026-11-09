"""Dependency-inversion boundary for external knowledge providers."""

from dataclasses import dataclass
from typing import Protocol


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
