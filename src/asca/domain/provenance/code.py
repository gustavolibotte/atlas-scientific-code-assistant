"""Workspace revisions, code symbols and implementation links."""

import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from asca.domain.provenance.errors import ProvenanceInvariantError
from asca.domain.provenance.ids import (
    DecisionId,
    IdKind,
    ImplementationLinkId,
    ProjectId,
    RevisionId,
    SymbolId,
    require_id,
)
from asca.domain.provenance.values import (
    optional_sha256,
    optional_text,
    require_bool,
    require_enum,
    require_int,
    require_relative_path,
    require_utc,
)

VCS_REF_MAX = 100
QUALIFIED_NAME_MAX = 300
_QUALIFIED_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*")


class Language(StrEnum):
    PYTHON = "python"


class SymbolKind(StrEnum):
    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    MODULE = "module"


@dataclass(frozen=True, slots=True)
class WorkspaceRevision:
    id: RevisionId
    project_id: ProjectId
    sequence: int
    vcs_ref: str | None
    symbols_indexed: bool
    recorded_at: datetime

    def __post_init__(self) -> None:
        require_id(IdKind.WORKSPACE_REVISION, self.id, "revision.id")
        require_id(IdKind.PROJECT, self.project_id, "revision.project_id")
        require_int("revision.sequence", self.sequence, minimum=1)
        optional_text("revision.vcs_ref", self.vcs_ref, max_len=VCS_REF_MAX)
        require_bool("revision.symbols_indexed", self.symbols_indexed)
        require_utc("revision.recorded_at", self.recorded_at)


@dataclass(frozen=True, slots=True)
class SourceSpan:
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        require_int("span.start_line", self.start_line, minimum=1)
        require_int("span.end_line", self.end_line, minimum=1)
        if self.end_line < self.start_line:
            raise ProvenanceInvariantError("R.span.order", "end_line must be >= start_line")


SymbolKey = tuple[Language, str, str]


@dataclass(frozen=True, slots=True)
class CodeSymbol:
    """A symbol snapshot in one workspace revision, matched across revisions by key."""

    id: SymbolId
    project_id: ProjectId
    revision_id: RevisionId
    language: Language
    kind: SymbolKind
    qualified_name: str
    file_path: str
    span: SourceSpan | None
    fingerprint: str | None

    def __post_init__(self) -> None:
        require_id(IdKind.SYMBOL, self.id, "symbol.id")
        require_id(IdKind.PROJECT, self.project_id, "symbol.project_id")
        require_id(IdKind.WORKSPACE_REVISION, self.revision_id, "symbol.revision_id")
        require_enum(Language, "symbol.language", self.language)
        require_enum(SymbolKind, "symbol.kind", self.kind)
        if (
            not isinstance(self.qualified_name, str)
            or len(self.qualified_name) > QUALIFIED_NAME_MAX
            or _QUALIFIED_NAME_RE.fullmatch(self.qualified_name) is None
        ):
            raise ProvenanceInvariantError(
                "R.symbol.qualified_name", "qualified_name must be a dotted Python identifier"
            )
        require_relative_path("symbol.file_path", self.file_path)
        if self.span is not None and not isinstance(self.span, SourceSpan):
            raise ProvenanceInvariantError("R.symbol.span", "span must be a SourceSpan")
        optional_sha256("symbol.fingerprint", self.fingerprint)

    @property
    def key(self) -> SymbolKey:
        return (self.language, self.file_path, self.qualified_name)


@dataclass(frozen=True, slots=True)
class ImplementationLink:
    id: ImplementationLinkId
    project_id: ProjectId
    decision_id: DecisionId
    symbol_id: SymbolId
    created_at: datetime

    def __post_init__(self) -> None:
        require_id(IdKind.IMPLEMENTATION_LINK, self.id, "implementation_link.id")
        require_id(IdKind.PROJECT, self.project_id, "implementation_link.project_id")
        require_id(IdKind.DECISION, self.decision_id, "implementation_link.decision_id")
        require_id(IdKind.SYMBOL, self.symbol_id, "implementation_link.symbol_id")
        require_utc("implementation_link.created_at", self.created_at)


class LinkFreshness(StrEnum):
    CURRENT = "current"
    STALE = "stale"
    MOVED = "moved"
    ORPHANED = "orphaned"
    UNKNOWN = "unknown"
