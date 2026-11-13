"""Workspace revisions, code symbols and implementation links."""

import re
from bisect import bisect_left
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from itertools import pairwise

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
FILE_ISSUES_MAX = 10_000
MODULE_QUALIFIED_NAME = "__module__"
_QUALIFIED_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*")


class Language(StrEnum):
    PYTHON = "python"


class SymbolKind(StrEnum):
    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    MODULE = "module"


class FingerprintAlgorithm(StrEnum):
    """Versioned symbol fingerprint algorithms; different ids are never compared."""

    PYTHON_AST_1 = "python-ast/1"

    @property
    def language(self) -> Language:
        return Language.PYTHON


class FileIssueKind(StrEnum):
    SYNTAX_ERROR = "syntax_error"
    UNSUPPORTED_ENCODING = "unsupported_encoding"
    DECODE_ERROR = "decode_error"
    BINARY = "binary"
    TOO_LARGE = "too_large"
    TOO_COMPLEX = "too_complex"
    UNSUPPORTED_SYNTAX = "unsupported_syntax"
    SYMLINK = "symlink"
    NOT_REGULAR = "not_regular"
    UNREADABLE = "unreadable"


@dataclass(frozen=True, slots=True)
class FileIssue:
    """A workspace file that matched an indexed suffix but produced no symbols."""

    file_path: str
    kind: FileIssueKind

    def __post_init__(self) -> None:
        require_relative_path("file_issue.file_path", self.file_path)
        require_enum(FileIssueKind, "file_issue.kind", self.kind)


@dataclass(frozen=True, slots=True)
class WorkspaceRevision:
    id: RevisionId
    project_id: ProjectId
    sequence: int
    vcs_ref: str | None
    symbols_indexed: bool
    recorded_at: datetime
    file_issues: tuple[FileIssue, ...] = ()
    source_digest: str | None = None

    def __post_init__(self) -> None:
        require_id(IdKind.WORKSPACE_REVISION, self.id, "revision.id")
        require_id(IdKind.PROJECT, self.project_id, "revision.project_id")
        require_int("revision.sequence", self.sequence, minimum=1)
        optional_text("revision.vcs_ref", self.vcs_ref, max_len=VCS_REF_MAX)
        require_bool("revision.symbols_indexed", self.symbols_indexed)
        require_utc("revision.recorded_at", self.recorded_at)
        issues = self.file_issues
        if not isinstance(issues, tuple) or not all(type(item) is FileIssue for item in issues):
            raise ProvenanceInvariantError(
                "R.revision.file_issues", "file_issues must be a tuple of FileIssue"
            )
        if len(issues) > FILE_ISSUES_MAX:
            raise ProvenanceInvariantError(
                "R.revision.file_issues", f"at most {FILE_ISSUES_MAX} file issues"
            )
        if any(left.file_path >= right.file_path for left, right in pairwise(issues)):
            raise ProvenanceInvariantError(
                "R.revision.file_issues", "file_issues must be sorted by unique file_path"
            )
        optional_sha256("revision.source_digest", self.source_digest)
        if not self.symbols_indexed and (issues or self.source_digest is not None):
            raise ProvenanceInvariantError(
                "R.revision.unindexed",
                "an unindexed revision has no file issues and no source digest",
            )

    def issue_for(self, file_path: str) -> FileIssue | None:
        """The issue recorded for ``file_path``, or None."""
        issues = self.file_issues
        position = bisect_left(issues, file_path, key=lambda item: item.file_path)
        if position < len(issues) and issues[position].file_path == file_path:
            return issues[position]
        return None

    @property
    def issue_paths(self) -> frozenset[str]:
        return frozenset(item.file_path for item in self.file_issues)


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
    fingerprint_algorithm: FingerprintAlgorithm | None = None

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
        algorithm = self.fingerprint_algorithm
        if algorithm is not None:
            require_enum(FingerprintAlgorithm, "symbol.fingerprint_algorithm", algorithm)
            if self.fingerprint is None or algorithm.language is not self.language:
                raise ProvenanceInvariantError(
                    "R.symbol.fingerprint_algorithm",
                    "a fingerprint algorithm needs a fingerprint in its own language",
                )

    @property
    def key(self) -> SymbolKey:
        return (self.language, self.file_path, self.qualified_name)

    @property
    def fingerprint_key(self) -> tuple[FingerprintAlgorithm | None, str] | None:
        """``(algorithm, fingerprint)``; fingerprints of different algorithms never match."""
        if self.fingerprint is None:
            return None
        return (self.fingerprint_algorithm, self.fingerprint)


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
