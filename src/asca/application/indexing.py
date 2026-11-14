"""Workspace indexing: turn a workspace snapshot into one recorded, symbol-indexed revision.

``build_index`` is pure and shared with the read-only preview CLI. ``IndexingService`` is
the only writer of indexed revisions. Every limit fails closed, and on any error nothing
is written: a misconfigured or oversized workspace never orphans links.
"""

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

from asca.application.errors import IndexFailure, WorkspaceIndexError
from asca.application.ports import (
    DEFAULT_INDEX_LIMITS,
    IndexLimits,
    SymbolExtractor,
    WorkspaceReader,
    WorkspaceSnapshot,
)
from asca.application.provenance import ProvenanceService, SymbolDraft
from asca.domain.provenance import (
    FileIssue,
    FileIssueKind,
    FingerprintAlgorithm,
    ProjectId,
    RevisionId,
)

SOURCE_DIGEST_PREFIX = b"asca-source-digest/1\n"


@dataclass(frozen=True, slots=True)
class BuiltIndex:
    drafts: tuple[SymbolDraft, ...]
    """Sorted by ``(file_path, qualified_name)``."""
    issues: tuple[FileIssue, ...]
    """Sorted by path."""
    source_digest: str
    files_seen: int
    files_indexed: int
    skipped_definitions: int
    skipped_entries: int


@dataclass(frozen=True, slots=True)
class IndexReport:
    revision_id: RevisionId
    revision_sequence: int
    source_digest: str
    files_seen: int
    files_indexed: int
    symbols_recorded: int
    skipped_definitions: int
    skipped_entries: int
    issues: tuple[FileIssue, ...]


def _checked_extractors(extractors: Sequence[SymbolExtractor]) -> tuple[SymbolExtractor, ...]:
    result = tuple(extractors)
    if not result:
        raise ValueError("at least one symbol extractor is needed")
    suffixes: set[str] = set()
    algorithms: set[FingerprintAlgorithm] = set()
    for extractor in result:
        if suffixes & extractor.suffixes:
            raise ValueError("symbol extractor suffixes must be disjoint")
        if extractor.algorithm in algorithms:
            raise ValueError("symbol extractor algorithms must be unique")
        suffixes |= extractor.suffixes
        algorithms.add(extractor.algorithm)
    return result


def _extractor_for(path: str, extractors: Sequence[SymbolExtractor]) -> SymbolExtractor | None:
    return next(
        (
            extractor
            for extractor in extractors
            if any(path.endswith(suffix) for suffix in extractor.suffixes)
        ),
        None,
    )


def source_digest(snapshot: WorkspaceSnapshot, extractors: Sequence[SymbolExtractor]) -> str:
    """Digest of the algorithms and of every file's path and content hash or reader issue."""
    digest = hashlib.sha256(SOURCE_DIGEST_PREFIX)
    algorithms = sorted(extractor.algorithm.value.encode("ascii") for extractor in extractors)
    digest.update(b"algorithms:" + b",".join(algorithms) + b"\n")
    for file in snapshot.files:
        if file.data is not None:
            state = b"c" + hashlib.sha256(file.data).hexdigest().encode("ascii")
        else:
            assert file.issue is not None  # guaranteed by WorkspaceFile
            state = b"p" + file.issue.value.encode("ascii")
        digest.update(file.path.encode("utf-8") + b"\t" + state + b"\n")
    return digest.hexdigest()


def build_index(
    snapshot: WorkspaceSnapshot,
    extractors: Sequence[SymbolExtractor],
    limits: IndexLimits,
    *,
    allow_empty: bool = False,
) -> BuiltIndex:
    """Extract every file of ``snapshot``; raise ``WorkspaceIndexError`` on a limit."""
    checked = _checked_extractors(extractors)
    files = snapshot.files
    if len(files) > limits.max_files:
        raise WorkspaceIndexError(IndexFailure.MAX_FILES)
    if sum(len(file.data) for file in files if file.data is not None) > limits.max_total_bytes:
        raise WorkspaceIndexError(IndexFailure.MAX_TOTAL_BYTES)
    if not files and not allow_empty:
        raise WorkspaceIndexError(IndexFailure.NO_SOURCE_FILES)
    drafts: list[SymbolDraft] = []
    issues: list[FileIssue] = []
    files_indexed = 0
    skipped_definitions = 0
    skipped_entries = snapshot.skipped_entries
    for file in files:
        if file.data is None:
            assert file.issue is not None  # guaranteed by WorkspaceFile
            issues.append(FileIssue(file.path, file.issue))
            continue
        if len(file.data) > limits.max_file_bytes:
            issues.append(FileIssue(file.path, FileIssueKind.TOO_LARGE))
            continue
        extractor = _extractor_for(file.path, checked)
        if extractor is None:
            skipped_entries += 1
            continue
        extraction = extractor.extract(file.data, limits)
        if extraction.issue is not None:
            issues.append(FileIssue(file.path, extraction.issue))
            continue
        files_indexed += 1
        skipped_definitions += extraction.skipped_definitions
        drafts.extend(
            SymbolDraft(
                extractor.language,
                symbol.kind,
                symbol.qualified_name,
                file.path,
                symbol.span,
                symbol.fingerprint,
                extractor.algorithm,
            )
            for symbol in extraction.symbols
        )
        if len(drafts) > limits.max_symbols:
            raise WorkspaceIndexError(IndexFailure.MAX_SYMBOLS)
    return BuiltIndex(
        drafts=tuple(sorted(drafts, key=lambda draft: (draft.file_path, draft.qualified_name))),
        issues=tuple(sorted(issues, key=lambda issue: issue.file_path)),
        source_digest=source_digest(snapshot, checked),
        files_seen=len(files),
        files_indexed=files_indexed,
        skipped_definitions=skipped_definitions,
        skipped_entries=skipped_entries,
    )


class IndexingService:
    """The only writer of symbol-indexed workspace revisions."""

    def __init__(
        self, provenance: ProvenanceService, extractors: Sequence[SymbolExtractor]
    ) -> None:
        self._provenance = provenance
        self._extractors = _checked_extractors(extractors)
        self._suffixes = frozenset(
            suffix for extractor in self._extractors for suffix in extractor.suffixes
        )

    def index_workspace(
        self,
        project_id: ProjectId,
        reader: WorkspaceReader,
        *,
        vcs_ref: str | None,
        limits: IndexLimits = DEFAULT_INDEX_LIMITS,
        allow_empty: bool = False,
    ) -> IndexReport:
        """Read, extract and record one revision in a single batch.

        Raise ``WorkspaceIndexError`` and write nothing when a limit is exceeded;
        ``ConcurrentModificationError`` propagates without a retry.
        """
        snapshot = reader.read(self._suffixes, limits)
        built = build_index(snapshot, self._extractors, limits, allow_empty=allow_empty)
        recorded = self._provenance.record_workspace_revision(
            project_id,
            vcs_ref=vcs_ref,
            symbols=built.drafts,
            symbols_indexed=True,
            file_issues=built.issues,
            source_digest=built.source_digest,
        )
        return IndexReport(
            revision_id=recorded.revision_id,
            revision_sequence=recorded.sequence,
            source_digest=built.source_digest,
            files_seen=built.files_seen,
            files_indexed=built.files_indexed,
            symbols_recorded=len(recorded.symbol_ids),
            skipped_definitions=built.skipped_definitions,
            skipped_entries=built.skipped_entries,
            issues=built.issues,
        )
