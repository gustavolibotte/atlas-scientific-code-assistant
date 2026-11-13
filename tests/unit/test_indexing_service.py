"""Indexing service and ``build_index`` with a fake reader and the real Python extractor."""

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field

import pytest
from provenance_builders import make_service

from asca.application.errors import (
    ConcurrentModificationError,
    IndexFailure,
    WorkspaceIndexError,
)
from asca.application.indexing import (
    IndexingService,
    build_index,
    source_digest,
)
from asca.application.ports import (
    DEFAULT_INDEX_LIMITS,
    EXTRACTION_ISSUES,
    READER_ISSUES,
    ExtractedSymbol,
    FileExtraction,
    IndexLimits,
    WorkspaceFile,
    WorkspaceSnapshot,
)
from asca.application.provenance import ProvenanceService
from asca.domain.provenance import (
    MODULE_QUALIFIED_NAME,
    FileIssue,
    FileIssueKind,
    FingerprintAlgorithm,
    Language,
    ProjectId,
    ProvenanceGraph,
    ProvenanceRecord,
    SourceSpan,
    SymbolKind,
)
from asca.infrastructure.indexing.python_symbols import PythonAstExtractor
from asca.infrastructure.memory_provenance import InMemoryProvenanceRepository

pytestmark = pytest.mark.unit

EXTRACTOR = PythonAstExtractor()


@dataclass
class FakeReader:
    snapshot: WorkspaceSnapshot
    calls: list[tuple[frozenset[str], IndexLimits]] = field(default_factory=list)

    def read(self, suffixes: frozenset[str], limits: IndexLimits) -> WorkspaceSnapshot:
        self.calls.append((suffixes, limits))
        return self.snapshot


@dataclass(frozen=True)
class FakeExtractor:
    suffixes: frozenset[str]
    algorithm: FingerprintAlgorithm = FingerprintAlgorithm.PYTHON_AST_1
    language: Language = Language.PYTHON

    def extract(self, data: bytes, limits: IndexLimits) -> FileExtraction:
        raise AssertionError("not used")


def snapshot(*files: WorkspaceFile, skipped: int = 0) -> WorkspaceSnapshot:
    return WorkspaceSnapshot(tuple(sorted(files, key=lambda item: item.path)), skipped)


def source(path: str, text: str) -> WorkspaceFile:
    return WorkspaceFile(path, text.encode("utf-8"), None)


def problem(path: str, issue: FileIssueKind) -> WorkspaceFile:
    return WorkspaceFile(path, None, issue)


WORKSPACE = snapshot(
    source("src/b.py", "def b():\n    return 1\n"),
    source("src/a.py", "class A:\n    def m(self):\n        pass\n"),
    source("src/bad.py", "def broken(:\n"),
    problem("src/link.py", FileIssueKind.SYMLINK),
    source("src/README.md", "not python"),
    skipped=2,
)


def _project() -> tuple[ProvenanceService, ProjectId]:
    service = make_service()
    return service, service.create_project("Indexing fixture", is_synthetic=False)


def test_index_workspace_records_sorted_drafts_with_algorithm_and_issues() -> None:
    service, project = _project()
    reader = FakeReader(WORKSPACE)
    report = IndexingService(service, [EXTRACTOR]).index_workspace(
        project, reader, vcs_ref="abc123"
    )
    assert reader.calls == [(frozenset({".py"}), DEFAULT_INDEX_LIMITS)]
    graph = service.load(project)
    (revision,) = graph.revisions
    assert revision.id == report.revision_id
    assert revision.sequence == report.revision_sequence == 1
    assert revision.symbols_indexed
    assert revision.vcs_ref == "abc123"
    assert revision.source_digest == report.source_digest
    assert revision.file_issues == (
        FileIssue("src/bad.py", FileIssueKind.SYNTAX_ERROR),
        FileIssue("src/link.py", FileIssueKind.SYMLINK),
    )
    assert report.issues == revision.file_issues
    symbols = graph.symbols_in(revision.id)
    assert {(item.file_path, item.qualified_name, item.kind) for item in symbols} == {
        ("src/a.py", MODULE_QUALIFIED_NAME, SymbolKind.MODULE),
        ("src/a.py", "A", SymbolKind.CLASS),
        ("src/a.py", "A.m", SymbolKind.METHOD),
        ("src/b.py", MODULE_QUALIFIED_NAME, SymbolKind.MODULE),
        ("src/b.py", "b", SymbolKind.FUNCTION),
    }
    assert all(item.fingerprint_algorithm is FingerprintAlgorithm.PYTHON_AST_1 for item in symbols)
    assert all(item.fingerprint is not None and item.span is not None for item in symbols)
    assert report.symbols_recorded == 5
    assert (report.files_seen, report.files_indexed) == (5, 2)
    assert report.skipped_entries == 3  # two from the reader, one unmatched suffix
    assert report.skipped_definitions == 0


def test_build_index_drafts_are_sorted_by_path_and_name() -> None:
    built = build_index(WORKSPACE, [EXTRACTOR], DEFAULT_INDEX_LIMITS)
    keys = [(draft.file_path, draft.qualified_name) for draft in built.drafts]
    assert keys == sorted(keys)
    assert {draft.fingerprint_algorithm for draft in built.drafts} == {
        FingerprintAlgorithm.PYTHON_AST_1
    }
    assert [issue.file_path for issue in built.issues] == ["src/bad.py", "src/link.py"]


def test_skipped_definitions_are_counted() -> None:
    files = snapshot(source("src/a.py", "def caf\u00e9(): pass\ndef __module__(): pass\n"))
    assert build_index(files, [EXTRACTOR], DEFAULT_INDEX_LIMITS).skipped_definitions == 2


def test_source_digest_is_deterministic_and_sensitive() -> None:
    def digest(files: WorkspaceSnapshot) -> str:
        return build_index(files, [EXTRACTOR], DEFAULT_INDEX_LIMITS).source_digest

    base = snapshot(source("src/a.py", "x = 1\n"), problem("src/b.py", FileIssueKind.SYMLINK))
    reference = digest(base)
    assert reference == digest(
        snapshot(source("src/a.py", "x = 1\n"), problem("src/b.py", FileIssueKind.SYMLINK))
    )
    variants = [
        snapshot(source("src/a.py", "x = 2\n"), problem("src/b.py", FileIssueKind.SYMLINK)),
        snapshot(source("src/c.py", "x = 1\n"), problem("src/b.py", FileIssueKind.SYMLINK)),
        snapshot(source("src/a.py", "x = 1\n"), problem("src/b.py", FileIssueKind.UNREADABLE)),
        snapshot(source("src/a.py", "x = 1\n"), problem("src/d.py", FileIssueKind.SYMLINK)),
        snapshot(source("src/a.py", "x = 1\n")),
    ]
    assert len({reference, *(digest(item) for item in variants)}) == len(variants) + 1
    assert source_digest(base, []) != reference
    expected = hashlib.sha256(
        b"asca-source-digest/1\n"
        b"algorithms:python-ast/1\n"
        b"src/a.py\tc" + hashlib.sha256(b"x = 1\n").hexdigest().encode() + b"\n"
        b"src/b.py\tpsymlink\n"
    ).hexdigest()
    assert reference == expected


def test_extractor_set_is_validated() -> None:
    service, _ = _project()
    with pytest.raises(ValueError, match="disjoint"):
        IndexingService(service, [EXTRACTOR, FakeExtractor(frozenset({".py", ".pyw"}))])
    with pytest.raises(ValueError, match="unique"):
        IndexingService(service, [EXTRACTOR, FakeExtractor(frozenset({".pyw"}))])
    with pytest.raises(ValueError, match="at least one"):
        IndexingService(service, [])
    with pytest.raises(ValueError, match="disjoint"):
        build_index(WORKSPACE, [EXTRACTOR, EXTRACTOR], DEFAULT_INDEX_LIMITS)


@pytest.mark.parametrize(
    ("files", "limits", "failure"),
    [
        (WORKSPACE, IndexLimits(max_files=4), IndexFailure.MAX_FILES),
        (WORKSPACE, IndexLimits(max_total_bytes=40), IndexFailure.MAX_TOTAL_BYTES),
        (WORKSPACE, IndexLimits(max_symbols=4), IndexFailure.MAX_SYMBOLS),
        (snapshot(skipped=3), DEFAULT_INDEX_LIMITS, IndexFailure.NO_SOURCE_FILES),
    ],
)
def test_index_failures_write_nothing(
    files: WorkspaceSnapshot, limits: IndexLimits, failure: IndexFailure
) -> None:
    service, project = _project()
    before = service.load(project)
    with pytest.raises(WorkspaceIndexError) as error:
        IndexingService(service, [EXTRACTOR]).index_workspace(
            project, FakeReader(files), vcs_ref=None, limits=limits
        )
    assert error.value.failure is failure
    assert str(error.value) == f"workspace indexing failed: {failure.value}"
    assert "src/" not in str(error.value)
    after = service.load(project)
    assert after.revision == before.revision
    assert after.revisions == ()


def test_limits_at_the_boundary_pass() -> None:
    total = sum(len(item.data) for item in WORKSPACE.files if item.data is not None)
    limits = IndexLimits(max_files=5, max_total_bytes=total, max_symbols=5)
    assert len(build_index(WORKSPACE, [EXTRACTOR], limits).drafts) == 5


def test_allow_empty_records_an_empty_revision() -> None:
    service, project = _project()
    report = IndexingService(service, [EXTRACTOR]).index_workspace(
        project, FakeReader(snapshot()), vcs_ref=None, allow_empty=True
    )
    graph = service.load(project)
    (revision,) = graph.revisions
    assert revision.symbols_indexed
    assert graph.symbols == ()
    assert report.symbols_recorded == 0
    assert report.files_seen == 0
    assert revision.source_digest == report.source_digest


def test_oversized_workspace_file_becomes_too_large() -> None:
    files = snapshot(source("src/a.py", "x = 1\n" * 10), source("src/b.py", "y = 2\n"))
    built = build_index(files, [EXTRACTOR], IndexLimits(max_file_bytes=10))
    assert built.issues == (FileIssue("src/a.py", FileIssueKind.TOO_LARGE),)
    assert {draft.file_path for draft in built.drafts} == {"src/b.py"}
    assert built.files_indexed == 1


def test_reindexing_records_a_new_revision_each_time() -> None:
    service, project = _project()
    indexing = IndexingService(service, [EXTRACTOR])
    first = indexing.index_workspace(project, FakeReader(WORKSPACE), vcs_ref=None)
    second = indexing.index_workspace(project, FakeReader(WORKSPACE), vcs_ref=None)
    assert (first.revision_sequence, second.revision_sequence) == (1, 2)
    assert first.source_digest == second.source_digest
    graph = service.load(project)
    fingerprints = [
        sorted((item.key, item.fingerprint) for item in graph.symbols_in(revision.id))
        for revision in graph.indexed_revisions()
    ]
    assert fingerprints[0] == fingerprints[1]


class ConflictingRepository(InMemoryProvenanceRepository):
    def append(
        self, project_id: ProjectId, expected_revision: int, records: Sequence[ProvenanceRecord]
    ) -> int:
        raise ConcurrentModificationError("conflict")


def test_concurrent_modification_propagates() -> None:
    repository = ConflictingRepository()
    service = make_service(repository)
    project = service.create_project("Conflict fixture", is_synthetic=False)
    with pytest.raises(ConcurrentModificationError):
        IndexingService(service, [EXTRACTOR]).index_workspace(
            project, FakeReader(WORKSPACE), vcs_ref=None
        )
    graph: ProvenanceGraph = service.load(project)
    assert graph.revisions == ()


# ---------------------------------------------------------------------- port validation


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "1"])
def test_index_limits_must_be_positive_integers(value: object) -> None:
    for name in ("max_files", "max_symbols", "max_ast_nodes_per_file"):
        with pytest.raises(ValueError, match="positive integers"):
            IndexLimits(**{name: value})  # type: ignore[arg-type]


def test_issue_partitions() -> None:
    assert frozenset(FileIssueKind) == READER_ISSUES | EXTRACTION_ISSUES
    assert not READER_ISSUES & EXTRACTION_ISSUES


@pytest.mark.parametrize(
    ("path", "data", "issue"),
    [
        ("/abs.py", b"", None),
        ("../x.py", b"", None),
        ("a.py", None, None),
        ("a.py", b"", FileIssueKind.SYMLINK),
        ("a.py", None, FileIssueKind.SYNTAX_ERROR),
        ("a.py", "text", None),
        ("a.py", bytearray(b"x"), None),
    ],
)
def test_workspace_file_validation(path: str, data: object, issue: FileIssueKind | None) -> None:
    with pytest.raises(ValueError) as error:
        WorkspaceFile(path, data, issue)  # type: ignore[arg-type]
    assert path not in str(error.value) or path == "a.py"


def test_workspace_snapshot_validation() -> None:
    first = source("a.py", "")
    second = source("b.py", "")
    with pytest.raises(ValueError, match="strictly increasing"):
        WorkspaceSnapshot((second, first), 0)
    with pytest.raises(ValueError, match="strictly increasing"):
        WorkspaceSnapshot((first, first), 0)
    with pytest.raises(ValueError, match="tuple"):
        WorkspaceSnapshot([first], 0)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="tuple"):
        WorkspaceSnapshot(("a.py",), 0)  # type: ignore[arg-type]
    for skipped in (-1, True, 1.0):
        with pytest.raises(ValueError, match="skipped_entries"):
            WorkspaceSnapshot((first,), skipped)  # type: ignore[arg-type]


def test_file_extraction_validation() -> None:
    symbol = ExtractedSymbol(SymbolKind.FUNCTION, "f", SourceSpan(1, 1), "0" * 64)
    with pytest.raises(ValueError, match="no symbols"):
        FileExtraction(FileIssueKind.SYNTAX_ERROR, (symbol,), 0)
    with pytest.raises(ValueError, match="reader issue"):
        FileExtraction(FileIssueKind.SYMLINK, (), 0)
    with pytest.raises(ValueError, match="unique"):
        FileExtraction(None, (symbol, symbol), 0)
    for skipped in (-1, True):
        with pytest.raises(ValueError, match="skipped_definitions"):
            FileExtraction(None, (symbol,), skipped)  # type: ignore[arg-type]
    assert FileExtraction(FileIssueKind.TOO_COMPLEX, (), 0).issue is FileIssueKind.TOO_COMPLEX
