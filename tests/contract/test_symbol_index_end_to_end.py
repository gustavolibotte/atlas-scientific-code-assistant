"""M2 exit criterion, end to end on a real directory tree and a migrated SQLite file.

A temporary workspace is read by ``FilesystemWorkspaceReader``, extracted by
``PythonAstExtractor``, recorded by ``IndexingService`` through ``ProvenanceService`` into
a SQLite store migrated to ``0002``, and read back through the inspector and the HTTP
API. Every fixture is synthetic.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from provenance_builders import make_service
from workspace_builders import write_tree

from asca.api.main import create_app
from asca.application.exports import ExportArtifact
from asca.application.indexing import IndexingService, IndexReport
from asca.application.inspection import inspect_function, link_health, list_symbols
from asca.application.ports import (
    DEFAULT_INDEX_LIMITS,
    IndexLimits,
    WorkspaceReader,
    WorkspaceSnapshot,
)
from asca.application.provenance import DecisionDraft, ProvenanceService
from asca.domain.provenance import (
    MODULE_QUALIFIED_NAME,
    AccessClass,
    CodeSymbol,
    FileIssueKind,
    FingerprintAlgorithm,
    FreshnessReason,
    ImplementationLink,
    LinkFreshness,
    ProjectId,
    ProvenanceGraph,
    SymbolKind,
    SymbolLineage,
    SymbolTrace,
)
from asca.infrastructure.indexing.filesystem import FilesystemWorkspaceReader
from asca.infrastructure.indexing.python_symbols import PythonAstExtractor
from asca.infrastructure.persistence import SqliteProvenanceStore, open_sqlite_store

pytestmark = pytest.mark.contract

PROJECTS = "/api/v1/projects"
ESTIMATORS = "src/reco/estimators.py"
PEDESTAL = "src/reco/pedestal.py"

REV1 = (
    "def estimate_amplitude(samples, weights):\n"
    "    return sum(s * w for s, w in zip(samples, weights))\n"
    "\n\n"
    "def subtract_pedestal(samples, pedestal):\n"
    "    return [s - pedestal for s in samples]\n"
    "\n\n"
    "class Fit:\n"
    "    def fit(self, values):\n"
    "        return max(values)\n"
)
REFORMATTED = (
    '"""Synthetic amplitude estimators (test fixture, not ATLAS code)."""\n'
    "\n\n"
    "def estimate_amplitude(\n"
    "    samples,\n"
    "    weights,  # one weight per sample\n"
    "):\n"
    '    """Weighted sum of the samples."""\n'
    "    # The pedestal is subtracted by the caller.\n"
    "    return sum(\n"
    "        (s * w) for s, w in zip(samples, weights)\n"
    "    )\n"
    "\n\n\n"
    "def subtract_pedestal(samples, pedestal):  # unchanged body\n"
    "    return [\n"
    "        s - pedestal\n"
    "        for s in samples\n"
    "    ]\n"
    "\n"
    "class Fit:\n"
    '    """A fixture fitter."""\n'
    "\n"
    "    def fit(self, values):\n"
    "        return max(values)  # trivially\n"
)
EDITED_BODY = REV1.replace("return sum(s * w", "return 0.5 * sum(s * w")
RENAMED = REV1.replace("def subtract_pedestal(", "def remove_pedestal(")
RENAMED_AND_EDITED = RENAMED.replace("[s - pedestal for s", "[s - 2 * pedestal for s")
DELETED = REV1.replace(
    "def estimate_amplitude(samples, weights):\n"
    "    return sum(s * w for s, w in zip(samples, weights))\n"
    "\n\n",
    "",
)
BROKEN = REV1.replace("def subtract_pedestal(samples, pedestal):", "def subtract_pedestal(samples,")
WITHOUT_PEDESTAL = REV1.replace(
    "def subtract_pedestal(samples, pedestal):\n    return [s - pedestal for s in samples]\n\n\n",
    "",
)
MOVED_PEDESTAL = (
    "def subtract_pedestal(samples, pedestal):\n    return [s - pedestal for s in samples]\n"
)

# Strings that live only in source text and must never leave the indexer.
MARKERS = (
    "MARKER-DOCSTRING-7f3a",
    "MARKER-COMMENT-91c2",
    "MARKER-CONSTANT-55e0",
    "zip(samples, weights)",
    "s - pedestal",
)
MARKED = (
    '"""MARKER-DOCSTRING-7f3a module docstring."""\n'
    "# MARKER-COMMENT-91c2\n"
    'NOTE = "MARKER-CONSTANT-55e0"\n'
    "\n\n" + REV1
)
assert all(marker in MARKED for marker in MARKERS)
# Every variant really differs from rev1 (``str.replace`` fails silently).
assert len({REV1, EDITED_BODY, RENAMED, RENAMED_AND_EDITED, DELETED, BROKEN, WITHOUT_PEDESTAL}) == 7


def _file_url(path: Path) -> str:
    return f"sqlite+pysqlite:///{path}"


@dataclass
class RecordingReader:
    """Delegates to a real reader and keeps every snapshot it returned."""

    inner: WorkspaceReader
    snapshots: list[WorkspaceSnapshot] = field(default_factory=list)

    def read(self, suffixes: frozenset[str], limits: IndexLimits) -> WorkspaceSnapshot:
        snapshot = self.inner.read(suffixes, limits)
        self.snapshots.append(snapshot)
        return snapshot


@dataclass
class ReplayReader:
    snapshots: list[WorkspaceSnapshot]

    def read(self, suffixes: frozenset[str], limits: IndexLimits) -> WorkspaceSnapshot:
        return self.snapshots.pop(0)


@dataclass(frozen=True)
class Linked:
    project: ProjectId
    d1: str
    d2: str
    link1: str
    link2: str
    rev1: IndexReport


def _link_fixture(
    service: ProvenanceService, indexer: IndexingService, reader: WorkspaceReader
) -> Linked:
    """Index rev1, then link D1 to ``estimate_amplitude`` and D2 to ``subtract_pedestal``."""
    project = service.create_project("End-to-end index fixture", is_synthetic=False)
    rev1 = indexer.index_workspace(project, reader, vcs_ref="rev-1")
    by_name = {
        item.qualified_name: item.id for item in service.load(project).symbols_in(rev1.revision_id)
    }
    d1 = service.propose_decision(
        project,
        DecisionDraft(
            title="Weighted amplitude estimate",
            statement="Use a weighted sum of the samples.",
            rationale="Synthetic fixture rationale.",
        ),
    )
    link1 = service.link_implementation(project, d1, by_name["estimate_amplitude"])
    d2 = service.propose_decision(
        project,
        DecisionDraft(
            title="Pedestal subtraction",
            statement="Subtract the pedestal before estimation.",
            rationale="Synthetic fixture rationale.",
        ),
    )
    link2 = service.link_implementation(project, d2, by_name["subtract_pedestal"])
    return Linked(project, d1, d2, link1, link2, rev1)


@dataclass
class World:
    root: Path
    url: str
    store: SqliteProvenanceStore
    service: ProvenanceService
    indexer: IndexingService
    reader: RecordingReader
    linked: Linked

    def write(self, files: dict[str, str]) -> None:
        write_tree(self.root, files)

    def index(self, vcs_ref: str, *, limits: IndexLimits = DEFAULT_INDEX_LIMITS) -> IndexReport:
        return self.indexer.index_workspace(
            self.linked.project, self.reader, vcs_ref=vcs_ref, limits=limits
        )

    def graph(self) -> ProvenanceGraph:
        return self.service.load(self.linked.project)

    def trace(self, link_id: str, graph: ProvenanceGraph | None = None) -> SymbolTrace:
        graph = graph if graph is not None else self.graph()
        return SymbolLineage(graph).resolve(graph.get(ImplementationLink, link_id))

    def latest_symbols(self, file_path: str | None = None) -> dict[str, CodeSymbol]:
        """Symbols of the latest indexed revision by qualified name, module symbols omitted
        unless ``file_path`` selects one file."""
        graph = self.graph()
        latest = graph.latest_revision(indexed_only=True)
        assert latest is not None
        return {
            item.qualified_name: item
            for item in graph.symbols_in(latest.id)
            if (
                item.kind is not SymbolKind.MODULE
                if file_path is None
                else item.file_path == file_path
            )
        }


@pytest.fixture
def world(tmp_path: Path) -> Iterator[World]:
    root = tmp_path / "workspace"
    root.mkdir()
    write_tree(root, {"src/reco/__init__.py": "", ESTIMATORS: REV1})
    url = _file_url(tmp_path / "asca.db")
    store = open_sqlite_store(url)
    try:
        service = make_service(store.repository)
        indexer = IndexingService(service, [PythonAstExtractor()])
        reader = RecordingReader(FilesystemWorkspaceReader(root))
        linked = _link_fixture(service, indexer, reader)
        yield World(root, url, store, service, indexer, reader, linked)
    finally:
        store.dispose()


@pytest.fixture
def client(world: World) -> Iterator[TestClient]:
    with TestClient(create_app(world.url, seed_demo=False)) as http:
        yield http


def _json(client: TestClient, path: str) -> Any:
    response = client.get(path)
    assert response.status_code == 200, path
    return response.json()


def _inspection(client: TestClient, world: World, qualified_name: str) -> Any:
    symbol = world.latest_symbols()[qualified_name]
    return _json(client, f"{PROJECTS}/{world.linked.project}/symbols/{symbol.id}/inspection")


def _every_response(client: TestClient, project: str) -> dict[str, Any]:
    """Every read-only representation of one stored project."""
    symbols = _json(client, f"{PROJECTS}/{project}/symbols")
    responses: dict[str, Any] = {"projects": _json(client, PROJECTS), "symbols": symbols}
    for item in symbols["items"]:
        responses[item["id"]] = _json(
            client, f"{PROJECTS}/{project}/symbols/{item['id']}/inspection"
        )
    for link in symbols["links"]:
        for location in (link["linked_symbol"], link["current_symbol"]):
            if location is not None:
                responses[location["symbol_id"]] = _json(
                    client, f"{PROJECTS}/{project}/symbols/{location['symbol_id']}/inspection"
                )
    for artifact in ExportArtifact:
        for audience in AccessClass:
            response = client.get(
                f"{PROJECTS}/{project}/exports/{artifact.value}?audience={audience.value}"
            )
            assert response.status_code == 200
            responses[f"{artifact.value}:{audience.value}"] = response.text
    return responses


# ---------------------------------------------------------------------- baseline


def test_rev1_indexes_the_tree_into_the_migrated_store(world: World) -> None:
    with world.store.engine.connect() as conn:
        assert conn.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one() == (
            "0002"
        )
    symbols = world.latest_symbols(ESTIMATORS)
    assert {name: item.kind for name, item in symbols.items()} == {
        MODULE_QUALIFIED_NAME: SymbolKind.MODULE,
        "estimate_amplitude": SymbolKind.FUNCTION,
        "subtract_pedestal": SymbolKind.FUNCTION,
        "Fit": SymbolKind.CLASS,
        "Fit.fit": SymbolKind.METHOD,
    }
    assert all(
        item.fingerprint_algorithm is FingerprintAlgorithm.PYTHON_AST_1 for item in symbols.values()
    )
    spans = {
        name: (item.span.start_line, item.span.end_line)
        for name, item in symbols.items()
        if item.span is not None
    }
    assert spans == {
        MODULE_QUALIFIED_NAME: (1, 11),
        "estimate_amplitude": (1, 2),
        "subtract_pedestal": (5, 6),
        "Fit": (9, 11),
        "Fit.fit": (10, 11),
    }
    assert len(world.graph().symbols_in(world.linked.rev1.revision_id)) == 6
    for link in (world.linked.link1, world.linked.link2):
        assert world.trace(link).reason is FreshnessReason.UNCHANGED


# ---------------------------------------------------------------------- exit criterion


def test_reformat_comments_and_docstring_keep_links_current(world: World) -> None:
    world.write({ESTIMATORS: REFORMATTED})
    report = world.index("rev-2")
    assert report.issues == ()
    assert report.source_digest != world.linked.rev1.source_digest

    for link in (world.linked.link1, world.linked.link2):
        trace = world.trace(link)
        assert (trace.freshness, trace.reason) == (LinkFreshness.CURRENT, FreshnessReason.UNCHANGED)
        assert trace.current is not None
        assert trace.current.revision_id == report.revision_id
    assert world.latest_symbols()["Fit.fit"].fingerprint == next(
        item.fingerprint
        for item in world.graph().symbols_in(world.linked.rev1.revision_id)
        if item.qualified_name == "Fit.fit"
    )


def test_editing_the_body_marks_the_link_stale(world: World, client: TestClient) -> None:
    world.write({ESTIMATORS: EDITED_BODY})
    world.index("rev-2")

    trace = world.trace(world.linked.link1)
    assert (trace.freshness, trace.reason) == (LinkFreshness.STALE, FreshnessReason.CONTENT_CHANGED)
    assert world.trace(world.linked.link2).freshness is LinkFreshness.CURRENT

    [view] = inspect_function(
        world.graph(), world.latest_symbols()["estimate_amplitude"].id
    ).decisions
    assert (view.decision.id, view.freshness) == (world.linked.d1, LinkFreshness.STALE)
    [decision] = _inspection(client, world, "estimate_amplitude")["decisions"]
    assert decision["implementation"]["freshness"] == "stale"
    assert decision["implementation"]["freshness_reason"] == "content_changed"


def test_rename_without_body_change_is_a_move(world: World, client: TestClient) -> None:
    world.write({ESTIMATORS: RENAMED})
    report = world.index("rev-2")

    trace = world.trace(world.linked.link2)
    assert (trace.freshness, trace.reason) == (LinkFreshness.MOVED, FreshnessReason.RELOCATED)
    assert trace.current is not None
    assert (trace.current.qualified_name, trace.current.file_path) == (
        "remove_pedestal",
        ESTIMATORS,
    )
    assert trace.current.revision_id == report.revision_id
    assert world.trace(world.linked.link1).freshness is LinkFreshness.CURRENT

    symbols = world.latest_symbols()
    assert "subtract_pedestal" not in symbols
    summaries = {item.symbol.qualified_name: item for item in list_symbols(world.graph())}
    assert "subtract_pedestal" not in summaries
    moved = summaries["remove_pedestal"]
    assert (moved.decision_count, moved.worst_freshness) == (1, LinkFreshness.MOVED)

    # The inspector shows the carried link and the new location.
    [view] = inspect_function(world.graph(), symbols["remove_pedestal"].id).decisions
    assert (view.decision.id, view.freshness) == (world.linked.d2, LinkFreshness.MOVED)
    assert view.trace.current == symbols["remove_pedestal"]
    [decision] = _inspection(client, world, "remove_pedestal")["decisions"]
    implementation = decision["implementation"]
    assert (implementation["freshness"], implementation["freshness_reason"]) == (
        "moved",
        "relocated",
    )
    assert implementation["linked_symbol"]["qualified_name"] == "subtract_pedestal"
    assert implementation["current_symbol"] == {
        "symbol_id": symbols["remove_pedestal"].id,
        "qualified_name": "remove_pedestal",
        "file_path": ESTIMATORS,
        "kind": "function",
        "span": {"start_line": 5, "end_line": 6},
        "revision_sequence": report.revision_sequence,
    }
    listing = _json(client, f"{PROJECTS}/{world.linked.project}/symbols")
    listed = {item["qualified_name"]: item for item in listing["items"]}
    assert "subtract_pedestal" not in listed
    assert (
        listed["remove_pedestal"]["decision_count"],
        listed["remove_pedestal"]["worst_freshness"],
    ) == (
        1,
        "moved",
    )


def test_move_to_another_file_is_a_move(world: World) -> None:
    world.write({ESTIMATORS: WITHOUT_PEDESTAL, PEDESTAL: MOVED_PEDESTAL})
    world.index("rev-2")

    trace = world.trace(world.linked.link2)
    assert (trace.freshness, trace.reason) == (LinkFreshness.MOVED, FreshnessReason.RELOCATED)
    assert trace.current is not None
    assert (trace.current.qualified_name, trace.current.file_path) == (
        "subtract_pedestal",
        PEDESTAL,
    )
    [summary] = [
        item for item in list_symbols(world.graph()) if item.symbol.key == trace.current.key
    ]
    assert (summary.decision_count, summary.worst_freshness) == (1, LinkFreshness.MOVED)


def test_rename_then_edit_is_stale_at_new_location(world: World) -> None:
    world.write({ESTIMATORS: RENAMED})
    world.index("rev-2")
    world.write({ESTIMATORS: RENAMED_AND_EDITED})
    rev3 = world.index("rev-3")

    trace = world.trace(world.linked.link2)
    assert (trace.freshness, trace.reason) == (
        LinkFreshness.STALE,
        FreshnessReason.RELOCATED_AND_CHANGED,
    )
    assert trace.current is not None
    assert (trace.current.qualified_name, trace.current.revision_id) == (
        "remove_pedestal",
        rev3.revision_id,
    )
    [view] = inspect_function(world.graph(), trace.current.id).decisions
    assert (view.decision.id, view.freshness) == (world.linked.d2, LinkFreshness.STALE)


def test_deleting_the_function_orphans_the_link(world: World, client: TestClient) -> None:
    world.write({ESTIMATORS: DELETED})
    rev2 = world.index("rev-2")

    trace = world.trace(world.linked.link1)
    assert (trace.freshness, trace.reason) == (LinkFreshness.ORPHANED, FreshnessReason.REMOVED)
    assert trace.current is None
    assert trace.lost_in_revision is not None
    assert trace.lost_in_revision.id == rev2.revision_id
    assert trace.last_seen.revision_id == world.linked.rev1.revision_id
    assert "estimate_amplitude" not in world.latest_symbols()

    health = {item.link.id: item for item in link_health(world.graph())}
    assert health[world.linked.link1].trace.freshness is LinkFreshness.ORPHANED
    assert health[world.linked.link2].trace.freshness is LinkFreshness.CURRENT
    assert next(iter(health)) == world.linked.link1  # orphaned links are listed first

    links = _json(client, f"{PROJECTS}/{world.linked.project}/symbols")["links"]
    by_id = {item["link_id"]: item for item in links}
    orphan = by_id[world.linked.link1]
    assert (orphan["freshness"], orphan["freshness_reason"]) == ("orphaned", "removed")
    assert orphan["current_symbol"] is None
    assert orphan["linked_symbol"]["qualified_name"] == "estimate_amplitude"
    assert orphan["decision_id"] == world.linked.d1


def test_syntax_error_is_unknown_and_recovers(world: World, client: TestClient) -> None:
    world.write({ESTIMATORS: BROKEN})
    rev2 = world.index("rev-2")
    assert [(item.file_path, item.kind) for item in rev2.issues] == [
        (ESTIMATORS, FileIssueKind.SYNTAX_ERROR)
    ]
    assert rev2.symbols_recorded == 1  # only the module symbol of __init__.py

    for link in (world.linked.link1, world.linked.link2):
        trace = world.trace(link)
        assert (trace.freshness, trace.reason) == (
            LinkFreshness.UNKNOWN,
            FreshnessReason.FILE_NOT_PARSED,
        )
        assert trace.lost_in_revision is None
        assert trace.last_seen.revision_id == world.linked.rev1.revision_id
    listing = _json(client, f"{PROJECTS}/{world.linked.project}/symbols")
    assert listing["file_issues"] == [{"file_path": ESTIMATORS, "kind": "syntax_error"}]
    assert {item["freshness"] for item in listing["links"]} == {"unknown"}
    assert all(item["freshness"] != "orphaned" for item in listing["links"])

    world.write({ESTIMATORS: REV1})
    rev3 = world.index("rev-3")
    assert rev3.issues == ()
    assert rev3.source_digest == world.linked.rev1.source_digest
    for link in (world.linked.link1, world.linked.link2):
        trace = world.trace(link)
        assert (trace.freshness, trace.reason) == (LinkFreshness.CURRENT, FreshnessReason.UNCHANGED)
        assert trace.current is not None
        assert trace.current.revision_id == rev3.revision_id


@pytest.mark.parametrize("problem", ["symlink", "oversized"])
def test_symlinked_or_oversized_file_is_unknown_not_orphaned(
    world: World, tmp_path: Path, problem: str
) -> None:
    limits = DEFAULT_INDEX_LIMITS
    if problem == "symlink":
        outside = tmp_path / "outside" / "estimators.py"
        outside.parent.mkdir()
        outside.write_text(REV1, encoding="utf-8")
        target = world.root / ESTIMATORS
        target.unlink()
        os.symlink(outside, target)
        expected = FileIssueKind.SYMLINK
    else:
        limits = replace(DEFAULT_INDEX_LIMITS, max_file_bytes=len(REV1) - 1)
        expected = FileIssueKind.TOO_LARGE
    rev2 = world.index("rev-2", limits=limits)
    assert [(item.file_path, item.kind) for item in rev2.issues] == [(ESTIMATORS, expected)]

    for link in (world.linked.link1, world.linked.link2):
        trace = world.trace(link)
        assert (trace.freshness, trace.reason) == (
            LinkFreshness.UNKNOWN,
            FreshnessReason.FILE_NOT_PARSED,
        )
    inspection = inspect_function(world.graph(), world.trace(world.linked.link1).last_seen.id)
    assert inspection.file_issue is not None
    assert inspection.file_issue.kind is expected


def test_reopened_store_gives_identical_traces_and_api_responses(world: World) -> None:
    world.write({ESTIMATORS: RENAMED.replace("return sum(s * w", "return 2 * sum(s * w")})
    world.index("rev-2")
    graph = world.graph()
    traces = {link: world.trace(link, graph) for link in (world.linked.link1, world.linked.link2)}
    assert {link: trace.freshness for link, trace in traces.items()} == {
        world.linked.link1: LinkFreshness.STALE,
        world.linked.link2: LinkFreshness.MOVED,
    }
    world.store.dispose()

    reopened = open_sqlite_store(world.url)
    try:
        stored = reopened.repository.load(world.linked.project)
    finally:
        reopened.dispose()
    assert stored == graph
    assert {link: world.trace(link, stored) for link in traces} == traces

    # The same reads replayed into the in-memory repository give the same graph.
    memory = make_service()
    replay = ReplayReader(list(world.reader.snapshots))
    memory_indexer = IndexingService(memory, [PythonAstExtractor()])
    assert _link_fixture(memory, memory_indexer, replay) == world.linked
    memory_indexer.index_workspace(world.linked.project, replay, vcs_ref="rev-2")
    assert memory.load(world.linked.project) == stored

    responses = []
    for _ in range(2):
        with TestClient(create_app(world.url, seed_demo=False)) as http:
            responses.append(_every_response(http, world.linked.project))
    assert responses[0] == responses[1]
    api_links = {item["link_id"]: item for item in responses[0]["symbols"]["links"]}
    assert {
        link: (item["freshness"], item["freshness_reason"]) for link, item in api_links.items()
    } == {link: (trace.freshness.value, trace.reason.value) for link, trace in traces.items()}


def test_unchanged_tree_reindex_gives_identical_digest_and_fingerprints(world: World) -> None:
    before = world.latest_symbols()
    rev2 = world.index("rev-2")
    after = world.latest_symbols()

    assert rev2.source_digest == world.linked.rev1.source_digest
    assert rev2.revision_id != world.linked.rev1.revision_id
    assert (rev2.files_seen, rev2.files_indexed, rev2.symbols_recorded) == (
        world.linked.rev1.files_seen,
        world.linked.rev1.files_indexed,
        world.linked.rev1.symbols_recorded,
    )
    assert {name: (item.key, item.fingerprint, item.span) for name, item in after.items()} == {
        name: (item.key, item.fingerprint, item.span) for name, item in before.items()
    }
    assert all(after[name].id != before[name].id for name in before)
    for link in (world.linked.link1, world.linked.link2):
        assert world.trace(link).reason is FreshnessReason.UNCHANGED


def test_api_responses_never_contain_source_text(world: World, client: TestClient) -> None:
    world.write(
        {ESTIMATORS: MARKED, "src/reco/broken.py": "def broken(:\n    'MARKER-COMMENT-91c2'\n"}
    )
    rev2 = world.index("rev-2")
    assert [(item.file_path, item.kind) for item in rev2.issues] == [
        ("src/reco/broken.py", FileIssueKind.SYNTAX_ERROR)
    ]

    responses = _every_response(client, world.linked.project)
    assert len(responses) > 10
    text = repr(responses)
    for marker in (*MARKERS, str(world.root), "workspace/src"):
        assert marker not in text
    # The stored rows hold no source text either.
    with world.store.engine.connect() as conn:
        dump = "\n".join(conn.connection.driver_connection.iterdump())
    for marker in MARKERS:
        assert marker not in dump
