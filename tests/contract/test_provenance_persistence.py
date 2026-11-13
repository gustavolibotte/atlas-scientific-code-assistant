"""SQLite provenance store: reload equality, compare-and-set and repository errors."""

from __future__ import annotations

import multiprocessing
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
import sqlalchemy as sa
from hypothesis import HealthCheck, given, settings
from provenance_builders import build_complete_real_project, make_service
from provenance_strategies import Script, command_scripts, replay
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects import sqlite as sqlite_dialect
from sqlalchemy.orm import sessionmaker
from store_workers import open_store_at_barrier

from asca.application.demo import DEMO_PROJECT_ID, seed_synthetic_demo
from asca.application.errors import (
    ConcurrentModificationError,
    DuplicateProjectError,
    ProjectNotFoundError,
    StoredGraphIntegrityError,
)
from asca.application.ports import ProjectSummary
from asca.application.provenance import ProvenanceService, SymbolDraft
from asca.domain.provenance import (
    AccessClass,
    FileIssue,
    FileIssueKind,
    FingerprintAlgorithm,
    Language,
    PersistentIdentifier,
    PidScheme,
    Project,
    ProjectId,
    ProvenanceGraph,
    ProvenanceInvariantError,
    ProvenanceRecord,
    RevisionId,
    Source,
    SourceAuthority,
    SourceId,
    SourceVersion,
    SourceVersionId,
    SymbolKind,
    ValidationRun,
    WorkspaceRevision,
)
from asca.infrastructure.memory_provenance import InMemoryProvenanceRepository
from asca.infrastructure.persistence import (
    SqlAlchemyProvenanceRepository,
    SqliteProvenanceStore,
    create_engine_for,
    open_sqlite_store,
    run_migrations,
)
from asca.infrastructure.persistence.mapping import record_to_rows
from asca.infrastructure.persistence.types import UtcDateTime

pytestmark = pytest.mark.contract

MEMORY_URL = "sqlite+pysqlite:///:memory:"
NOW = datetime(2026, 11, 12, 9, 30, tzinfo=UTC)


def _file_url(path: Path) -> str:
    return f"sqlite+pysqlite:///{path}"


@pytest.fixture
def memory_store() -> Iterator[SqliteProvenanceStore]:
    store = open_sqlite_store(MEMORY_URL)
    yield store
    store.dispose()


def _project(n: int = 1, *, created_at: datetime = NOW) -> Project:
    return Project(
        id=ProjectId(f"prj_{n:032x}"),
        title=f"Fixture project {n}",
        is_synthetic=False,
        created_at=created_at,
    )


def _source(project: Project, n: int) -> Source:
    return Source(
        id=SourceId(f"src_{n:032x}"),
        project_id=project.id,
        title=f"Fixture source {n}",
        persistent_id=PersistentIdentifier(
            PidScheme.URL, f"https://example.org/asca-test/source-{n}"
        ),
        created_at=NOW,
    )


def _count(store: SqliteProvenanceStore, table: str) -> int:
    with store.engine.connect() as conn:
        return int(conn.exec_driver_sql(f"SELECT COUNT(*) FROM {table}").scalar_one())


# ---------------------------------------------------------------------- exit criterion


def test_complete_project_survives_engine_disposal_and_reopen(tmp_path: Path) -> None:
    url = _file_url(tmp_path / "asca.db")
    store = open_sqlite_store(url)
    ids = build_complete_real_project(make_service(store.repository))
    store.dispose()

    reopened = open_sqlite_store(url)
    try:
        stored = reopened.repository.load(ids.project)
    finally:
        reopened.dispose()

    memory_service = make_service()
    memory_ids = build_complete_real_project(memory_service)
    assert memory_ids == ids
    assert stored == memory_service.load(ids.project)
    assert stored.revision > 0


@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
@given(script=command_scripts())
def test_replayed_scripts_load_identically_from_sqlite_and_memory(script: Script) -> None:
    store = open_sqlite_store(MEMORY_URL)
    try:
        sqlite_service = make_service(store.repository)
        memory_service = make_service()
        sqlite_result = replay(script, sqlite_service)
        memory_result = replay(script, memory_service)
        assert sqlite_result == memory_result
        assert sqlite_service.load(sqlite_result.project_id) == memory_service.load(
            memory_result.project_id
        )
    finally:
        store.dispose()


def test_seeded_demo_loads_identically_from_sqlite_and_memory(
    memory_store: SqliteProvenanceStore,
) -> None:
    """The demo has alternatives and assumptions (with and without a justification)."""
    seed_synthetic_demo(memory_store.repository)
    memory = InMemoryProvenanceRepository()
    seed_synthetic_demo(memory)
    stored = memory_store.repository.load(DEMO_PROJECT_ID)
    assert stored == memory.load(DEMO_PROJECT_ID)
    details = [(item.alternatives, item.assumptions) for item in stored.decisions]
    assert any(alternatives for alternatives, _ in details)
    justifications = {item.justification for _, items in details for item in items}
    assert None in justifications and len(justifications) > 1


# ---------------------------------------------------------------------- symbol index fields

INDEX_DIGEST = "d" * 64


@dataclass(frozen=True)
class IndexedProject:
    project: ProjectId
    indexed: RevisionId
    unindexed: RevisionId


def _record_index_revisions(service: ProvenanceService) -> IndexedProject:
    """An indexed revision with file issues, a digest and fingerprinted symbols (with and
    without an algorithm), then an unindexed revision."""
    project = service.create_project("Symbol index fixture", is_synthetic=False)
    algorithm = FingerprintAlgorithm.PYTHON_AST_1
    indexed = service.record_workspace_revision(
        project,
        vcs_ref="fixture-ref",
        symbols=[
            SymbolDraft(
                Language.PYTHON,
                SymbolKind.MODULE,
                "__module__",
                "src/reco/a.py",
                None,
                "1" * 64,
                algorithm,
            ),
            SymbolDraft(
                Language.PYTHON,
                SymbolKind.FUNCTION,
                "estimate",
                "src/reco/a.py",
                None,
                "2" * 64,
                algorithm,
            ),
            SymbolDraft(
                Language.PYTHON, SymbolKind.FUNCTION, "legacy", "src/reco/a.py", None, "3" * 64
            ),
            SymbolDraft(Language.PYTHON, SymbolKind.FUNCTION, "unhashed", "src/reco/a.py"),
        ],
        symbols_indexed=True,
        file_issues=(
            FileIssue("src/reco/z_binary.py", FileIssueKind.BINARY),
            FileIssue("src/reco/broken.py", FileIssueKind.SYNTAX_ERROR),
        ),
        source_digest=INDEX_DIGEST,
    )
    unindexed = service.record_workspace_revision(
        project, vcs_ref=None, symbols=[], symbols_indexed=False
    )
    return IndexedProject(project, indexed.revision_id, unindexed.revision_id)


def test_symbol_index_fields_round_trip_through_sqlite_and_memory(tmp_path: Path) -> None:
    url = _file_url(tmp_path / "index.db")
    store = open_sqlite_store(url)
    ids = _record_index_revisions(make_service(store.repository))
    store.dispose()
    reopened = open_sqlite_store(url)
    try:
        stored = reopened.repository.load(ids.project)
    finally:
        reopened.dispose()

    memory_service = make_service()
    assert _record_index_revisions(memory_service) == ids
    assert stored == memory_service.load(ids.project)
    revision = stored.get(WorkspaceRevision, ids.indexed)
    assert revision.source_digest == INDEX_DIGEST
    assert revision.file_issues == (
        FileIssue("src/reco/broken.py", FileIssueKind.SYNTAX_ERROR),
        FileIssue("src/reco/z_binary.py", FileIssueKind.BINARY),
    )
    algorithms = {symbol.qualified_name: symbol.fingerprint_algorithm for symbol in stored.symbols}
    assert algorithms == {
        "__module__": FingerprintAlgorithm.PYTHON_AST_1,
        "estimate": FingerprintAlgorithm.PYTHON_AST_1,
        "legacy": None,
        "unhashed": None,
    }
    assert all(type(value) is not str for value in algorithms.values())
    unindexed = stored.get(WorkspaceRevision, ids.unindexed)
    assert unindexed.file_issues == () and unindexed.source_digest is None


def test_file_issues_are_stored_as_a_json_list_of_path_and_kind(
    memory_store: SqliteProvenanceStore,
) -> None:
    ids = _record_index_revisions(make_service(memory_store.repository))
    with memory_store.engine.connect() as conn:
        stored = dict(
            conn.exec_driver_sql("SELECT id, file_issues FROM workspace_revisions").tuples().all()
        )
    assert stored == {
        ids.indexed: '[{"file_path": "src/reco/broken.py", "kind": "syntax_error"}, '
        '{"file_path": "src/reco/z_binary.py", "kind": "binary"}]',
        ids.unindexed: "[]",
    }


def _tamper(store: SqliteProvenanceStore, sql: str, **params: object) -> None:
    """Run ``sql`` with the append-only triggers dropped and CHECKs ignored."""
    with store.engine.begin() as conn:
        for name in list(
            conn.exec_driver_sql("SELECT name FROM sqlite_master WHERE type = 'trigger'").scalars()
        ):
            conn.exec_driver_sql(f"DROP TRIGGER {name}")
        conn.exec_driver_sql("PRAGMA ignore_check_constraints = ON")
    try:
        with store.engine.begin() as conn:
            conn.execute(sa.text(sql), params)
    finally:
        with store.engine.begin() as conn:
            conn.exec_driver_sql("PRAGMA ignore_check_constraints = OFF")


_ISSUE = '{"file_path": "src/reco/broken.py", "kind": "syntax_error"}'


@pytest.mark.parametrize(
    ("issues", "cause_type", "rule"),
    [
        pytest.param(
            '[{"file_path": "src/reco/broken.py", "kind": "syntax_error", "line": 3}]',
            TypeError,
            None,
            id="extra-key",
        ),
        pytest.param('[{"file_path": "src/reco/broken.py"}]', TypeError, None, id="missing-key"),
        pytest.param(
            '[{"file_path": "src/reco/broken.py", "kind": "exploded"}]',
            ValueError,
            None,
            id="unknown-kind",
        ),
        pytest.param(
            '[{"file_path": "src/reco/broken.py", "kind": "SYNTAX_ERROR"}]',
            ValueError,
            None,
            id="kind-by-member-name",
        ),
        pytest.param(
            _ISSUE.replace("{", "[", 1).replace("}", "]"), ValueError, None, id="bad-json"
        ),
        pytest.param(f'{{"issues": [{_ISSUE}]}}', TypeError, None, id="object-not-list"),
        pytest.param("null", TypeError, None, id="null"),
        pytest.param('"[]"', TypeError, None, id="string-not-list"),
        pytest.param('["src/reco/broken.py"]', TypeError, None, id="item-not-object"),
        pytest.param(
            '[{"file_path": 7, "kind": "syntax_error"}]', TypeError, None, id="non-str-path"
        ),
        pytest.param(
            '[{"file_path": "src/reco/broken.py", "kind": ["binary"]}]',
            TypeError,
            None,
            id="non-str-kind",
        ),
        pytest.param(
            '[{"file_path": "src/reco/z.py", "kind": "binary"}, ' + _ISSUE + "]",
            ProvenanceInvariantError,
            "R.revision.file_issues",
            id="unsorted",
        ),
        pytest.param(
            f"[{_ISSUE}, {_ISSUE}]", ProvenanceInvariantError, "R.revision.file_issues", id="dup"
        ),
        pytest.param(
            '[{"file_path": "/etc/passwd", "kind": "binary"}]',
            ProvenanceInvariantError,
            None,
            id="absolute-path",
        ),
        pytest.param(
            '[{"file_path": "src/reco/a.py", "kind": "binary"}]',
            ProvenanceInvariantError,
            "G.symbol.issue_file",
            id="issue-on-a-file-with-symbols",
        ),
    ],
)
def test_tampered_file_issues_fail_the_load(
    memory_store: SqliteProvenanceStore,
    issues: str,
    cause_type: type[BaseException],
    rule: str | None,
) -> None:
    ids = _record_index_revisions(make_service(memory_store.repository))
    _tamper(
        memory_store,
        "UPDATE workspace_revisions SET file_issues = :issues WHERE id = :rid",
        issues=issues,
        rid=ids.indexed,
    )
    with pytest.raises(StoredGraphIntegrityError) as caught:
        memory_store.repository.load(ids.project)
    assert str(caught.value) == "stored provenance failed integrity validation"
    assert isinstance(caught.value.__cause__, cause_type)
    if rule is not None:
        assert isinstance(caught.value.__cause__, ProvenanceInvariantError)
        assert caught.value.__cause__.rule == rule


@pytest.mark.parametrize(
    ("sql", "cause_type", "rule"),
    [
        pytest.param(
            f"UPDATE workspace_revisions SET file_issues = '[{_ISSUE}]' WHERE id = :unindexed",
            ProvenanceInvariantError,
            "R.revision.unindexed",
            id="issues-on-an-unindexed-revision",
        ),
        pytest.param(
            f"UPDATE workspace_revisions SET source_digest = '{INDEX_DIGEST}' "
            "WHERE id = :unindexed",
            ProvenanceInvariantError,
            "R.revision.unindexed",
            id="digest-on-an-unindexed-revision",
        ),
        pytest.param(
            "UPDATE workspace_revisions SET source_digest = 'not-a-digest' WHERE id = :indexed",
            ProvenanceInvariantError,
            None,
            id="malformed-digest",
        ),
        pytest.param(
            "UPDATE code_symbols SET fingerprint_algorithm = 'python-ast/0' "
            "WHERE qualified_name = 'estimate'",
            LookupError,
            None,
            id="unknown-algorithm",
        ),
        pytest.param(
            "UPDATE code_symbols SET fingerprint_algorithm = 'python-ast/1' "
            "WHERE qualified_name = 'unhashed'",
            ProvenanceInvariantError,
            "R.symbol.fingerprint_algorithm",
            id="algorithm-without-fingerprint",
        ),
    ],
)
def test_tampered_symbol_index_columns_fail_the_load(
    memory_store: SqliteProvenanceStore,
    sql: str,
    cause_type: type[BaseException],
    rule: str | None,
) -> None:
    ids = _record_index_revisions(make_service(memory_store.repository))
    _tamper(memory_store, sql, indexed=ids.indexed, unindexed=ids.unindexed)
    with pytest.raises(StoredGraphIntegrityError) as caught:
        memory_store.repository.load(ids.project)
    assert isinstance(caught.value.__cause__, cause_type)
    if rule is not None:
        assert isinstance(caught.value.__cause__, ProvenanceInvariantError)
        assert caught.value.__cause__.rule == rule


# ---------------------------------------------------------------------- engine and types


@pytest.mark.parametrize("on_file", [False, True])
def test_foreign_keys_are_enforced(tmp_path: Path, on_file: bool) -> None:
    url = _file_url(tmp_path / "fk.db") if on_file else MEMORY_URL
    store = open_sqlite_store(url)
    try:
        with store.engine.connect() as conn:
            assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
            if on_file:
                assert conn.exec_driver_sql("PRAGMA journal_mode").scalar_one() == "wal"
                assert conn.exec_driver_sql("PRAGMA busy_timeout").scalar_one() == 5000
    finally:
        store.dispose()


def test_utc_datetime_round_trips_microseconds_and_normalizes_to_utc() -> None:
    engine = create_engine_for(MEMORY_URL)
    metadata = sa.MetaData()
    table = sa.Table(
        "instants",
        metadata,
        sa.Column("n", sa.Integer, primary_key=True),
        sa.Column("at", UtcDateTime),
    )
    metadata.create_all(engine)
    plus_two = timezone(timedelta(hours=2))
    values = [
        datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC),
        datetime(2026, 1, 2, 3, 4, 5, 1, tzinfo=plus_two),
        datetime(1999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC),
    ]
    with engine.begin() as conn:
        conn.execute(table.insert(), [{"n": n, "at": value} for n, value in enumerate(values)])
        stored = conn.execute(sa.select(table.c.at).order_by(table.c.n)).scalars().all()
        conn.execute(table.insert(), [{"n": 99, "at": None}])
        assert conn.execute(sa.select(table.c.at).where(table.c.n == 99)).scalar_one() is None
    assert stored == values
    assert all(item.tzinfo is UTC for item in stored)
    assert stored[1].hour == 1 and stored[1].microsecond == 1
    engine.dispose()


def test_utc_datetime_rejects_naive_values() -> None:
    column_type = UtcDateTime()
    dialect = sqlite_dialect.dialect()
    with pytest.raises(ValueError, match="naive"):
        column_type.process_bind_param(datetime(2026, 1, 1, 12, 0), dialect)
    engine = create_engine_for(MEMORY_URL)
    run_migrations(engine)
    with pytest.raises(sa.exc.StatementError), engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO projects (id, title, is_synthetic, created_at) VALUES (:i, 't', 0, :c)"
            ).bindparams(sa.bindparam("c", type_=UtcDateTime())),
            {"i": "prj_" + "0" * 32, "c": datetime(2026, 1, 1, 12, 0)},
        )
    engine.dispose()


def test_utc_datetime_keeps_tzinfo_for_dialects_that_store_it() -> None:
    column_type = UtcDateTime()
    dialect = postgresql.dialect()
    plus_two = timezone(timedelta(hours=2))
    bound = column_type.process_bind_param(datetime(2026, 1, 1, 12, 0, tzinfo=plus_two), dialect)
    assert bound == datetime(2026, 1, 1, 10, 0, tzinfo=UTC) and bound.tzinfo is UTC
    loaded = column_type.process_result_value(datetime(2026, 1, 1, 12, 0, tzinfo=plus_two), dialect)
    assert loaded is not None and loaded.tzinfo is UTC and loaded.hour == 10


# ---------------------------------------------------------------------- append bookkeeping


@dataclass
class RecordingRepository:
    """Delegates to a repository and remembers the revision each append produced."""

    inner: SqlAlchemyProvenanceRepository
    appended: list[tuple[int, tuple[ProvenanceRecord, ...]]] = field(default_factory=list)

    def create_project(self, project: Project) -> None:
        self.inner.create_project(project)

    def list_projects(self) -> list[ProjectSummary]:
        return self.inner.list_projects()

    def load(self, project_id: ProjectId) -> ProvenanceGraph:
        return self.inner.load(project_id)

    def append(
        self, project_id: ProjectId, expected_revision: int, records: Sequence[ProvenanceRecord]
    ) -> int:
        revision = self.inner.append(project_id, expected_revision, records)
        self.appended.append((revision, tuple(records)))
        return revision


TABLES = (
    "sources",
    "source_versions",
    "supersession_notices",
    "claims",
    "claim_checks",
    "decisions",
    "evidence_links",
    "workspace_revisions",
    "code_symbols",
    "implementation_links",
    "test_cases",
    "verification_links",
    "environment_snapshots",
    "validation_runs",
    "approvals",
)


def test_added_in_revision_is_the_revision_written_by_the_append(
    memory_store: SqliteProvenanceStore,
) -> None:
    recording = RecordingRepository(memory_store.repository)
    ids = build_complete_real_project(make_service(recording))

    expected: dict[str, int] = {}
    previous = 0
    for revision, records in recording.appended:
        assert revision == previous + 1
        previous = revision
        for record in records:
            expected[record.id] = revision
    with memory_store.engine.connect() as conn:
        stored: dict[str, int] = {}
        for table in TABLES:
            stored.update(
                conn.exec_driver_sql(f"SELECT id, added_in_revision FROM {table}").tuples().all()
            )
        result_revisions = conn.exec_driver_sql(
            "SELECT run_id, added_in_revision FROM validation_results"
        ).all()
        project_revision = conn.exec_driver_sql("SELECT revision FROM projects").scalar_one()
    assert stored == expected
    assert result_revisions and all(expected[run] == rev for run, rev in result_revisions)
    runs = [r for _, batch in recording.appended for r in batch if isinstance(r, ValidationRun)]
    assert len(result_revisions) == sum(len(run.results) for run in runs)
    assert (
        project_revision
        == max(expected.values())
        == memory_store.repository.load(ids.project).revision
    )


# ---------------------------------------------------------------------- compare-and-set


def test_second_writer_on_a_stale_revision_is_refused(tmp_path: Path) -> None:
    url = _file_url(tmp_path / "cas.db")
    first, second = open_sqlite_store(url), open_sqlite_store(url)
    try:
        project = _project()
        first.repository.create_project(project)
        first.repository.append(project.id, 0, [_source(project, 1)])
        base = first.repository.load(project.id)
        assert second.repository.load(project.id) == base

        assert first.repository.append(project.id, base.revision, [_source(project, 2)]) == 2
        before = _count(first, "sources")
        with pytest.raises(ConcurrentModificationError):
            second.repository.append(project.id, base.revision, [_source(project, 3)])

        assert _count(first, "sources") == before == 2
        reloaded = second.repository.load(project.id)
        assert reloaded.revision == 2
        assert {source.id for source in reloaded.sources} == {
            _source(project, 1).id,
            _source(project, 2).id,
        }
    finally:
        first.dispose()
        second.dispose()


def test_write_lock_held_elsewhere_is_reported_as_concurrent_modification(
    tmp_path: Path,
) -> None:
    path = tmp_path / "locked.db"
    engine = create_engine_for(_file_url(path))
    sa.event.listen(
        engine, "connect", lambda dbapi, _record: dbapi.execute("PRAGMA busy_timeout=50")
    )
    run_migrations(engine)
    repository = SqlAlchemyProvenanceRepository(sessionmaker(engine, expire_on_commit=False))
    project = _project()
    repository.create_project(project)
    blocker = sqlite3.connect(path, isolation_level=None)
    try:
        blocker.execute("BEGIN IMMEDIATE")
        with pytest.raises(ConcurrentModificationError):
            repository.append(project.id, 0, [_source(project, 1)])
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    assert repository.append(project.id, 0, [_source(project, 1)]) == 1
    engine.dispose()


def test_other_operational_errors_are_not_masked(memory_store: SqliteProvenanceStore) -> None:
    project = _project()
    memory_store.repository.create_project(project)
    with memory_store.engine.begin() as conn:
        conn.exec_driver_sql("DROP TABLE sources")
    with pytest.raises(sa.exc.OperationalError):
        memory_store.repository.append(project.id, 0, [_source(project, 1)])


def test_constraint_violation_rolls_back_the_whole_append(
    memory_store: SqliteProvenanceStore,
) -> None:
    project = _project()
    repository = memory_store.repository
    repository.create_project(project)
    orphan_version = SourceVersion(
        id=SourceVersionId(f"ver_{1:032x}"),
        project_id=project.id,
        source_id=SourceId(f"src_{999:032x}"),
        version_label="v1",
        authority=SourceAuthority.WORKING_MATERIAL,
        access_class=AccessClass.PUBLIC,
        access_conditions=None,
        authority_basis=None,
        content_sha256=None,
        retrieved_at=None,
        published_on=None,
        recorded_at=NOW,
    )
    with pytest.raises(StoredGraphIntegrityError) as caught:
        repository.append(project.id, 0, [_source(project, 1), orphan_version])
    assert isinstance(caught.value.__cause__, sa.exc.IntegrityError)
    assert repository.load(project.id).revision == 0
    assert _count(memory_store, "sources") == 0


# ---------------------------------------------------------------------- concurrency


def test_concurrent_loads_on_the_shared_in_memory_store_return_the_stored_graph(
    memory_store: SqliteProvenanceStore,
) -> None:
    repository = memory_store.repository
    ids = build_complete_real_project(make_service(repository))
    reference = repository.load(ids.project)
    start = threading.Barrier(16)

    def load_many(_: int) -> list[ProvenanceGraph | str]:
        start.wait()
        outcomes: list[ProvenanceGraph | str] = []
        for _ in range(25):
            try:
                graph = repository.load(ids.project)
                listed = [item.project.id for item in repository.list_projects()]
                outcomes.append(graph if listed == [ids.project] else "wrong project list")
            except Exception as error:  # every error is a failure; report its type
                outcomes.append(type(error).__name__)
        return outcomes

    with ThreadPoolExecutor(max_workers=16) as pool:
        outcomes = [item for batch in pool.map(load_many, range(16)) for item in batch]
    assert len(outcomes) == 16 * 25
    assert [item for item in outcomes if item != reference] == []


def test_concurrent_first_start_on_a_fresh_file_migrates_once(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    processes_per_trial = 4
    outcomes: list[str] = []
    for trial in range(3):
        url = _file_url(tmp_path / f"fresh-{trial}.db")
        barrier = context.Barrier(processes_per_trial)
        results = context.Queue()
        workers = [
            context.Process(target=open_store_at_barrier, args=(url, barrier, results))
            for _ in range(processes_per_trial)
        ]
        for worker in workers:
            worker.start()
        outcomes.extend(results.get(timeout=60) for _ in workers)
        for worker in workers:
            worker.join(timeout=60)
        store = open_sqlite_store(url)
        try:
            with store.engine.connect() as conn:
                heads = conn.exec_driver_sql("SELECT version_num FROM alembic_version").all()
        finally:
            store.dispose()
        assert len(heads) == 1
    assert outcomes == ["ok"] * (3 * processes_per_trial)


# ---------------------------------------------------------------------- projects


def test_duplicate_project_is_refused(memory_store: SqliteProvenanceStore) -> None:
    memory_store.repository.create_project(_project())
    with pytest.raises(DuplicateProjectError):
        memory_store.repository.create_project(_project())
    assert _count(memory_store, "projects") == 1


def test_unknown_project_is_not_found(memory_store: SqliteProvenanceStore) -> None:
    unknown = _project(7)
    with pytest.raises(ProjectNotFoundError):
        memory_store.repository.append(unknown.id, 0, [_source(unknown, 1)])
    with pytest.raises(ProjectNotFoundError):
        memory_store.repository.load(unknown.id)
    assert _count(memory_store, "sources") == 0


def test_projects_are_listed_by_creation_time_then_id(
    memory_store: SqliteProvenanceStore,
) -> None:
    later = _project(1, created_at=NOW + timedelta(microseconds=1))
    earlier_b = _project(3)
    earlier_a = _project(2)
    for project in (later, earlier_b, earlier_a):
        memory_store.repository.create_project(project)
    memory_store.repository.append(earlier_a.id, 0, [_source(earlier_a, 1)])

    listed = memory_store.repository.list_projects()

    assert [item.project for item in listed] == [earlier_a, earlier_b, later]
    assert [item.revision for item in listed] == [1, 0, 0]
    assert listed[0].project.created_at.tzinfo is UTC


def test_store_that_cannot_be_migrated_is_not_returned(tmp_path: Path) -> None:
    missing_directory = tmp_path / "missing" / "asca.db"
    with pytest.raises(sa.exc.OperationalError):
        open_sqlite_store(_file_url(missing_directory))
    assert not missing_directory.parent.exists()


def test_only_provenance_records_map_to_rows() -> None:
    with pytest.raises(TypeError):
        record_to_rows(_project(), 1)  # type: ignore[arg-type]
