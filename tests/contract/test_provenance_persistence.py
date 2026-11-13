"""SQLite provenance store: reload equality, compare-and-set and repository errors."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Sequence
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

from asca.application.errors import (
    ConcurrentModificationError,
    DuplicateProjectError,
    ProjectNotFoundError,
    StoredGraphIntegrityError,
)
from asca.application.ports import ProjectSummary
from asca.domain.provenance import (
    AccessClass,
    PersistentIdentifier,
    PidScheme,
    Project,
    ProjectId,
    ProvenanceGraph,
    ProvenanceRecord,
    Source,
    SourceAuthority,
    SourceId,
    SourceVersion,
    SourceVersionId,
    ValidationRun,
)
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
