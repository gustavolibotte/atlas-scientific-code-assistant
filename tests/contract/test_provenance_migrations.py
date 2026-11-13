"""Alembic migrations of the provenance store: schema parity, reversibility and policy."""

from __future__ import annotations

import ast
import re
import shutil
import threading
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from provenance_builders import build_complete_real_project, make_service
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from asca.application.ports import ProjectSummary
from asca.domain.provenance import Project, ProjectId, ProvenanceGraph, ProvenanceRecord
from asca.infrastructure.memory_provenance import InMemoryProvenanceRepository
from asca.infrastructure.persistence import (
    SqlAlchemyProvenanceRepository,
    create_engine_for,
    run_migrations,
)
from asca.infrastructure.persistence.database import MIGRATIONS_LOCATION
from asca.infrastructure.persistence.mapping import project_to_row, record_to_rows
from asca.infrastructure.persistence.orm import RECORD_ROW_TYPES, Base

pytestmark = pytest.mark.contract

MEMORY_URL = "sqlite+pysqlite:///:memory:"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
HEAD = "0002"
TABLE_COUNT = 17
TRIGGER_COUNT = 2 * 16 + 2
#: Columns added by 0002, per table.
M2_COLUMNS = {
    "code_symbols": {"fingerprint_algorithm"},
    "workspace_revisions": {"source_digest", "file_issues"},
}


@pytest.fixture
def engine() -> Iterator[Engine]:
    engine = create_engine_for(MEMORY_URL)
    yield engine
    engine.dispose()


def _config() -> Config:
    config = Config()
    config.set_main_option("script_location", MIGRATIONS_LOCATION)
    return config


def _run(engine: Engine, action: str, target: str) -> None:
    config = _config()
    with engine.begin() as conn:
        config.attributes["connection"] = conn
        getattr(command, action)(config, target)


def _tables(engine: Engine) -> set[str]:
    return set(sa.inspect(engine).get_table_names())


def _triggers(engine: Engine) -> set[str]:
    with engine.connect() as conn:
        rows = conn.exec_driver_sql("SELECT name FROM sqlite_master WHERE type = 'trigger'")
        return {row[0] for row in rows}


def _columns(engine: Engine, table: str) -> dict[str, tuple[str, int, str | None]]:
    """``name -> (declared type, notnull, default)`` from ``PRAGMA table_info``."""
    with engine.connect() as conn:
        rows = conn.exec_driver_sql(f"PRAGMA table_info({table})").all()
    return {row[1]: (row[2], row[3], row[4]) for row in rows}


def _current_revision(engine: Engine) -> str | None:
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


def _repository(engine: Engine) -> SqlAlchemyProvenanceRepository:
    return SqlAlchemyProvenanceRepository(
        sessionmaker(engine, expire_on_commit=False), lock=threading.RLock()
    )


@dataclass
class RecordingMemoryRepository:
    """An in-memory repository that remembers every appended batch and its revision."""

    inner: InMemoryProvenanceRepository = field(default_factory=InMemoryProvenanceRepository)
    projects: list[Project] = field(default_factory=list)
    appended: list[tuple[int, tuple[ProvenanceRecord, ...]]] = field(default_factory=list)

    def create_project(self, project: Project) -> None:
        self.inner.create_project(project)
        self.projects.append(project)

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


def _m1_values(row: Base) -> dict[str, Any]:
    """The values of the columns that exist at revision 0001."""
    table = row.__table__
    assert isinstance(table, sa.Table)
    skipped = M2_COLUMNS.get(table.name, set())
    return {
        column.key: getattr(row, column.key)
        for column in table.columns
        if column.key not in skipped
    }


def _insert_at_0001(engine: Engine, recording: RecordingMemoryRepository) -> None:
    """Write the recorded projects and batches with the 0001 columns only."""
    with engine.begin() as conn:
        for project in recording.projects:
            conn.execute(
                Base.metadata.tables["projects"].insert(), _m1_values(project_to_row(project))
            )
        for revision, records in recording.appended:
            rows = [row for record in records for row in record_to_rows(record, revision)]
            for row_type in RECORD_ROW_TYPES:
                batch = [_m1_values(row) for row in rows if type(row) is row_type]
                if batch:
                    conn.execute(row_type.__table__.insert(), batch)  # type: ignore[attr-defined]
            project_id = records[0].project_id
            conn.execute(
                sa.text("UPDATE projects SET revision = :revision WHERE id = :pid"),
                {"revision": revision, "pid": project_id},
            )


def test_upgraded_schema_matches_the_orm_metadata(engine: Engine) -> None:
    run_migrations(engine)
    with engine.connect() as conn:
        diff = compare_metadata(
            MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata
        )
    assert diff == []
    assert _tables(engine) == {*Base.metadata.tables, "alembic_version"}
    assert len(Base.metadata.tables) == TABLE_COUNT
    assert len(_triggers(engine)) == TRIGGER_COUNT


def test_upgrade_is_idempotent(engine: Engine) -> None:
    run_migrations(engine)
    run_migrations(engine)
    assert _current_revision(engine) == HEAD


def test_0002_adds_the_symbol_index_columns_and_nothing_else(engine: Engine) -> None:
    _run(engine, "upgrade", "0001")
    assert _current_revision(engine) == "0001"
    before = {table: _columns(engine, table) for table in M2_COLUMNS}
    tables, triggers = _tables(engine), _triggers(engine)
    for table, added in M2_COLUMNS.items():
        assert not added & set(before[table])

    _run(engine, "upgrade", "0002")
    assert _current_revision(engine) == "0002"
    assert _tables(engine) == tables and len(tables) == TABLE_COUNT + 1
    assert _triggers(engine) == triggers and len(triggers) == TRIGGER_COUNT
    for table, added in M2_COLUMNS.items():
        after = _columns(engine, table)
        assert set(after) == set(before[table]) | added
        assert {name: after[name] for name in before[table]} == before[table]
    symbols = _columns(engine, "code_symbols")
    revisions = _columns(engine, "workspace_revisions")
    assert symbols["fingerprint_algorithm"] == ("VARCHAR(32)", 0, None)
    assert revisions["source_digest"] == ("VARCHAR(64)", 0, None)
    assert revisions["file_issues"] == ("JSON", 1, "'[]'")
    with engine.connect() as conn:
        ddl = dict(
            conn.exec_driver_sql(
                "SELECT name, sql FROM sqlite_master WHERE type = 'table' "
                "AND name IN ('code_symbols', 'workspace_revisions')"
            )
            .tuples()
            .all()
        )
    assert "ck_code_symbols_fingerprint_algorithm CHECK" in ddl["code_symbols"]
    assert "ck_code_symbols_fingerprint_algorithm_pair CHECK" in ddl["code_symbols"]
    assert "ck_workspace_revisions_source_digest CHECK" in ddl["workspace_revisions"]


def test_0001_database_upgrades_and_loads_identically(engine: Engine) -> None:
    recording = RecordingMemoryRepository()
    ids = build_complete_real_project(make_service(recording))
    reference = recording.load(ids.project)
    _run(engine, "upgrade", "0001")
    _insert_at_0001(engine, recording)

    run_migrations(engine)

    assert _current_revision(engine) == HEAD
    stored = _repository(engine).load(ids.project)
    assert stored == reference
    assert stored.symbols and stored.revisions
    assert all(symbol.fingerprint_algorithm is None for symbol in stored.symbols)
    assert any(symbol.fingerprint is not None for symbol in stored.symbols)
    assert all(revision.file_issues == () for revision in stored.revisions)
    assert all(revision.source_digest is None for revision in stored.revisions)
    with engine.connect() as conn:
        issues = conn.exec_driver_sql("SELECT file_issues FROM workspace_revisions").scalars()
        assert set(issues) == {"[]"}


def test_downgrade_to_0001_and_back_keeps_the_m1_rows(engine: Engine) -> None:
    run_migrations(engine)
    repository = _repository(engine)
    ids = build_complete_real_project(make_service(repository))
    reference = repository.load(ids.project)
    counts = {table: _count(engine, table) for table in Base.metadata.tables}

    _run(engine, "downgrade", "0001")
    assert _current_revision(engine) == "0001"
    for table, added in M2_COLUMNS.items():
        assert not added & set(_columns(engine, table))
    assert {table: _count(engine, table) for table in Base.metadata.tables} == counts
    assert len(_triggers(engine)) == TRIGGER_COUNT

    _run(engine, "upgrade", "0002")
    assert {table: _count(engine, table) for table in Base.metadata.tables} == counts
    assert _repository(engine).load(ids.project) == reference


def _count(engine: Engine, table: str) -> int:
    with engine.connect() as conn:
        return int(conn.exec_driver_sql(f"SELECT COUNT(*) FROM {table}").scalar_one())


def test_downgrade_to_base_leaves_only_the_version_table_and_upgrade_works_again(
    engine: Engine,
) -> None:
    run_migrations(engine)
    assert len(_triggers(engine)) == TRIGGER_COUNT

    _run(engine, "downgrade", "base")
    assert _tables(engine) == {"alembic_version"}
    assert _triggers(engine) == set()

    _run(engine, "upgrade", "head")
    assert _tables(engine) == {*Base.metadata.tables, "alembic_version"}
    assert len(_triggers(engine)) == TRIGGER_COUNT


def test_there_is_exactly_one_head_and_revision_ids_are_four_digits() -> None:
    scripts = ScriptDirectory.from_config(_config())
    assert scripts.get_heads() == [HEAD]
    revisions = list(scripts.walk_revisions())
    assert [script.revision for script in revisions] == [HEAD, "0001"]
    assert [script.down_revision for script in revisions] == ["0001", None]
    for script in revisions:
        assert re.fullmatch(r"\d{4}", script.revision)
        assert script.down_revision is None or re.fullmatch(r"\d{4}", str(script.down_revision))
        assert callable(getattr(script.module, "upgrade", None))
        assert callable(getattr(script.module, "downgrade", None))


def test_migration_files_ship_as_package_resources() -> None:
    migrations = resources.files("asca.infrastructure.persistence") / "migrations"
    assert (migrations / "script.py.mako").is_file()
    assert (migrations / "env.py").is_file()
    versions = resources.files("asca.infrastructure.persistence.migrations.versions")
    assert (versions / "0001_provenance_core.py").is_file()
    assert (versions / "0002_symbol_index.py").is_file()


def test_0002_is_self_contained_and_spells_out_its_enum_values() -> None:
    versions = resources.files("asca.infrastructure.persistence.migrations.versions")
    source = (versions / "0002_symbol_index.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name if isinstance(node, ast.Import) else str(node.module)
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in node.names
    }
    # Nothing from 0001 or from the application: later enum changes need a new migration.
    assert imported == {"collections.abc", "alembic"}
    assert "IN ('python-ast/1')" in source


def test_env_builds_its_own_engine_from_the_configured_url(tmp_path: Path) -> None:
    database = tmp_path / "developer.db"
    config = _config()
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{database}")
    command.upgrade(config, "head")

    engine = create_engine_for(f"sqlite+pysqlite:///{database}")
    try:
        assert "approvals" in _tables(engine)
        with engine.connect() as conn:
            assert MigrationContext.configure(conn).get_current_revision() == HEAD
    finally:
        engine.dispose()


def test_env_refuses_unsupported_urls_without_echoing_them() -> None:
    config = _config()
    config.set_main_option("sqlalchemy.url", "postgresql://user:secret@db.example.org/asca")
    with pytest.raises(ValueError) as caught:
        command.upgrade(config, "head")
    assert "secret" not in str(caught.value)
    assert "db.example.org" not in str(caught.value)


def test_new_revisions_render_from_the_typed_template(tmp_path: Path) -> None:
    location = tmp_path / "migrations"
    package = resources.files("asca.infrastructure.persistence") / "migrations"
    with resources.as_file(package) as source:
        shutil.copytree(source, location, ignore=shutil.ignore_patterns("__pycache__"))
    config = Config()
    config.set_main_option("script_location", str(location))
    command.revision(config, message="next step", rev_id="0003")

    generated = next((location / "versions").glob("0003_*.py"))
    tree = ast.parse(generated.read_text(encoding="utf-8"))
    assignments = {
        node.target.id: node.value
        for node in tree.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }
    assert ast.literal_eval(assignments["revision"]) == "0003"
    assert ast.literal_eval(assignments["down_revision"]) == HEAD
    functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    assert {"upgrade", "downgrade"} <= functions


def test_developer_alembic_ini_points_at_the_packaged_migrations() -> None:
    config = Config(str(REPOSITORY_ROOT / "alembic.ini"))
    assert config.get_main_option("script_location") == (
        "src/asca/infrastructure/persistence/migrations"
    )
    assert config.get_main_option("sqlalchemy.url") == "sqlite+pysqlite:///./.asca/asca.db"
