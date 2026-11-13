"""Alembic migrations of the provenance store: schema parity, reversibility and policy."""

from __future__ import annotations

import ast
import re
import shutil
from collections.abc import Iterator
from importlib import resources
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.engine import Engine

from asca.infrastructure.persistence import create_engine_for, run_migrations
from asca.infrastructure.persistence.database import MIGRATIONS_LOCATION
from asca.infrastructure.persistence.orm import Base

pytestmark = pytest.mark.contract

MEMORY_URL = "sqlite+pysqlite:///:memory:"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


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


def test_upgraded_schema_matches_the_orm_metadata(engine: Engine) -> None:
    run_migrations(engine)
    with engine.connect() as conn:
        diff = compare_metadata(
            MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata
        )
    assert diff == []
    assert _tables(engine) == {*Base.metadata.tables, "alembic_version"}
    assert len(Base.metadata.tables) == 17


def test_upgrade_is_idempotent(engine: Engine) -> None:
    run_migrations(engine)
    run_migrations(engine)
    with engine.connect() as conn:
        assert MigrationContext.configure(conn).get_current_revision() == "0001"


def test_downgrade_to_base_leaves_only_the_version_table_and_upgrade_works_again(
    engine: Engine,
) -> None:
    run_migrations(engine)
    assert len(_triggers(engine)) == 2 * 16 + 2

    _run(engine, "downgrade", "base")
    assert _tables(engine) == {"alembic_version"}
    assert _triggers(engine) == set()

    _run(engine, "upgrade", "head")
    assert _tables(engine) == {*Base.metadata.tables, "alembic_version"}
    assert len(_triggers(engine)) == 2 * 16 + 2


def test_there_is_exactly_one_head_and_revision_ids_are_four_digits() -> None:
    scripts = ScriptDirectory.from_config(_config())
    assert scripts.get_heads() == ["0001"]
    revisions = list(scripts.walk_revisions())
    assert revisions
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


def test_env_builds_its_own_engine_from_the_configured_url(tmp_path: Path) -> None:
    database = tmp_path / "developer.db"
    config = _config()
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{database}")
    command.upgrade(config, "head")

    engine = create_engine_for(f"sqlite+pysqlite:///{database}")
    try:
        assert "approvals" in _tables(engine)
        with engine.connect() as conn:
            assert MigrationContext.configure(conn).get_current_revision() == "0001"
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
    command.revision(config, message="next step", rev_id="0002")

    generated = next((location / "versions").glob("0002_*.py"))
    tree = ast.parse(generated.read_text(encoding="utf-8"))
    assignments = {
        node.target.id: node.value
        for node in tree.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }
    assert ast.literal_eval(assignments["revision"]) == "0002"
    assert ast.literal_eval(assignments["down_revision"]) == "0001"
    functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    assert {"upgrade", "downgrade"} <= functions


def test_developer_alembic_ini_points_at_the_packaged_migrations() -> None:
    config = Config(str(REPOSITORY_ROOT / "alembic.ini"))
    assert config.get_main_option("script_location") == (
        "src/asca/infrastructure/persistence/migrations"
    )
    assert config.get_main_option("sqlalchemy.url") == "sqlite+pysqlite:///./.asca/asca.db"
