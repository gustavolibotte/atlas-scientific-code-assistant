"""Append-only enforcement, tamper detection and URL validation of the SQLite store."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
import sqlalchemy as sa
from provenance_builders import CompleteProject, build_complete_real_project, make_service

from asca.application.demo import DEMO_DECISION_ID, DEMO_PROJECT_ID, seed_synthetic_demo
from asca.application.errors import StoredGraphIntegrityError
from asca.domain.provenance import ProvenanceInvariantError
from asca.infrastructure.persistence import (
    SqliteProvenanceStore,
    create_engine_for,
    open_sqlite_store,
    validate_database_url,
)

pytestmark = pytest.mark.security

MEMORY_URL = "sqlite+pysqlite:///:memory:"
RECORD_TABLES = (
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
    "validation_results",
    "approvals",
)
TAMPERED_SHA = "f" * 64


@pytest.fixture(scope="module")
def populated() -> Iterator[tuple[SqliteProvenanceStore, CompleteProject]]:
    store = open_sqlite_store(MEMORY_URL)
    ids = build_complete_real_project(make_service(store.repository))
    yield store, ids
    store.dispose()


@pytest.fixture
def fresh() -> Iterator[tuple[SqliteProvenanceStore, CompleteProject]]:
    store = open_sqlite_store(MEMORY_URL)
    ids = build_complete_real_project(make_service(store.repository))
    yield store, ids
    store.dispose()


def _execute(store: SqliteProvenanceStore, sql: str, **params: object) -> None:
    with store.engine.begin() as conn:
        conn.execute(sa.text(sql), params)


def _count(store: SqliteProvenanceStore, table: str) -> int:
    with store.engine.connect() as conn:
        return int(conn.exec_driver_sql(f"SELECT COUNT(*) FROM {table}").scalar_one())


def _drop_triggers(store: SqliteProvenanceStore) -> None:
    with store.engine.begin() as conn:
        names = conn.exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type = 'trigger'"
        ).scalars()
        for name in list(names):
            conn.exec_driver_sql(f"DROP TRIGGER {name}")


def _integrity_cause(store: SqliteProvenanceStore, ids: CompleteProject) -> BaseException:
    with pytest.raises(StoredGraphIntegrityError) as caught:
        store.repository.load(ids.project)
    assert str(caught.value) == "stored provenance failed integrity validation"
    assert caught.value.__cause__ is not None
    return caught.value.__cause__


# ---------------------------------------------------------------------- append-only triggers


@pytest.mark.parametrize("table", RECORD_TABLES)
def test_record_rows_cannot_be_updated(
    populated: tuple[SqliteProvenanceStore, CompleteProject], table: str
) -> None:
    store, _ = populated
    before = _count(store, table)
    assert before > 0
    with pytest.raises(sa.exc.DBAPIError, match="append-only"):
        _execute(store, f"UPDATE {table} SET added_in_revision = added_in_revision + 1")
    with store.engine.connect() as conn:
        columns = [row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")]
    assert "project_id" in columns and len(columns) > 2
    # Every column is protected, not only the one probed above: a trigger narrowed to
    # ``UPDATE OF <column>`` would let content columns (quote, verdict, hashes) change.
    for column in columns:
        with pytest.raises(sa.exc.DBAPIError, match="append-only"):
            _execute(store, f"UPDATE {table} SET {column} = {column}")
    with store.engine.connect() as conn:
        triggers = conn.exec_driver_sql(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = :table",
            {"table": table},
        ).scalars()
        update_triggers = [sql for sql in triggers if " UPDATE" in sql.upper()]
    assert update_triggers
    assert not any("UPDATE OF" in sql.upper() for sql in update_triggers)
    assert _count(store, table) == before


@pytest.mark.parametrize("table", RECORD_TABLES)
def test_record_rows_cannot_be_deleted(
    populated: tuple[SqliteProvenanceStore, CompleteProject], table: str
) -> None:
    store, _ = populated
    before = _count(store, table)
    with pytest.raises(sa.exc.DBAPIError, match="append-only"):
        _execute(store, f"DELETE FROM {table}")
    assert _count(store, table) == before


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("title", "Renamed"),
        ("is_synthetic", 1),
        ("created_at", "2000-01-01 00:00:00.000000"),
        ("id", "prj_" + "0" * 32),
    ],
)
def test_project_identity_columns_are_immutable(
    populated: tuple[SqliteProvenanceStore, CompleteProject], column: str, value: object
) -> None:
    store, ids = populated
    with pytest.raises(sa.exc.DBAPIError, match="append-only"):
        _execute(
            store,
            f"UPDATE projects SET {column} = :value WHERE id = :pid",
            value=value,
            pid=ids.project,
        )


def test_project_revision_may_advance_but_projects_cannot_be_deleted(
    fresh: tuple[SqliteProvenanceStore, CompleteProject],
) -> None:
    store, ids = fresh
    revision = store.repository.load(ids.project).revision
    _execute(store, "UPDATE projects SET revision = revision + 1 WHERE id = :pid", pid=ids.project)
    assert store.repository.load(ids.project).revision == revision + 1
    with pytest.raises(sa.exc.DBAPIError, match="append-only"):
        _execute(store, "DELETE FROM projects")
    assert _count(store, "projects") == 1


# ---------------------------------------------------------------------- symbol index columns

FINGERPRINT = "c" * 64


def _insert_symbol(
    store: SqliteProvenanceStore,
    ids: CompleteProject,
    *,
    name: str,
    fingerprint: str | None,
    algorithm: str | None,
) -> None:
    _execute(
        store,
        "INSERT INTO code_symbols (id, project_id, added_in_revision, revision_id, language, "
        "kind, qualified_name, file_path, span_start, span_end, fingerprint, "
        "fingerprint_algorithm) VALUES (:id, :pid, 1, :rev, 'python', 'function', :name, "
        "'src/reco/injected.py', NULL, NULL, :fp, :algorithm)",
        id="sym_" + name.encode().hex().ljust(32, "0"),
        pid=ids.project,
        rev=ids.revision1,
        name=name,
        fp=fingerprint,
        algorithm=algorithm,
    )


def _insert_revision(
    store: SqliteProvenanceStore, ids: CompleteProject, *, indexed: bool, digest: str | None
) -> None:
    _execute(
        store,
        "INSERT INTO workspace_revisions (id, project_id, added_in_revision, sequence, vcs_ref, "
        "symbols_indexed, recorded_at, source_digest) VALUES (:id, :pid, 1, 99, NULL, "
        ":indexed, '2026-11-12 00:00:00.000000', :digest)",
        id="rev_" + "e" * 32,
        pid=ids.project,
        indexed=indexed,
        digest=digest,
    )


@pytest.mark.parametrize(
    ("fingerprint", "algorithm", "constraint"),
    [
        pytest.param(None, "python-ast/1", "fingerprint_algorithm_pair", id="no-fingerprint"),
        pytest.param(FINGERPRINT, "python-ast/0", "fingerprint_algorithm", id="unknown-id"),
        pytest.param(FINGERPRINT, "PYTHON_AST_1", "fingerprint_algorithm", id="member-name"),
        pytest.param(FINGERPRINT, "", "fingerprint_algorithm", id="empty"),
    ],
)
def test_check_constraints_reject_bad_fingerprint_algorithms(
    fresh: tuple[SqliteProvenanceStore, CompleteProject],
    fingerprint: str | None,
    algorithm: str,
    constraint: str,
) -> None:
    store, ids = fresh
    before = _count(store, "code_symbols")
    with pytest.raises(
        sa.exc.IntegrityError, match=rf"CHECK constraint failed: ck_code_symbols_{constraint}\b"
    ):
        _insert_symbol(store, ids, name="injected", fingerprint=fingerprint, algorithm=algorithm)
    assert _count(store, "code_symbols") == before
    _insert_symbol(store, ids, name="accepted", fingerprint=FINGERPRINT, algorithm="python-ast/1")
    _insert_symbol(store, ids, name="legacy", fingerprint=FINGERPRINT, algorithm=None)
    assert _count(store, "code_symbols") == before + 2


def test_check_constraint_rejects_a_source_digest_on_an_unindexed_revision(
    fresh: tuple[SqliteProvenanceStore, CompleteProject],
) -> None:
    store, ids = fresh
    before = _count(store, "workspace_revisions")
    with pytest.raises(
        sa.exc.IntegrityError,
        match=r"CHECK constraint failed: ck_workspace_revisions_source_digest",
    ):
        _insert_revision(store, ids, indexed=False, digest=FINGERPRINT)
    assert _count(store, "workspace_revisions") == before
    _insert_revision(store, ids, indexed=True, digest=FINGERPRINT)
    assert _count(store, "workspace_revisions") == before + 1


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE workspace_revisions SET file_issues = '[]'",
        'UPDATE workspace_revisions SET file_issues = \'[{"file_path": "src/x.py", '
        '"kind": "binary"}]\' WHERE symbols_indexed = 1',
        "UPDATE workspace_revisions SET source_digest = NULL",
        "UPDATE code_symbols SET fingerprint_algorithm = NULL",
        "UPDATE code_symbols SET fingerprint_algorithm = 'python-ast/1' "
        "WHERE fingerprint IS NOT NULL",
    ],
)
def test_symbol_index_columns_are_append_only(
    populated: tuple[SqliteProvenanceStore, CompleteProject], sql: str
) -> None:
    store, ids = populated
    reference = store.repository.load(ids.project)
    with pytest.raises(sa.exc.DBAPIError, match="append-only"):
        _execute(store, sql)
    assert store.repository.load(ids.project) == reference


# ---------------------------------------------------------------------- tamper detection


def test_tampered_check_hash_fails_the_load(
    fresh: tuple[SqliteProvenanceStore, CompleteProject],
) -> None:
    store, ids = fresh
    _drop_triggers(store)
    _execute(
        store,
        "UPDATE claim_checks SET content_sha256 = :sha WHERE claim_id = :claim",
        sha=TAMPERED_SHA,
        claim=ids.journal_claim,
    )
    cause = _integrity_cause(store, ids)
    assert isinstance(cause, ProvenanceInvariantError) and cause.rule == "G.check.hash"


def test_approval_smuggled_into_a_synthetic_project_fails_the_load() -> None:
    store = open_sqlite_store(MEMORY_URL)
    try:
        seed_synthetic_demo(store.repository)
        _drop_triggers(store)
        _execute(
            store,
            "INSERT INTO approvals (id, decision_id, sequence, verdict, reviewer, rationale, "
            "conflict_resolution, support_fingerprint, reviewed_at, project_id, "
            "added_in_revision) VALUES (:id, :decision, 1, 'approved', 'Fixture reviewer', "
            "'Fixture rationale.', NULL, :sha, '2026-11-12 00:00:00.000000', :pid, 1)",
            id="apr_" + "a" * 32,
            decision=DEMO_DECISION_ID,
            sha=TAMPERED_SHA,
            pid=DEMO_PROJECT_ID,
        )
        with pytest.raises(StoredGraphIntegrityError) as caught:
            store.repository.load(DEMO_PROJECT_ID)
        cause = caught.value.__cause__
        assert isinstance(cause, ProvenanceInvariantError)
        assert cause.rule == "G.synthetic.approvals"
    finally:
        store.dispose()


def test_altered_environment_packages_fail_the_load(
    fresh: tuple[SqliteProvenanceStore, CompleteProject],
) -> None:
    store, ids = fresh
    _drop_triggers(store)
    _execute(
        store,
        "UPDATE environment_snapshots SET packages = :packages",
        packages='[{"name": "numpy", "version": "9.9.9"}]',
    )
    cause = _integrity_cause(store, ids)
    assert isinstance(cause, ProvenanceInvariantError)
    assert cause.rule == "R.environment.content_address"


@pytest.mark.parametrize(
    ("sql", "cause_type"),
    [
        ("UPDATE claims SET locator = '{}'", TypeError),
        ('UPDATE claims SET locator = \'[{"kind": "page"}]\'', KeyError),
        ('UPDATE claims SET locator = \'[{"kind": "chapter", "value": "1"}]\'', ValueError),
        ("UPDATE decisions SET alternatives = 'null'", TypeError),
        ("UPDATE decisions SET assumptions = '{}'", TypeError),
        ("UPDATE environment_snapshots SET packages = '\"numpy\"'", TypeError),
        ("UPDATE evidence_links SET stance = 'endorses'", LookupError),
        ("UPDATE code_symbols SET span_start = NULL, span_end = 3", ProvenanceInvariantError),
        ("UPDATE claim_checks SET checked_at = 'not a time'", ValueError),
        (
            "UPDATE validation_results SET run_id = 'run_" + "0" * 32 + "' "
            "WHERE rowid = (SELECT MIN(rowid) FROM validation_results)",
            KeyError,
        ),
    ],
)
def test_malformed_rows_fail_the_load_generically(
    fresh: tuple[SqliteProvenanceStore, CompleteProject],
    sql: str,
    cause_type: type[BaseException],
) -> None:
    store, ids = fresh
    _drop_triggers(store)
    with store.engine.begin() as conn:
        conn.exec_driver_sql("PRAGMA ignore_check_constraints = ON")
        conn.exec_driver_sql("PRAGMA foreign_keys = OFF")
    try:
        _execute(store, sql)
    finally:
        with store.engine.begin() as conn:
            conn.exec_driver_sql("PRAGMA ignore_check_constraints = OFF")
    cause = _integrity_cause(store, ids)
    assert isinstance(cause, cause_type)


def test_corrupt_project_row_fails_the_listing(
    fresh: tuple[SqliteProvenanceStore, CompleteProject],
) -> None:
    store, ids = fresh
    _drop_triggers(store)
    _execute(store, "UPDATE projects SET title = '   ' WHERE id = :pid", pid=ids.project)
    with pytest.raises(StoredGraphIntegrityError) as caught:
        store.repository.list_projects()
    assert isinstance(caught.value.__cause__, ProvenanceInvariantError)
    _integrity_cause(store, ids)


# ---------------------------------------------------------------------- URL validation


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://asca:hunter2@db.example.org/asca",
        "sqlite:///x",
        "sqlite+pysqlite:///x?mode=ro",
        "sqlite+pysqlite:///x#fragment",
        "sqlite+pysqlite:///x\x00.db",
        "sqlite+pysqlite:///",
        "sqlite+pysqlite://user@host/x",
        "",
    ],
)
def test_unsupported_urls_are_refused_without_echoing_them(url: str) -> None:
    for factory in (validate_database_url, create_engine_for, open_sqlite_store):
        with pytest.raises(ValueError) as caught:
            factory(url)
        message = str(caught.value)
        assert message == "Only sqlite+pysqlite URLs are supported in M1"
        assert url == "" or url not in message
        assert "hunter2" not in message


@pytest.mark.parametrize(
    "url",
    [
        "sqlite+pysqlite:///:memory:",
        "sqlite+pysqlite:///relative/asca.db",
        "sqlite+pysqlite:////abs/asca.db",
    ],
)
def test_supported_urls_are_accepted(url: str) -> None:
    assert validate_database_url(url) == url
