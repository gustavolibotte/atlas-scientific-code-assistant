"""SQLite engine construction and schema migration for the provenance store."""

import re
import sqlite3
import time
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.pool import ConnectionPoolEntry, StaticPool

MIGRATIONS_LOCATION = "asca.infrastructure.persistence:migrations"
MEMORY_URL = "sqlite+pysqlite:///:memory:"
_BEGIN_IMMEDIATE = "asca_begin_immediate"
_WAL_RETRY_SECONDS = 5.0
_URL_RE = re.compile(r"sqlite\+pysqlite:///(:memory:|[^?#\x00]+)")


def validate_database_url(url: str) -> str:
    """Return ``url`` when it is a supported SQLite URL; the error never echoes it."""
    if not isinstance(url, str) or _URL_RE.fullmatch(url) is None:
        raise ValueError("Only sqlite+pysqlite URLs are supported in M1")
    return url


def create_engine_for(url: str) -> Engine:
    """Build an engine with foreign keys on and, for files, WAL and a busy timeout.

    File databases also hand transaction control to SQLAlchemy (an explicit ``BEGIN``
    per transaction) so that a load reads one consistent snapshot. The in-memory
    database is a single shared connection and keeps the driver default.
    """
    url = validate_database_url(url)
    in_memory = url == MEMORY_URL
    if in_memory:
        engine = create_engine(url, poolclass=StaticPool, connect_args={"check_same_thread": False})
    else:
        engine = create_engine(url, connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_connection: Any, _record: ConnectionPoolEntry) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
            if not in_memory:
                cursor.execute("PRAGMA busy_timeout=5000")
                _enable_wal(cursor)
        finally:
            cursor.close()
        if not in_memory:
            dbapi_connection.isolation_level = None

    if not in_memory:

        @event.listens_for(engine, "begin")
        def _on_begin(connection: Connection) -> None:
            immediate = connection.get_execution_options().get(_BEGIN_IMMEDIATE, False)
            connection.exec_driver_sql("BEGIN IMMEDIATE" if immediate else "BEGIN")

    return engine


def _enable_wal(cursor: Any) -> None:
    """Switch a file database to WAL, retrying while another connection switches it.

    The switch reads the header and then needs an exclusive lock; SQLite reports a
    competing switch as "database is locked" at once instead of using the busy handler.
    Once one connection has switched, WAL is persistent and the pragma takes no lock.
    """
    deadline = time.monotonic() + _WAL_RETRY_SECONDS
    while True:
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            return
        except sqlite3.OperationalError as error:
            if "locked" not in str(error).lower() or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def run_migrations(engine: Engine) -> None:
    """Upgrade the database to the single head revision.

    On a file database the migration transaction takes the write lock up front
    (``BEGIN IMMEDIATE``). A deferred transaction would first read the schema and then
    fail to upgrade that read snapshot to a write once another process has migrated,
    which SQLite reports as "database is locked" without waiting for the busy timeout.
    With the lock taken first, a concurrent starter waits and then finds the head.
    """
    cfg = Config()
    cfg.set_main_option("script_location", MIGRATIONS_LOCATION)
    with engine.connect() as conn:
        conn.execution_options(**{_BEGIN_IMMEDIATE: True})
        with conn.begin():
            cfg.attributes["connection"] = conn
            command.upgrade(cfg, "head")
