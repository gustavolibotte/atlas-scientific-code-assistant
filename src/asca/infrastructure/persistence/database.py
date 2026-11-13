"""SQLite engine construction and schema migration for the provenance store."""

import re
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.pool import ConnectionPoolEntry, StaticPool

MIGRATIONS_LOCATION = "asca.infrastructure.persistence:migrations"
MEMORY_URL = "sqlite+pysqlite:///:memory:"
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
                cursor.execute("PRAGMA journal_mode=WAL")
        finally:
            cursor.close()
        if not in_memory:
            dbapi_connection.isolation_level = None

    if not in_memory:

        @event.listens_for(engine, "begin")
        def _on_begin(connection: Connection) -> None:
            connection.exec_driver_sql("BEGIN")

    return engine


def run_migrations(engine: Engine) -> None:
    """Upgrade the database to the single head revision."""
    cfg = Config()
    cfg.set_main_option("script_location", MIGRATIONS_LOCATION)
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")
