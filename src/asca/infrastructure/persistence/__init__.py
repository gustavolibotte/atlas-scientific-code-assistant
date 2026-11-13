"""SQLite persistence of provenance graphs (SQLAlchemy 2 and Alembic)."""

from dataclasses import dataclass

from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from asca.infrastructure.persistence.database import (
    create_engine_for,
    run_migrations,
    validate_database_url,
)
from asca.infrastructure.persistence.repository import SqlAlchemyProvenanceRepository

__all__ = [
    "SqlAlchemyProvenanceRepository",
    "SqliteProvenanceStore",
    "create_engine_for",
    "open_sqlite_store",
    "run_migrations",
    "validate_database_url",
]


@dataclass(frozen=True, slots=True)
class SqliteProvenanceStore:
    repository: SqlAlchemyProvenanceRepository
    engine: Engine

    def dispose(self) -> None:
        self.engine.dispose()


def open_sqlite_store(database_url: str) -> SqliteProvenanceStore:
    """Validate the URL, build the engine, migrate to head and return the repository."""
    url = validate_database_url(database_url)
    engine = create_engine_for(url)
    try:
        run_migrations(engine)
    except BaseException:
        engine.dispose()
        raise
    repository = SqlAlchemyProvenanceRepository(sessionmaker(engine, expire_on_commit=False))
    return SqliteProvenanceStore(repository=repository, engine=engine)
