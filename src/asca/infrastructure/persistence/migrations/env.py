"""Alembic environment for the provenance store.

The application passes an open connection in ``config.attributes["connection"]``.
Without one (developer use through ``alembic.ini``), an engine is built from
``sqlalchemy.url`` with the same validation and pragmas as the application.
"""

from alembic import context
from sqlalchemy.engine import Connection

from asca.infrastructure.persistence.database import create_engine_for, validate_database_url
from asca.infrastructure.persistence.orm import Base

config = context.config
target_metadata = Base.metadata


def _run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if isinstance(connection, Connection):
        _run(connection)
        return
    url = validate_database_url(config.get_main_option("sqlalchemy.url") or "")
    engine = create_engine_for(url)
    try:
        with engine.begin() as owned:
            _run(owned)
    finally:
        engine.dispose()


run_migrations_online()
