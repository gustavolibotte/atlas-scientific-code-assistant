"""SQLAlchemy implementation of the append-only provenance repository port."""

from collections.abc import Sequence
from typing import Any, TypeVar, cast

import sqlalchemy as sa
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session, class_mapper, sessionmaker

from asca.application.errors import (
    ConcurrentModificationError,
    DuplicateProjectError,
    ProjectNotFoundError,
    StoredGraphIntegrityError,
)
from asca.application.ports import ProjectSummary
from asca.domain.provenance import (
    Project,
    ProjectId,
    ProvenanceGraph,
    ProvenanceInvariantError,
    ProvenanceRecord,
)
from asca.infrastructure.persistence.mapping import (
    APPEND_ORDER,
    ROW_FIELDS,
    LoadedRows,
    project_to_row,
    record_to_rows,
    row_to_project,
    rows_to_graph,
)
from asca.infrastructure.persistence.orm import RECORD_ROW_TYPES, Base, ProjectRow, RecordColumns

#: Errors that mean stored rows fail domain validation (``LookupError`` also covers
#: unknown stored enum values, which SQLAlchemy reports as ``LookupError``).
_INTEGRITY_ERRORS = (ProvenanceInvariantError, ValueError, LookupError, TypeError)
_APPEND_RANK = {kind: rank for rank, kind in enumerate(APPEND_ORDER)}

RowT = TypeVar("RowT", bound=RecordColumns)


def _project_rows(session: Session, row_type: type[RowT], project_id: str) -> tuple[RowT, ...]:
    order = class_mapper(row_type).primary_key
    statement = sa.select(row_type).where(row_type.project_id == project_id).order_by(*order)
    return tuple(session.scalars(statement).all())


def _is_lock_error(error: OperationalError) -> bool:
    message = str(error.orig).lower()
    return "locked" in message or "busy" in message


class SqlAlchemyProvenanceRepository:
    """Append-only store; ``append`` is a compare-and-set on ``projects.revision``."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def create_project(self, project: Project) -> None:
        try:
            with self._session_factory() as session, session.begin():
                session.add(project_to_row(project))
        except IntegrityError as error:
            raise DuplicateProjectError("project already exists") from error

    def list_projects(self) -> list[ProjectSummary]:
        statement = sa.select(ProjectRow).order_by(ProjectRow.created_at, ProjectRow.id)
        with self._session_factory() as session, session.begin():
            try:
                return [
                    ProjectSummary(project=row_to_project(row), revision=row.revision)
                    for row in session.scalars(statement)
                ]
            except _INTEGRITY_ERRORS as error:
                raise StoredGraphIntegrityError() from error

    def load(self, project_id: ProjectId) -> ProvenanceGraph:
        with self._session_factory() as session, session.begin():
            try:
                project_row = session.get(ProjectRow, project_id)
                if project_row is not None:
                    fields: dict[str, Any] = {
                        name: _project_rows(
                            session, cast(type[RecordColumns], row_type), project_id
                        )
                        for row_type, name in ROW_FIELDS.items()
                    }
                    return rows_to_graph(project_row, LoadedRows(**fields))
            except _INTEGRITY_ERRORS as error:
                raise StoredGraphIntegrityError() from error
        raise ProjectNotFoundError("project not found")

    def append(
        self,
        project_id: ProjectId,
        expected_revision: int,
        records: Sequence[ProvenanceRecord],
    ) -> int:
        new_revision = expected_revision + 1
        ordered = sorted(records, key=lambda record: _APPEND_RANK[type(record)])
        rows_by_type: dict[type[Base], list[Base]] = {row_type: [] for row_type in RECORD_ROW_TYPES}
        for record in ordered:
            for row in record_to_rows(record, new_revision):
                rows_by_type[type(row)].append(row)
        bump = (
            sa.update(ProjectRow)
            .where(ProjectRow.id == project_id, ProjectRow.revision == expected_revision)
            .values(revision=new_revision)
        )
        try:
            with self._session_factory() as session, session.begin():
                result = cast(CursorResult[Any], session.execute(bump))
                if result.rowcount != 1:
                    if session.get(ProjectRow, project_id) is None:
                        raise ProjectNotFoundError("project not found")
                    raise ConcurrentModificationError("project revision changed")
                # Rows are flushed table by table in dependency order: there are no ORM
                # relationships to let the unit of work order inserts across tables.
                for row_type in RECORD_ROW_TYPES:
                    if rows_by_type[row_type]:
                        session.add_all(rows_by_type[row_type])
                        session.flush()
        except IntegrityError as error:
            raise StoredGraphIntegrityError() from error
        except OperationalError as error:
            if _is_lock_error(error):
                raise ConcurrentModificationError("project revision changed") from error
            raise
        return new_revision
