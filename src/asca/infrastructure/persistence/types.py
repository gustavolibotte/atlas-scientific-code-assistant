"""Column types shared by the ORM rows and the migrations."""

from datetime import UTC, datetime
from enum import StrEnum

import sqlalchemy as sa
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator

ID = sa.String(36)
SHA = sa.String(64)


class UtcDateTime(TypeDecorator[datetime]):
    """Aware UTC datetimes only; SQLite stores them naive and they come back as UTC."""

    impl = sa.DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("naive datetimes cannot be stored")
        value = value.astimezone(UTC)
        if dialect.name == "sqlite":
            value = value.replace(tzinfo=None)
        return value

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


def enum_column(enum_cls: type[StrEnum], name: str) -> sa.Enum:
    """A non-native enum stored as its values, with a CHECK constraint named after the column."""
    return sa.Enum(
        enum_cls,
        native_enum=False,
        create_constraint=True,
        length=32,
        validate_strings=True,
        values_callable=lambda members: [member.value for member in members],
        name=name,
    )
