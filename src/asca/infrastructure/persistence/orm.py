"""SQLAlchemy rows for the provenance store: one table per record kind, no relationships.

Every record table carries ``project_id`` and ``added_in_revision``. Project scope is
enforced by the domain on every load; foreign keys are single-column (ADR 0038).
"""

from datetime import date, datetime
from typing import Any, ClassVar

import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.schema import SchemaItem

from asca.domain.provenance import (
    AccessClass,
    ApprovalVerdict,
    AssertionOrigin,
    CheckMethod,
    ClaimCheckOutcome,
    Language,
    PidScheme,
    RunOrigin,
    SourceAuthority,
    Stance,
    SupersessionDimension,
    SymbolKind,
    TestKind,
    TestOutcome,
)
from asca.infrastructure.persistence.types import ID, SHA, UtcDateTime, enum_column

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

JsonList = list[dict[str, Any]]


class Base(DeclarativeBase):
    metadata = sa.MetaData(naming_convention=NAMING_CONVENTION)


def _record_args(*items: SchemaItem) -> tuple[SchemaItem, ...]:
    """Table arguments of a record table: the shared revision check plus ``items``."""
    return (sa.CheckConstraint("added_in_revision >= 1", name="added_rev"), *items)


def _fk(target: str) -> sa.ForeignKey:
    return sa.ForeignKey(target)


class RecordColumns:
    """Columns shared by every record table."""

    project_id: Mapped[str] = mapped_column(ID, _fk("projects.id"), index=True)
    added_in_revision: Mapped[int] = mapped_column(sa.Integer)


class ProjectRow(Base):
    __tablename__ = "projects"
    __table_args__ = (sa.CheckConstraint("revision >= 0", name="revision"),)

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    title: Mapped[str] = mapped_column(sa.String(300))
    is_synthetic: Mapped[bool] = mapped_column(sa.Boolean)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)
    revision: Mapped[int] = mapped_column(sa.Integer, default=0, server_default=sa.text("0"))


class SourceRow(RecordColumns, Base):
    __tablename__ = "sources"
    __table_args__ = _record_args(sa.UniqueConstraint("project_id", "pid_scheme", "pid_value"))

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    title: Mapped[str] = mapped_column(sa.String(300))
    pid_scheme: Mapped[PidScheme] = mapped_column(enum_column(PidScheme, "pid_scheme"))
    pid_value: Mapped[str] = mapped_column(sa.String(2000))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)


class SourceVersionRow(RecordColumns, Base):
    __tablename__ = "source_versions"
    __table_args__ = _record_args(
        sa.UniqueConstraint("source_id", "version_label"),
        sa.CheckConstraint(
            "(content_sha256 IS NULL) = (retrieved_at IS NULL)", name="retrieval_pair"
        ),
        sa.CheckConstraint(
            "authority <> 'published' OR access_class = 'public'", name="published_public"
        ),
    )

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    source_id: Mapped[str] = mapped_column(ID, _fk("sources.id"))
    version_label: Mapped[str] = mapped_column(sa.String(100))
    authority: Mapped[SourceAuthority] = mapped_column(enum_column(SourceAuthority, "authority"))
    access_class: Mapped[AccessClass] = mapped_column(enum_column(AccessClass, "access_class"))
    access_conditions: Mapped[str | None] = mapped_column(sa.Text)
    authority_basis: Mapped[str | None] = mapped_column(sa.Text)
    content_sha256: Mapped[str | None] = mapped_column(SHA)
    retrieved_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    published_on: Mapped[date | None] = mapped_column(sa.Date)
    recorded_at: Mapped[datetime] = mapped_column(UtcDateTime)


class SupersessionNoticeRow(RecordColumns, Base):
    __tablename__ = "supersession_notices"
    __table_args__ = _record_args(
        sa.UniqueConstraint("superseded_version_id", "dimension"),
        sa.CheckConstraint(
            "superseding_version_id IS NULL OR superseding_version_id <> superseded_version_id",
            name="distinct",
        ),
    )

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    superseded_version_id: Mapped[str] = mapped_column(ID, _fk("source_versions.id"))
    superseding_version_id: Mapped[str | None] = mapped_column(ID, _fk("source_versions.id"))
    dimension: Mapped[SupersessionDimension] = mapped_column(
        enum_column(SupersessionDimension, "dimension")
    )
    reason: Mapped[str] = mapped_column(sa.Text)
    recorded_at: Mapped[datetime] = mapped_column(UtcDateTime)


class ClaimRow(RecordColumns, Base):
    __tablename__ = "claims"
    __table_args__ = _record_args()

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    source_version_id: Mapped[str] = mapped_column(ID, _fk("source_versions.id"), index=True)
    quote: Mapped[str] = mapped_column(sa.Text)
    locator: Mapped[JsonList] = mapped_column(sa.JSON)
    statement: Mapped[str | None] = mapped_column(sa.Text)
    extracted_by: Mapped[AssertionOrigin] = mapped_column(
        enum_column(AssertionOrigin, "extracted_by")
    )
    recorded_at: Mapped[datetime] = mapped_column(UtcDateTime)


class ClaimCheckRow(RecordColumns, Base):
    __tablename__ = "claim_checks"
    __table_args__ = _record_args(
        sa.UniqueConstraint("claim_id", "sequence"),
        sa.CheckConstraint("sequence >= 1", name="sequence"),
    )

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    claim_id: Mapped[str] = mapped_column(ID, _fk("claims.id"))
    sequence: Mapped[int] = mapped_column(sa.Integer)
    outcome: Mapped[ClaimCheckOutcome] = mapped_column(enum_column(ClaimCheckOutcome, "outcome"))
    method: Mapped[CheckMethod] = mapped_column(enum_column(CheckMethod, "method"))
    content_sha256: Mapped[str | None] = mapped_column(SHA)
    detail: Mapped[str | None] = mapped_column(sa.Text)
    checked_at: Mapped[datetime] = mapped_column(UtcDateTime)


class DecisionRow(RecordColumns, Base):
    __tablename__ = "decisions"
    __table_args__ = _record_args(
        sa.CheckConstraint("supersedes_id IS NULL OR supersedes_id <> id", name="not_self"),
    )

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    title: Mapped[str] = mapped_column(sa.String(300))
    statement: Mapped[str] = mapped_column(sa.Text)
    rationale: Mapped[str] = mapped_column(sa.Text)
    alternatives: Mapped[JsonList] = mapped_column(sa.JSON)
    assumptions: Mapped[JsonList] = mapped_column(sa.JSON)
    access_floor: Mapped[AccessClass] = mapped_column(enum_column(AccessClass, "access_floor"))
    supersedes_id: Mapped[str | None] = mapped_column(ID, _fk("decisions.id"), unique=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)


class EvidenceLinkRow(RecordColumns, Base):
    __tablename__ = "evidence_links"
    __table_args__ = _record_args(sa.UniqueConstraint("decision_id", "claim_id"))

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    decision_id: Mapped[str] = mapped_column(ID, _fk("decisions.id"))
    claim_id: Mapped[str] = mapped_column(ID, _fk("claims.id"), index=True)
    stance: Mapped[Stance] = mapped_column(enum_column(Stance, "stance"))
    asserted_by: Mapped[AssertionOrigin] = mapped_column(
        enum_column(AssertionOrigin, "asserted_by")
    )
    note: Mapped[str | None] = mapped_column(sa.Text)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)


class WorkspaceRevisionRow(RecordColumns, Base):
    __tablename__ = "workspace_revisions"
    __table_args__ = _record_args(
        sa.UniqueConstraint("project_id", "sequence"),
        sa.CheckConstraint("sequence >= 1", name="sequence"),
    )

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    sequence: Mapped[int] = mapped_column(sa.Integer)
    vcs_ref: Mapped[str | None] = mapped_column(sa.String(100))
    symbols_indexed: Mapped[bool] = mapped_column(sa.Boolean)
    recorded_at: Mapped[datetime] = mapped_column(UtcDateTime)


class CodeSymbolRow(RecordColumns, Base):
    __tablename__ = "code_symbols"
    __table_args__ = _record_args(
        sa.UniqueConstraint("revision_id", "file_path", "qualified_name"),
        sa.CheckConstraint(
            "(span_start IS NULL AND span_end IS NULL) OR "
            "(span_start >= 1 AND span_end >= span_start)",
            name="span",
        ),
        sa.Index(None, "project_id", "language", "file_path", "qualified_name"),
    )

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    revision_id: Mapped[str] = mapped_column(ID, _fk("workspace_revisions.id"))
    language: Mapped[Language] = mapped_column(enum_column(Language, "language"))
    kind: Mapped[SymbolKind] = mapped_column(enum_column(SymbolKind, "kind"))
    qualified_name: Mapped[str] = mapped_column(sa.String(300))
    file_path: Mapped[str] = mapped_column(sa.String(500))
    span_start: Mapped[int | None] = mapped_column(sa.Integer)
    span_end: Mapped[int | None] = mapped_column(sa.Integer)
    fingerprint: Mapped[str | None] = mapped_column(SHA)


class ImplementationLinkRow(RecordColumns, Base):
    __tablename__ = "implementation_links"
    __table_args__ = _record_args(sa.UniqueConstraint("decision_id", "symbol_id"))

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    decision_id: Mapped[str] = mapped_column(ID, _fk("decisions.id"))
    symbol_id: Mapped[str] = mapped_column(ID, _fk("code_symbols.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)


class TestCaseRow(RecordColumns, Base):
    __tablename__ = "test_cases"
    __table_args__ = _record_args(sa.UniqueConstraint("project_id", "node_id"))
    __test__: ClassVar[bool] = False

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    node_id: Mapped[str] = mapped_column(sa.String(500))
    kind: Mapped[TestKind] = mapped_column(enum_column(TestKind, "kind"))
    description: Mapped[str] = mapped_column(sa.Text)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)


class VerificationLinkRow(RecordColumns, Base):
    __tablename__ = "verification_links"
    __table_args__ = _record_args(
        sa.UniqueConstraint("test_case_id", "decision_id"),
        sa.UniqueConstraint("test_case_id", "symbol_id"),
        sa.CheckConstraint(
            "(decision_id IS NOT NULL AND symbol_id IS NULL) OR "
            "(decision_id IS NULL AND symbol_id IS NOT NULL)",
            name="one_target",
        ),
    )

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    test_case_id: Mapped[str] = mapped_column(ID, _fk("test_cases.id"))
    decision_id: Mapped[str | None] = mapped_column(ID, _fk("decisions.id"))
    symbol_id: Mapped[str | None] = mapped_column(ID, _fk("code_symbols.id"))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)


class EnvironmentSnapshotRow(RecordColumns, Base):
    __tablename__ = "environment_snapshots"
    __table_args__ = _record_args()

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    python_version: Mapped[str] = mapped_column(sa.String(50))
    implementation: Mapped[str] = mapped_column(sa.String(50))
    platform: Mapped[str] = mapped_column(sa.String(200))
    packages: Mapped[JsonList] = mapped_column(sa.JSON)


class ValidationRunRow(RecordColumns, Base):
    __tablename__ = "validation_runs"
    __table_args__ = _record_args(
        sa.CheckConstraint("finished_at >= started_at", name="time_order"),
    )

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    revision_id: Mapped[str] = mapped_column(ID, _fk("workspace_revisions.id"))
    environment_id: Mapped[str] = mapped_column(ID, _fk("environment_snapshots.id"))
    origin: Mapped[RunOrigin] = mapped_column(enum_column(RunOrigin, "origin"))
    started_at: Mapped[datetime] = mapped_column(UtcDateTime)
    finished_at: Mapped[datetime] = mapped_column(UtcDateTime)


class ValidationResultRow(RecordColumns, Base):
    __tablename__ = "validation_results"
    __table_args__ = _record_args(
        sa.CheckConstraint("duration_seconds >= 0", name="duration"),
    )

    run_id: Mapped[str] = mapped_column(ID, _fk("validation_runs.id"), primary_key=True)
    test_case_id: Mapped[str] = mapped_column(
        ID, _fk("test_cases.id"), primary_key=True, index=True
    )
    outcome: Mapped[TestOutcome] = mapped_column(enum_column(TestOutcome, "outcome"))
    duration_seconds: Mapped[float | None] = mapped_column(sa.Float)
    message: Mapped[str | None] = mapped_column(sa.Text)


class ApprovalRow(RecordColumns, Base):
    __tablename__ = "approvals"
    __table_args__ = _record_args(
        sa.UniqueConstraint("decision_id", "sequence"),
        sa.CheckConstraint("sequence >= 1", name="sequence"),
        sa.CheckConstraint(
            "verdict = 'approved' OR conflict_resolution IS NULL", name="resolution"
        ),
    )

    id: Mapped[str] = mapped_column(ID, primary_key=True)
    decision_id: Mapped[str] = mapped_column(ID, _fk("decisions.id"))
    sequence: Mapped[int] = mapped_column(sa.Integer)
    verdict: Mapped[ApprovalVerdict] = mapped_column(enum_column(ApprovalVerdict, "verdict"))
    reviewer: Mapped[str] = mapped_column(sa.String(200))
    rationale: Mapped[str] = mapped_column(sa.Text)
    conflict_resolution: Mapped[str | None] = mapped_column(sa.Text)
    support_fingerprint: Mapped[str] = mapped_column(SHA)
    reviewed_at: Mapped[datetime] = mapped_column(UtcDateTime)


#: Record tables in foreign-key dependency order (parents first).
RECORD_ROW_TYPES: tuple[type[Base], ...] = (
    SourceRow,
    SourceVersionRow,
    SupersessionNoticeRow,
    ClaimRow,
    ClaimCheckRow,
    DecisionRow,
    EvidenceLinkRow,
    WorkspaceRevisionRow,
    CodeSymbolRow,
    ImplementationLinkRow,
    TestCaseRow,
    VerificationLinkRow,
    EnvironmentSnapshotRow,
    ValidationRunRow,
    ValidationResultRow,
    ApprovalRow,
)
