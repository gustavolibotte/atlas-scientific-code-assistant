"""Provenance core: projects and the 16 append-only record tables.

Revision ID: 0001
Revises:
Create Date: 2026-11-12

Handwritten and immutable after merge. Enum values are spelled out here on purpose so
that later changes to the domain enums need a new migration.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.schema import SchemaItem

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ACCESS = ("public", "internal", "restricted")
ORIGIN = ("human", "automated")

# Record tables in foreign-key dependency order (parents first).
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


def _id() -> sa.String:
    return sa.String(36)


def _sha() -> sa.String:
    return sa.String(64)


def _time() -> sa.DateTime:
    return sa.DateTime(timezone=True)


def _enum(table: str, column: str, values: Sequence[str]) -> tuple[sa.Column[str], sa.Constraint]:
    allowed = ", ".join(f"'{value}'" for value in values)
    return (
        sa.Column(column, sa.String(32), nullable=False),
        sa.CheckConstraint(f"{column} IN ({allowed})", name=op.f(f"ck_{table}_{column}")),
    )


def _fk(table: str, column: str, target: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        [column], [f"{target}.id"], name=op.f(f"fk_{table}_{column}_{target}")
    )


def _uq(table: str, *columns: str) -> sa.UniqueConstraint:
    return sa.UniqueConstraint(*columns, name=op.f(f"uq_{table}_{'_'.join(columns)}"))


def _ck(table: str, name: str, condition: str) -> sa.CheckConstraint:
    return sa.CheckConstraint(condition, name=op.f(f"ck_{table}_{name}"))


def _record_table(table: str, *items: SchemaItem, has_id: bool = True) -> None:
    """Create a record table with the shared project scope and revision columns."""
    common: list[SchemaItem] = [
        sa.Column("project_id", _id(), nullable=False),
        sa.Column("added_in_revision", sa.Integer(), nullable=False),
        _ck(table, "added_rev", "added_in_revision >= 1"),
        _fk(table, "project_id", "projects"),
    ]
    head: list[SchemaItem] = []
    if has_id:
        head.append(sa.Column("id", _id(), nullable=False))
        common.append(sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{table}")))
    op.create_table(table, *head, *items, *common)
    op.create_index(op.f(f"ix_{table}_project_id"), table, ["project_id"])


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", _id(), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("is_synthetic", sa.Boolean(), nullable=False),
        sa.Column("created_at", _time(), nullable=False),
        sa.Column("revision", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.CheckConstraint("revision >= 0", name=op.f("ck_projects_revision")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_projects")),
    )

    t = "sources"
    _record_table(
        t,
        sa.Column("title", sa.String(300), nullable=False),
        *_enum(
            t,
            "pid_scheme",
            (
                "doi",
                "arxiv",
                "inspire",
                "cds_report",
                "cds_record",
                "git_repository",
                "url",
                "local_document",
                "synthetic",
            ),
        ),
        sa.Column("pid_value", sa.String(2000), nullable=False),
        sa.Column("created_at", _time(), nullable=False),
        _uq(t, "project_id", "pid_scheme", "pid_value"),
    )

    t = "source_versions"
    _record_table(
        t,
        sa.Column("source_id", _id(), nullable=False),
        sa.Column("version_label", sa.String(100), nullable=False),
        *_enum(
            t,
            "authority",
            (
                "published",
                "approved_internal",
                "verified_implementation",
                "working_material",
                "automated_inference",
            ),
        ),
        *_enum(t, "access_class", ACCESS),
        sa.Column("access_conditions", sa.Text(), nullable=True),
        sa.Column("authority_basis", sa.Text(), nullable=True),
        sa.Column("content_sha256", _sha(), nullable=True),
        sa.Column("retrieved_at", _time(), nullable=True),
        sa.Column("published_on", sa.Date(), nullable=True),
        sa.Column("recorded_at", _time(), nullable=False),
        _fk(t, "source_id", "sources"),
        _uq(t, "source_id", "version_label"),
        _ck(t, "retrieval_pair", "(content_sha256 IS NULL) = (retrieved_at IS NULL)"),
        _ck(t, "published_public", "authority <> 'published' OR access_class = 'public'"),
    )

    t = "supersession_notices"
    _record_table(
        t,
        sa.Column("superseded_version_id", _id(), nullable=False),
        sa.Column("superseding_version_id", _id(), nullable=True),
        *_enum(t, "dimension", ("scientific", "technical")),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("recorded_at", _time(), nullable=False),
        _fk(t, "superseded_version_id", "source_versions"),
        _fk(t, "superseding_version_id", "source_versions"),
        _uq(t, "superseded_version_id", "dimension"),
        _ck(
            t,
            "distinct",
            "superseding_version_id IS NULL OR superseding_version_id <> superseded_version_id",
        ),
    )

    t = "claims"
    _record_table(
        t,
        sa.Column("source_version_id", _id(), nullable=False),
        sa.Column("quote", sa.Text(), nullable=False),
        sa.Column("locator", sa.JSON(), nullable=False),
        sa.Column("statement", sa.Text(), nullable=True),
        *_enum(t, "extracted_by", ORIGIN),
        sa.Column("recorded_at", _time(), nullable=False),
        _fk(t, "source_version_id", "source_versions"),
    )
    op.create_index(op.f("ix_claims_source_version_id"), t, ["source_version_id"])

    t = "claim_checks"
    _record_table(
        t,
        sa.Column("claim_id", _id(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        *_enum(t, "outcome", ("source_text_checked", "mismatch", "unavailable")),
        *_enum(t, "method", ("normalized_substring", "not_performed")),
        sa.Column("content_sha256", _sha(), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("checked_at", _time(), nullable=False),
        _fk(t, "claim_id", "claims"),
        _uq(t, "claim_id", "sequence"),
        _ck(t, "sequence", "sequence >= 1"),
    )

    t = "decisions"
    _record_table(
        t,
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("alternatives", sa.JSON(), nullable=False),
        sa.Column("assumptions", sa.JSON(), nullable=False),
        *_enum(t, "access_floor", ACCESS),
        sa.Column("supersedes_id", _id(), nullable=True),
        sa.Column("created_at", _time(), nullable=False),
        _fk(t, "supersedes_id", "decisions"),
        _uq(t, "supersedes_id"),
        _ck(t, "not_self", "supersedes_id IS NULL OR supersedes_id <> id"),
    )

    t = "evidence_links"
    _record_table(
        t,
        sa.Column("decision_id", _id(), nullable=False),
        sa.Column("claim_id", _id(), nullable=False),
        *_enum(t, "stance", ("supports", "contradicts", "context")),
        *_enum(t, "asserted_by", ORIGIN),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_at", _time(), nullable=False),
        _fk(t, "decision_id", "decisions"),
        _fk(t, "claim_id", "claims"),
        _uq(t, "decision_id", "claim_id"),
    )
    op.create_index(op.f("ix_evidence_links_claim_id"), t, ["claim_id"])

    t = "workspace_revisions"
    _record_table(
        t,
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("vcs_ref", sa.String(100), nullable=True),
        sa.Column("symbols_indexed", sa.Boolean(), nullable=False),
        sa.Column("recorded_at", _time(), nullable=False),
        _uq(t, "project_id", "sequence"),
        _ck(t, "sequence", "sequence >= 1"),
    )

    t = "code_symbols"
    _record_table(
        t,
        sa.Column("revision_id", _id(), nullable=False),
        *_enum(t, "language", ("python",)),
        *_enum(t, "kind", ("function", "method", "class", "module")),
        sa.Column("qualified_name", sa.String(300), nullable=False),
        sa.Column("file_path", sa.String(500), nullable=False),
        sa.Column("span_start", sa.Integer(), nullable=True),
        sa.Column("span_end", sa.Integer(), nullable=True),
        sa.Column("fingerprint", _sha(), nullable=True),
        _fk(t, "revision_id", "workspace_revisions"),
        _uq(t, "revision_id", "file_path", "qualified_name"),
        _ck(
            t,
            "span",
            "(span_start IS NULL AND span_end IS NULL) OR "
            "(span_start >= 1 AND span_end >= span_start)",
        ),
    )
    op.create_index(
        op.f("ix_code_symbols_project_id_language_file_path_qualified_name"),
        t,
        ["project_id", "language", "file_path", "qualified_name"],
    )

    t = "implementation_links"
    _record_table(
        t,
        sa.Column("decision_id", _id(), nullable=False),
        sa.Column("symbol_id", _id(), nullable=False),
        sa.Column("created_at", _time(), nullable=False),
        _fk(t, "decision_id", "decisions"),
        _fk(t, "symbol_id", "code_symbols"),
        _uq(t, "decision_id", "symbol_id"),
    )
    op.create_index(op.f("ix_implementation_links_symbol_id"), t, ["symbol_id"])

    t = "test_cases"
    _record_table(
        t,
        sa.Column("node_id", sa.String(500), nullable=False),
        *_enum(
            t,
            "kind",
            ("analytic", "numerical", "property", "regression", "unit", "integration"),
        ),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", _time(), nullable=False),
        _uq(t, "project_id", "node_id"),
    )

    t = "verification_links"
    _record_table(
        t,
        sa.Column("test_case_id", _id(), nullable=False),
        sa.Column("decision_id", _id(), nullable=True),
        sa.Column("symbol_id", _id(), nullable=True),
        sa.Column("created_at", _time(), nullable=False),
        _fk(t, "test_case_id", "test_cases"),
        _fk(t, "decision_id", "decisions"),
        _fk(t, "symbol_id", "code_symbols"),
        _uq(t, "test_case_id", "decision_id"),
        _uq(t, "test_case_id", "symbol_id"),
        _ck(
            t,
            "one_target",
            "(decision_id IS NOT NULL AND symbol_id IS NULL) OR "
            "(decision_id IS NULL AND symbol_id IS NOT NULL)",
        ),
    )

    t = "environment_snapshots"
    _record_table(
        t,
        sa.Column("python_version", sa.String(50), nullable=False),
        sa.Column("implementation", sa.String(50), nullable=False),
        sa.Column("platform", sa.String(200), nullable=False),
        sa.Column("packages", sa.JSON(), nullable=False),
    )

    t = "validation_runs"
    _record_table(
        t,
        sa.Column("revision_id", _id(), nullable=False),
        sa.Column("environment_id", _id(), nullable=False),
        *_enum(t, "origin", ("executed", "imported", "synthetic")),
        sa.Column("started_at", _time(), nullable=False),
        sa.Column("finished_at", _time(), nullable=False),
        _fk(t, "revision_id", "workspace_revisions"),
        _fk(t, "environment_id", "environment_snapshots"),
        _ck(t, "time_order", "finished_at >= started_at"),
    )

    t = "validation_results"
    _record_table(
        t,
        sa.Column("run_id", _id(), nullable=False),
        sa.Column("test_case_id", _id(), nullable=False),
        *_enum(
            t,
            "outcome",
            ("passed", "failed", "error", "skipped", "xfailed", "xpassed"),
        ),
        sa.Column("duration_seconds", sa.Float(), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        _fk(t, "run_id", "validation_runs"),
        _fk(t, "test_case_id", "test_cases"),
        sa.PrimaryKeyConstraint("run_id", "test_case_id", name=op.f(f"pk_{t}")),
        _ck(t, "duration", "duration_seconds >= 0"),
        has_id=False,
    )
    op.create_index(op.f("ix_validation_results_test_case_id"), t, ["test_case_id"])

    t = "approvals"
    _record_table(
        t,
        sa.Column("decision_id", _id(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        *_enum(t, "verdict", ("approved", "rejected")),
        sa.Column("reviewer", sa.String(200), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("conflict_resolution", sa.Text(), nullable=True),
        sa.Column("support_fingerprint", _sha(), nullable=False),
        sa.Column("reviewed_at", _time(), nullable=False),
        _fk(t, "decision_id", "decisions"),
        _uq(t, "decision_id", "sequence"),
        _ck(t, "sequence", "sequence >= 1"),
        _ck(t, "resolution", "verdict = 'approved' OR conflict_resolution IS NULL"),
    )

    if op.get_bind().dialect.name == "sqlite":
        _create_sqlite_triggers()


def _create_sqlite_triggers() -> None:
    abort = "BEGIN SELECT RAISE(ABORT, 'append-only'); END"
    for table in RECORD_TABLES:
        op.execute(f"CREATE TRIGGER trg_{table}_no_update BEFORE UPDATE ON {table} {abort}")
        op.execute(f"CREATE TRIGGER trg_{table}_no_delete BEFORE DELETE ON {table} {abort}")
    op.execute(
        "CREATE TRIGGER trg_projects_immutable_columns "
        f"BEFORE UPDATE OF id, title, is_synthetic, created_at ON projects {abort}"
    )
    op.execute(f"CREATE TRIGGER trg_projects_no_delete BEFORE DELETE ON projects {abort}")


def downgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        for table in RECORD_TABLES:
            op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_no_update")
            op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_no_delete")
        op.execute("DROP TRIGGER IF EXISTS trg_projects_immutable_columns")
        op.execute("DROP TRIGGER IF EXISTS trg_projects_no_delete")
    for table in reversed(RECORD_TABLES):
        op.drop_table(table)
    op.drop_table("projects")
