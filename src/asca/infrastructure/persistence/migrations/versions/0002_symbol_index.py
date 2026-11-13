"""Symbol index: fingerprint algorithm, revision source digest and file issues.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-13

Handwritten and immutable after merge. Purely additive: three ``ADD COLUMN``s, no new
table and no new trigger. The allowed algorithm ids are spelled out here on purpose,
so a later algorithm needs a new migration (an SQLite table rebuild that recreates the
append-only triggers). ``DROP COLUMN`` in the downgrade needs SQLite 3.35 or later.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE code_symbols ADD COLUMN fingerprint_algorithm VARCHAR(32) "
        "CONSTRAINT ck_code_symbols_fingerprint_algorithm "
        "CHECK (fingerprint_algorithm IN ('python-ast/1')) "
        "CONSTRAINT ck_code_symbols_fingerprint_algorithm_pair "
        "CHECK (fingerprint_algorithm IS NULL OR fingerprint IS NOT NULL)"
    )
    op.execute(
        "ALTER TABLE workspace_revisions ADD COLUMN source_digest VARCHAR(64) "
        "CONSTRAINT ck_workspace_revisions_source_digest "
        "CHECK (source_digest IS NULL OR symbols_indexed = 1)"
    )
    op.execute("ALTER TABLE workspace_revisions ADD COLUMN file_issues JSON DEFAULT '[]' NOT NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE workspace_revisions DROP COLUMN file_issues")
    op.execute("ALTER TABLE workspace_revisions DROP COLUMN source_digest")
    op.execute("ALTER TABLE code_symbols DROP COLUMN fingerprint_algorithm")
