"""honeypot update run package snapshot + rollback linkage

Revision ID: c8d9e0f1a2b3
Revises: b7c8d9e0f1a2
Create Date: 2026-09-10

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c8d9e0f1a2b3"
down_revision: str | None = "b7c8d9e0f1a2"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "honeypot_update_runs", sa.Column("package_snapshot", sa.Text(), nullable=True)
    )
    op.add_column(
        "honeypot_update_runs", sa.Column("rollback_of_run_id", sa.Uuid(), nullable=True)
    )
    op.create_index(
        op.f("ix_honeypot_update_runs_rollback_of_run_id"),
        "honeypot_update_runs",
        ["rollback_of_run_id"],
    )
    op.create_foreign_key(
        op.f("fk_honeypot_update_runs_rollback_of_run_id_honeypot_update_runs"),
        "honeypot_update_runs",
        "honeypot_update_runs",
        ["rollback_of_run_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("fk_honeypot_update_runs_rollback_of_run_id_honeypot_update_runs"),
        "honeypot_update_runs",
        type_="foreignkey",
    )
    op.drop_index(
        op.f("ix_honeypot_update_runs_rollback_of_run_id"), table_name="honeypot_update_runs"
    )
    op.drop_column("honeypot_update_runs", "rollback_of_run_id")
    op.drop_column("honeypot_update_runs", "package_snapshot")
