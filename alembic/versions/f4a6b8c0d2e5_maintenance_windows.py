"""maintenance windows (mute notifications, pause scheduled tasks)

Ported from debcontrol (its maintenance_windows tables), scoped to one
company per window like a scheduled task. Adds the windows, their honeypot
list, and NotificationLog.muted_by. Every new column is nullable or has a
server default, so existing rows need nothing.

Revision ID: f4a6b8c0d2e5
Revises: e3f5a7b9c1d4
Create Date: 2026-10-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f4a6b8c0d2e5"
down_revision: str | None = "e3f5a7b9c1d4"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "maintenance_windows",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_company_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("all_honeypots", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("pause_scheduled_tasks", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("mute_alerts", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["owner_company_id"], ["companies.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_maintenance_windows_ends_at", "maintenance_windows", ["ends_at"])
    op.create_index(
        "ix_maintenance_windows_owner_company_id", "maintenance_windows", ["owner_company_id"]
    )
    op.create_table(
        "maintenance_window_honeypots",
        sa.Column("window_id", sa.Uuid(), nullable=False),
        sa.Column("honeypot_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["window_id"], ["maintenance_windows.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["honeypot_id"], ["honeypots.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("window_id", "honeypot_id"),
    )
    op.add_column("notification_logs", sa.Column("muted_by", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("notification_logs", "muted_by")
    op.drop_table("maintenance_window_honeypots")
    op.drop_index("ix_maintenance_windows_owner_company_id", table_name="maintenance_windows")
    op.drop_index("ix_maintenance_windows_ends_at", table_name="maintenance_windows")
    op.drop_table("maintenance_windows")
