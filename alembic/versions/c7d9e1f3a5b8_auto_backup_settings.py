"""Automatic full backups: settings

Revision ID: c7d9e1f3a5b8
Revises: b6c8d0e2f4a7
Create Date: 2026-10-04

Six `app_settings` columns for scheduled full backups
(`app.services.auto_backup`). Off by default: an existing instance changes
nothing until a superadmin sets a passphrase and enables it.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c7d9e1f3a5b8"
down_revision: str | None = "b6c8d0e2f4a7"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column("auto_backup_enabled", sa.Boolean(), server_default="false", nullable=False),
    )
    op.add_column(
        "app_settings",
        sa.Column("auto_backup_interval_hours", sa.Integer(), server_default="24", nullable=False),
    )
    op.add_column(
        "app_settings",
        sa.Column("auto_backup_keep", sa.Integer(), server_default="7", nullable=False),
    )
    op.add_column(
        "app_settings",
        sa.Column("auto_backup_passphrase_encrypted", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        "app_settings",
        sa.Column("auto_backup_last_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "app_settings",
        sa.Column("auto_backup_last_error", sa.String(length=1000), nullable=True),
    )


def downgrade() -> None:
    for column in (
        "auto_backup_last_error",
        "auto_backup_last_at",
        "auto_backup_passphrase_encrypted",
        "auto_backup_keep",
        "auto_backup_interval_hours",
        "auto_backup_enabled",
    ):
        op.drop_column("app_settings", column)
