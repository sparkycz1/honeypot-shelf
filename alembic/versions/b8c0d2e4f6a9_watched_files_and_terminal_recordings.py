"""Watched files on a honeypot, and terminal session recordings

Revision ID: b8c0d2e4f6a9
Revises: a7b9c1d3e5f8
Create Date: 2026-10-14

Two new tables, one honeypot flag, one rule switch, one notification kind
and two settings columns. Nothing changes for an existing deployment until
it is used: recording is off, every rule's new switch is off, and the
default watched files are only read from the next facts refresh on.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b8c0d2e4f6a9"
down_revision: str | None = "a7b9c1d3e5f8"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TYPE notification_kind ADD VALUE IF NOT EXISTS 'file_changed'")

    op.create_table(
        "honeypot_watched_files",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("honeypot_id", sa.Uuid(), nullable=False),
        sa.Column("path", sa.String(length=512), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("content_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("previous_content_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("lines_added", sa.Integer(), nullable=True),
        sa.Column("lines_removed", sa.Integer(), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["honeypot_id"], ["honeypots.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("honeypot_id", "path", name="uq_honeypot_watched_files_path"),
    )
    op.create_index(
        "ix_honeypot_watched_files_honeypot_id", "honeypot_watched_files", ["honeypot_id"]
    )
    op.add_column(
        "honeypots",
        sa.Column(
            "watched_files_customized", sa.Boolean(), server_default="false", nullable=False
        ),
    )
    op.add_column(
        "notification_rules",
        sa.Column("notify_on_file_changed", sa.Boolean(), server_default="false", nullable=False),
    )

    op.create_table(
        "terminal_recordings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("honeypot_id", sa.Uuid(), nullable=True),
        sa.Column("honeypot_name", sa.String(length=255), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_seconds", sa.Float(), nullable=False),
        sa.Column("cols", sa.Integer(), nullable=False),
        sa.Column("rows", sa.Integer(), nullable=False),
        sa.Column("output_bytes", sa.Integer(), nullable=False),
        sa.Column("truncated", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("data_encrypted", sa.LargeBinary(), nullable=False),
        sa.ForeignKeyConstraint(["honeypot_id"], ["honeypots.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_terminal_recordings_started_at", "terminal_recordings", ["started_at"])
    op.create_index(
        "ix_terminal_recordings_honeypot_id_started_at",
        "terminal_recordings",
        ["honeypot_id", "started_at"],
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "terminal_recording_enabled", sa.Boolean(), server_default=sa.false(), nullable=False
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "terminal_recording_retention_days",
            sa.Integer(),
            server_default="30",
            nullable=True,
        ),
    )


def downgrade() -> None:
    # The enum value stays: Postgres cannot drop a value from a type.
    op.drop_column("app_settings", "terminal_recording_retention_days")
    op.drop_column("app_settings", "terminal_recording_enabled")
    op.drop_table("terminal_recordings")
    op.drop_column("notification_rules", "notify_on_file_changed")
    op.drop_column("honeypots", "watched_files_customized")
    op.drop_table("honeypot_watched_files")
