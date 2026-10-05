"""Honeypot notes and saved log views

Revision ID: d4e6f8a0b2c5
Revises: c3d5e7f9a1b4
Create Date: 2026-10-04

Two new tables, nothing existing is touched.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d4e6f8a0b2c5"
down_revision: str | None = "c3d5e7f9a1b4"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "honeypot_notes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("honeypot_id", sa.Uuid(), nullable=False),
        sa.Column("author", sa.String(length=255), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["honeypot_id"], ["honeypots.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_honeypot_notes_honeypot_id_created_at",
        "honeypot_notes",
        ["honeypot_id", "created_at"],
    )
    op.create_table(
        "saved_log_views",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("query_string", sa.String(length=1000), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "name", name="uq_saved_log_views_user_id_name"),
    )
    op.create_index("ix_saved_log_views_user_id", "saved_log_views", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_saved_log_views_user_id", table_name="saved_log_views")
    op.drop_table("saved_log_views")
    op.drop_index("ix_honeypot_notes_honeypot_id_created_at", table_name="honeypot_notes")
    op.drop_table("honeypot_notes")
