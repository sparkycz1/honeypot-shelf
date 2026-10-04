"""Ignore list for event sources

Revision ID: a1b3c5d7e9f2
Revises: f0a2b4c6d8e1
Create Date: 2026-10-04

A new `ignored_sources` table (an address or network, per company or for
every honeypot) and `honeypot_events.ignored`, false for every existing
event: nothing is ignored until someone adds an entry.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1b3c5d7e9f2"
down_revision: str | None = "f0a2b4c6d8e1"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "ignored_sources",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("company_id", sa.Uuid(), nullable=True),
        sa.Column("network", sa.String(length=64), nullable=False),
        sa.Column("note", sa.String(length=255), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("company_id", "network", name="uq_ignored_source_company_network"),
    )
    op.create_index("ix_ignored_sources_company_id", "ignored_sources", ["company_id"])
    op.add_column(
        "honeypot_events",
        sa.Column("ignored", sa.Boolean(), server_default="false", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("honeypot_events", "ignored")
    op.drop_index("ix_ignored_sources_company_id", table_name="ignored_sources")
    op.drop_table("ignored_sources")
