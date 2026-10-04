"""Acknowledge a problem on a honeypot

Revision ID: d8e0f2a4b6c9
Revises: c7d9e1f3a5b8
Create Date: 2026-10-04

Four nullable columns on `honeypots`: when a problem was acknowledged,
until when, by whom and with what note (`app.services.acknowledgements`).
Nothing is acknowledged after the upgrade, so nothing changes until someone
uses it.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d8e0f2a4b6c9"
down_revision: str | None = "c7d9e1f3a5b8"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "honeypots", sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "honeypots", sa.Column("acknowledged_until", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("honeypots", sa.Column("acknowledged_by", sa.String(length=255), nullable=True))
    op.add_column(
        "honeypots", sa.Column("acknowledged_note", sa.String(length=500), nullable=True)
    )


def downgrade() -> None:
    for column in ("acknowledged_note", "acknowledged_by", "acknowledged_until", "acknowledged_at"):
        op.drop_column("honeypots", column)
