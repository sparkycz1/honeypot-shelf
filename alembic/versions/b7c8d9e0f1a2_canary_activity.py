"""opencanary_log_offset/polled_at/poll_interval on honeypots, source on
honeypot_events

Revision ID: b7c8d9e0f1a2
Revises: a6b7c8d9e0f1
Create Date: 2026-09-09

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b7c8d9e0f1a2"
down_revision: str | None = "a6b7c8d9e0f1"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "honeypots",
        sa.Column(
            "opencanary_log_offset", sa.BigInteger(), server_default="0", nullable=False
        ),
    )
    op.add_column(
        "honeypots",
        sa.Column("opencanary_log_polled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "honeypots",
        sa.Column("opencanary_log_poll_interval_seconds", sa.Integer(), nullable=True),
    )
    op.add_column(
        "honeypot_events",
        sa.Column("source", sa.String(length=20), server_default="push", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("honeypot_events", "source")
    op.drop_column("honeypots", "opencanary_log_poll_interval_seconds")
    op.drop_column("honeypots", "opencanary_log_polled_at")
    op.drop_column("honeypots", "opencanary_log_offset")
