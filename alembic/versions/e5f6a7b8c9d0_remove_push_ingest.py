"""Remove push-based event ingestion

`POST /api/ingest/{honeypot_id}/events` and its shared `INGEST_TOKEN` are
removed per explicit instruction — the SSH log poll already covers every
honeypot with no forwarder to set up, making the push path pure
redundancy. `honeypot_events.source` keeps its historical "push" rows
(never touched, never rewritten); only the column's own default for a
row inserted with no explicit value changes, from "push" to "ssh_poll",
matching the only value the app ever writes going forward.

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-09-11
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "e5f6a7b8c9d0"
down_revision: str | None = "d4e5f6a7b8c9"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "honeypot_events", "source", server_default=sa.text("'ssh_poll'")
    )


def downgrade() -> None:
    op.alter_column("honeypot_events", "source", server_default=sa.text("'push'"))
