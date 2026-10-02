"""ScheduledTask.timezone (a schedule's own IANA time zone)

Ported from debcontrol. Nullable: every existing schedule keeps running in
UTC, exactly as before, until someone picks a zone for it.

Revision ID: a5b7c9d1e3f6
Revises: f4a6b8c0d2e5
Create Date: 2026-10-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a5b7c9d1e3f6"
down_revision: str | None = "f4a6b8c0d2e5"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("scheduled_tasks", sa.Column("timezone", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("scheduled_tasks", "timezone")
