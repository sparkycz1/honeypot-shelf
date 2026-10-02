"""Honeypot.disk_forecast (disk-full forecast)

Revision ID: e3f5a7b9c1d4
Revises: d2e4f6a8b0c3
Create Date: 2026-10-02

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e3f5a7b9c1d4"
down_revision: str | None = "d2e4f6a8b0c3"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("honeypots", sa.Column("disk_forecast", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("honeypots", "disk_forecast")
