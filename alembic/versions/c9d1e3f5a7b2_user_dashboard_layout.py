"""Each account's own Dashboard layout

Revision ID: c9d1e3f5a7b2
Revises: a7b9c1d3e5f8
Create Date: 2026-10-14

One nullable column; every account keeps the default Dashboard until it
arranges its own.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c9d1e3f5a7b2"
down_revision: str | None = "a7b9c1d3e5f8"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("dashboard_layout", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "dashboard_layout")
