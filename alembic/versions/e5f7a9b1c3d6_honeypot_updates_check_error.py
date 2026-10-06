"""Remember why a honeypot's last update check failed

Revision ID: e5f7a9b1c3d6
Revises: d4e6f8a0b2c5
Create Date: 2026-10-06

One nullable column, nothing existing is touched.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e5f7a9b1c3d6"
down_revision: str | None = "d4e6f8a0b2c5"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("honeypots", sa.Column("updates_check_error", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("honeypots", "updates_check_error")
