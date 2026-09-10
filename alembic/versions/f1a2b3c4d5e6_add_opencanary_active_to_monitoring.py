"""add opencanary_active to honeypot_monitoring_samples

Revision ID: f1a2b3c4d5e6
Revises: e0f1a2b3c4d5
Create Date: 2026-09-10

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f1a2b3c4d5e6"
down_revision: str | None = "e0f1a2b3c4d5"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "honeypot_monitoring_samples",
        sa.Column("opencanary_active", sa.Boolean(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("honeypot_monitoring_samples", "opencanary_active")
