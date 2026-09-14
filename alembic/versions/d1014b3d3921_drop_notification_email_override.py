"""drop notification_email override on users

Revision ID: d1014b3d3921
Revises: 384c2557115e
Create Date: 2026-09-14 10:05:00.000000

"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'd1014b3d3921'
down_revision: str | None = '384c2557115e'
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.drop_column('users', 'notification_email')


def downgrade() -> None:
    op.add_column(
        'users', sa.Column('notification_email', sa.VARCHAR(length=255), nullable=True)
    )
