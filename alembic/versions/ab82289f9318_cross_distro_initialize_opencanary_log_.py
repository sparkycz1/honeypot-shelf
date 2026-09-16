"""cross-distro Initialize: opencanary_log_path, supports_readonly_root on honeypots

Revision ID: ab82289f9318
Revises: 96c7650d79fb
Create Date: 2026-09-16 08:28:16.933229

"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'ab82289f9318'
down_revision: str | None = '96c7650d79fb'
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        'honeypots',
        sa.Column(
            'opencanary_log_path',
            sa.String(length=255),
            server_default='/mnt/tmpfs/opencanary.log',
            nullable=False,
        ),
    )
    op.add_column(
        'honeypots',
        sa.Column(
            'supports_readonly_root', sa.Boolean(), server_default='true', nullable=False
        ),
    )


def downgrade() -> None:
    op.drop_column('honeypots', 'supports_readonly_root')
    op.drop_column('honeypots', 'opencanary_log_path')
