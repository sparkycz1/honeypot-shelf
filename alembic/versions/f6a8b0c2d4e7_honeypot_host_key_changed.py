"""Remember that a honeypot answered with a different SSH host key

Revision ID: f6a8b0c2d4e7
Revises: e5f7a9b1c3d6
Create Date: 2026-10-06

Two nullable columns, nothing existing is touched.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f6a8b0c2d4e7"
down_revision: str | None = "e5f7a9b1c3d6"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "honeypots", sa.Column("host_key_changed_fingerprint", sa.String(length=255), nullable=True)
    )
    op.add_column(
        "honeypots", sa.Column("host_key_changed_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("honeypots", "host_key_changed_at")
    op.drop_column("honeypots", "host_key_changed_fingerprint")
