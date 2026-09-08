"""drop netbird_management_url from app_settings

NetBird's management URL is no longer a global setting — it's entered
fresh on each Initialize run instead (never persisted), the same
one-time-use pattern already used for the SSH password and the NetBird
setup key. See app.web.routes.initialize.PendingInitializeRun.

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7
Create Date: 2026-09-08

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d3e4f5a6b7c8"
down_revision: str | None = "c2d3e4f5a6b7"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.drop_column("app_settings", "netbird_management_url")


def downgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column("netbird_management_url", sa.String(length=500), nullable=True),
    )
