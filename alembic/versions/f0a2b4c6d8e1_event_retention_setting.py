"""Event retention can be set in Settings

Revision ID: f0a2b4c6d8e1
Revises: e9f1a3b5c7d0
Create Date: 2026-10-04

`app_settings.event_retention_days`, NULL on upgrade: until someone sets it
in Settings, `EVENT_RETENTION_DAYS` from `.env` keeps applying.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f0a2b4c6d8e1"
down_revision: str | None = "e9f1a3b5c7d0"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "app_settings", sa.Column("event_retention_days", sa.Integer(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("app_settings", "event_retention_days")
