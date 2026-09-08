"""netbird_enabled/management_url/setup_key_encrypted on app_settings

Revision ID: f5a6b7c8d9e0
Revises: e4f5a6b7c8d9
Create Date: 2026-09-08

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f5a6b7c8d9e0"
down_revision: str | None = "e4f5a6b7c8d9"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column("netbird_enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column(
        "app_settings",
        sa.Column("netbird_management_url", sa.String(length=500), nullable=True),
    )
    op.add_column(
        "app_settings",
        sa.Column("netbird_setup_key_encrypted", sa.LargeBinary(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("app_settings", "netbird_setup_key_encrypted")
    op.drop_column("app_settings", "netbird_management_url")
    op.drop_column("app_settings", "netbird_enabled")
