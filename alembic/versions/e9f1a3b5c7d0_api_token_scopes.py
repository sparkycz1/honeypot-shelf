"""API tokens: read-only and company limits

Revision ID: e9f1a3b5c7d0
Revises: d8e0f2a4b6c9
Create Date: 2026-10-04

`api_tokens.read_only` (false for every existing token) and
`api_tokens.company_ids` (NULL = no limit). Existing tokens keep working
exactly as before.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e9f1a3b5c7d0"
down_revision: str | None = "d8e0f2a4b6c9"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "api_tokens",
        sa.Column("read_only", sa.Boolean(), server_default="false", nullable=False),
    )
    op.add_column("api_tokens", sa.Column("company_ids", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("api_tokens", "company_ids")
    op.drop_column("api_tokens", "read_only")
