"""drop per-honeypot ingest token

Revision ID: e0f1a2b3c4d5
Revises: d9e0f1a2b3c4
Create Date: 2026-09-10

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e0f1a2b3c4d5"
down_revision: str | None = "d9e0f1a2b3c4"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.drop_constraint(
        op.f("uq_honeypots_ingest_token_hash"), "honeypots", type_="unique"
    )
    op.drop_column("honeypots", "ingest_token_hash")


def downgrade() -> None:
    op.add_column(
        "honeypots",
        sa.Column("ingest_token_hash", sa.String(length=64), nullable=True),
    )
    op.create_unique_constraint(
        op.f("uq_honeypots_ingest_token_hash"), "honeypots", ["ingest_token_hash"]
    )
