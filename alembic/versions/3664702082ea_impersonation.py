"""impersonation: user_sessions.impersonator_id

Revision ID: 3664702082ea
Revises: 00f38ecd49e7
Create Date: 2026-09-12

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "3664702082ea"
down_revision: str | None = "00f38ecd49e7"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    # Nullable, no default needed — every existing session simply wasn't an
    # impersonation (safe for a running instance, see CLAUDE.md's "Upgrade
    # safety"). Ported from an identical debcontrol change.
    op.add_column(
        "user_sessions",
        sa.Column("impersonator_id", sa.Uuid(), nullable=True),
    )
    op.create_foreign_key(
        "fk_user_sessions_impersonator_id_users",
        "user_sessions",
        "users",
        ["impersonator_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_user_sessions_impersonator_id_users", "user_sessions", type_="foreignkey"
    )
    op.drop_column("user_sessions", "impersonator_id")
