"""Updates: upgrade and security strategies, reboot if needed, rolling, held packages

Revision ID: c3d5e7f9a1b4
Revises: b2c4d6e8f0a3
Create Date: 2026-10-04

Two new upgrade strategies, three columns on an update run (reboot only if
needed, its outcome, the position in a rolling batch) and the list of held
packages on a honeypot. Existing runs get "no reboot asked for" and "not
rolling", so they read exactly as before.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c3d5e7f9a1b4"
down_revision: str | None = "b2c4d6e8f0a3"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None

_NEW_STRATEGIES = ("upgrade", "security")


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for value in _NEW_STRATEGIES:
            op.execute(f"ALTER TYPE upgrade_strategy ADD VALUE IF NOT EXISTS '{value}'")
    op.add_column(
        "honeypot_update_runs",
        sa.Column("reboot_if_required", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column(
        "honeypot_update_runs", sa.Column("reboot_outcome", sa.String(length=16), nullable=True)
    )
    op.add_column(
        "honeypot_update_runs", sa.Column("rollout_position", sa.Integer(), nullable=True)
    )
    op.add_column("honeypots", sa.Column("apt_held_packages", sa.JSON(), nullable=True))


def downgrade() -> None:
    # The enum values stay: Postgres cannot drop a value from a type.
    op.drop_column("honeypots", "apt_held_packages")
    op.drop_column("honeypot_update_runs", "rollout_position")
    op.drop_column("honeypot_update_runs", "reboot_outcome")
    op.drop_column("honeypot_update_runs", "reboot_if_required")
