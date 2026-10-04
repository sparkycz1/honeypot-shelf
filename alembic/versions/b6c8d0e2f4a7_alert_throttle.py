"""Notification rules: a throttle window for alert notifications

Revision ID: b6c8d0e2f4a7
Revises: a5b7c9d1e3f6
Create Date: 2026-10-04

`notification_rules.alert_throttle_minutes` (NULL = send every alert, as
before) and, per rule and honeypot, when the last alert went out and how
many were held back since. Existing rules and state rows need no backfill.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b6c8d0e2f4a7"
down_revision: str | None = "a5b7c9d1e3f6"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "notification_rules", sa.Column("alert_throttle_minutes", sa.Integer(), nullable=True)
    )
    op.add_column(
        "notification_rule_states",
        sa.Column("alert_notified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "notification_rule_states",
        sa.Column("alerts_held_back", sa.Integer(), server_default="0", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("notification_rule_states", "alerts_held_back")
    op.drop_column("notification_rule_states", "alert_notified_at")
    op.drop_column("notification_rules", "alert_throttle_minutes")
