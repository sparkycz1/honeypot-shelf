"""Notification rules: alert type filter and honeypot health events

Revision ID: b2c4d6e8f0a3
Revises: a1b3c5d7e9f2
Create Date: 2026-10-04

Three new notification kinds (disk about to fill, a failed service, a
pending reboot), four rule columns and one honeypot column. The new rule
switches are off and the type filter empty, so an existing rule behaves
exactly as before.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b2c4d6e8f0a3"
down_revision: str | None = "a1b3c5d7e9f2"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None

_NEW_KINDS = ("disk_full", "service_failed", "reboot_required")


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for value in _NEW_KINDS:
            op.execute(f"ALTER TYPE notification_kind ADD VALUE IF NOT EXISTS '{value}'")
    op.add_column("notification_rules", sa.Column("alert_event_types", sa.JSON(), nullable=True))
    for column in ("notify_on_disk_full", "notify_on_service_failed", "notify_on_reboot_required"):
        op.add_column(
            "notification_rules",
            sa.Column(column, sa.Boolean(), server_default="false", nullable=False),
        )
    op.add_column("honeypots", sa.Column("health_announced", sa.JSON(), nullable=True))


def downgrade() -> None:
    # The enum values stay: Postgres cannot drop a value from a type.
    op.drop_column("honeypots", "health_announced")
    for column in ("notify_on_reboot_required", "notify_on_service_failed", "notify_on_disk_full"):
        op.drop_column("notification_rules", column)
    op.drop_column("notification_rules", "alert_event_types")
