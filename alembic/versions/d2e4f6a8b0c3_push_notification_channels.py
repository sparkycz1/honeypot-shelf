"""push notification channels (ntfy, Gotify, Telegram, Discord, Pushover,
Mattermost, Slack, Microsoft Teams)

New `notification_channel` enum values, plus a rule's channel token
(encrypted) and recipient. Existing email/webhook rules are untouched.

Revision ID: d2e4f6a8b0c3
Revises: c1d3e5f7a9b2
Create Date: 2026-10-02
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d2e4f6a8b0c3"
down_revision: str | None = "c1d3e5f7a9b2"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None

_NEW_CHANNELS = (
    "ntfy", "gotify", "telegram", "discord", "pushover", "mattermost", "slack", "teams",
)


def upgrade() -> None:
    for value in _NEW_CHANNELS:
        op.execute(f"ALTER TYPE notification_channel ADD VALUE IF NOT EXISTS '{value}'")
    op.add_column(
        "notification_rules", sa.Column("channel_token_encrypted", sa.LargeBinary(), nullable=True)
    )
    op.add_column(
        "notification_rules", sa.Column("channel_recipient", sa.String(length=255), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("notification_rules", "channel_recipient")
    op.drop_column("notification_rules", "channel_token_encrypted")
    # Postgres can't drop enum values; rules still using one must be moved
    # back to email/webhook by hand before downgrading.
