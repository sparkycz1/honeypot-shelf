"""Notifications: user email/notification_email, honeypot_notification_
subscriptions, honeypots.unreachable_since, app_settings notification
templates

Revision ID: ecbd56bc810b
Revises: 3664702082ea
Create Date: 2026-09-12

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "ecbd56bc810b"
down_revision: str | None = "3664702082ea"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("email", sa.String(length=255), nullable=True))
    op.add_column(
        "users", sa.Column("notification_email", sa.String(length=255), nullable=True)
    )

    op.add_column(
        "honeypots", sa.Column("unreachable_since", sa.DateTime(timezone=True), nullable=True)
    )

    op.add_column(
        "app_settings",
        sa.Column("notification_alert_subject", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "app_settings", sa.Column("notification_alert_body", sa.Text(), nullable=True)
    )
    op.add_column(
        "app_settings",
        sa.Column("notification_unavailable_subject", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "app_settings", sa.Column("notification_unavailable_body", sa.Text(), nullable=True)
    )
    op.add_column(
        "app_settings",
        sa.Column("notification_recovered_subject", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "app_settings", sa.Column("notification_recovered_body", sa.Text(), nullable=True)
    )

    op.create_table(
        "honeypot_notification_subscriptions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("honeypot_id", sa.Uuid(), nullable=False),
        sa.Column("notify_on_alert", sa.Boolean(), nullable=False),
        sa.Column("notify_on_unavailable", sa.Boolean(), nullable=False),
        sa.Column("unavailable_after_minutes", sa.Integer(), nullable=False),
        sa.Column("unavailable_notified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["honeypot_id"], ["honeypots.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "user_id",
            "honeypot_id",
            name="uq_honeypot_notification_subscription_user_honeypot",
        ),
    )
    op.create_index(
        op.f("ix_honeypot_notification_subscriptions_user_id"),
        "honeypot_notification_subscriptions",
        ["user_id"],
    )
    op.create_index(
        op.f("ix_honeypot_notification_subscriptions_honeypot_id"),
        "honeypot_notification_subscriptions",
        ["honeypot_id"],
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_honeypot_notification_subscriptions_honeypot_id"),
        table_name="honeypot_notification_subscriptions",
    )
    op.drop_index(
        op.f("ix_honeypot_notification_subscriptions_user_id"),
        table_name="honeypot_notification_subscriptions",
    )
    op.drop_table("honeypot_notification_subscriptions")

    op.drop_column("app_settings", "notification_recovered_body")
    op.drop_column("app_settings", "notification_recovered_subject")
    op.drop_column("app_settings", "notification_unavailable_body")
    op.drop_column("app_settings", "notification_unavailable_subject")
    op.drop_column("app_settings", "notification_alert_body")
    op.drop_column("app_settings", "notification_alert_subject")

    op.drop_column("honeypots", "unreachable_since")

    op.drop_column("users", "notification_email")
    op.drop_column("users", "email")
