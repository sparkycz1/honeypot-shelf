"""Move background-check settings from environment variables into
app_settings (new "Checks & retention" Settings tab)

Ported from an identical debcontrol change: ssh_connect_timeout,
update_timeout_seconds, facts_refresh_interval_seconds,
reachability_check_interval_seconds, reachability_check_concurrency, and
monitoring_interval_seconds used to be `app.core.config.Settings` fields
(env vars, restart to change) — now DB-backed, editable from Settings.
opencanary_log_poll_interval_seconds has no debcontrol equivalent (it's
this app's own honeypot-log-poll setting) but is moved the same way, for
the same reason.

Each new column is added NOT NULL with a `server_default` matching its
old env-var default, so an existing deployment upgrades with identical
behavior to before this migration, until an admin changes one from the
new tab.

Revision ID: 00f38ecd49e7
Revises: e5f6a7b8c9d0
Create Date: 2026-09-12
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "00f38ecd49e7"
down_revision: str | None = "e5f6a7b8c9d0"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column(
            "ssh_connect_timeout", sa.Integer(), nullable=False, server_default="10"
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "update_timeout_seconds", sa.Integer(), nullable=False, server_default="1800"
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "facts_refresh_interval_seconds",
            sa.Integer(),
            nullable=False,
            server_default="600",
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "reachability_check_interval_seconds",
            sa.Integer(),
            nullable=False,
            server_default="60",
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "reachability_check_concurrency",
            sa.Integer(),
            nullable=False,
            server_default="20",
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "monitoring_interval_seconds", sa.Integer(), nullable=False, server_default="120"
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "opencanary_log_poll_interval_seconds",
            sa.Integer(),
            nullable=False,
            server_default="120",
        ),
    )


def downgrade() -> None:
    op.drop_column("app_settings", "opencanary_log_poll_interval_seconds")
    op.drop_column("app_settings", "monitoring_interval_seconds")
    op.drop_column("app_settings", "reachability_check_concurrency")
    op.drop_column("app_settings", "reachability_check_interval_seconds")
    op.drop_column("app_settings", "facts_refresh_interval_seconds")
    op.drop_column("app_settings", "update_timeout_seconds")
    op.drop_column("app_settings", "ssh_connect_timeout")
