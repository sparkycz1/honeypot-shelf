"""add fleet-wide honeypot-alert syslog target on app_settings

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-09-11

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c3d4e5f6a7b8"
down_revision: str | None = "b2c3d4e5f6a7"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None

# Reuses the existing `syslog_protocol` enum type (already created for
# AppSettings.syslog_protocol / Company.syslog_protocol) — create_type=False
# stops SQLAlchemy from trying to CREATE TYPE a third time.
_syslog_protocol_enum = postgresql.ENUM(
    "udp", "tcp", "tls", name="syslog_protocol", create_type=False
)


def upgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column(
            "fleet_alert_syslog_enabled", sa.Boolean(), nullable=False, server_default="false"
        ),
    )
    op.add_column(
        "app_settings", sa.Column("fleet_alert_syslog_host", sa.String(length=255), nullable=True)
    )
    op.add_column(
        "app_settings",
        sa.Column("fleet_alert_syslog_port", sa.Integer(), nullable=False, server_default="514"),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "fleet_alert_syslog_protocol",
            _syslog_protocol_enum,
            nullable=False,
            server_default="udp",
        ),
    )


def downgrade() -> None:
    op.drop_column("app_settings", "fleet_alert_syslog_protocol")
    op.drop_column("app_settings", "fleet_alert_syslog_port")
    op.drop_column("app_settings", "fleet_alert_syslog_host")
    op.drop_column("app_settings", "fleet_alert_syslog_enabled")
