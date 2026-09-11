"""add per-company syslog forwarding of honeypot alerts

Revision ID: a1b2c3d4e5f6
Revises: f1a2b3c4d5e6
Create Date: 2026-09-11

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: str | None = "f1a2b3c4d5e6"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None

# The `syslog_protocol` Postgres enum type already exists — created by the
# initial migration for `app_settings.syslog_protocol` (the global,
# audit-log-only syslog target). `Company.syslog_protocol` reuses that
# same type (see app.services.syslog_transport's module docstring for
# why) rather than creating a second, differently-named one with the same
# three values — `create_type=False` is what stops SQLAlchemy from trying
# to `CREATE TYPE syslog_protocol` again here, which would fail outright
# ("type already exists").
_syslog_protocol_enum = postgresql.ENUM(
    "udp", "tcp", "tls", name="syslog_protocol", create_type=False
)


def upgrade() -> None:
    op.add_column(
        "companies",
        sa.Column("syslog_enabled", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column("companies", sa.Column("syslog_host", sa.String(length=255), nullable=True))
    op.add_column(
        "companies",
        sa.Column("syslog_port", sa.Integer(), nullable=False, server_default="514"),
    )
    op.add_column(
        "companies",
        sa.Column("syslog_protocol", _syslog_protocol_enum, nullable=False, server_default="udp"),
    )


def downgrade() -> None:
    op.drop_column("companies", "syslog_protocol")
    op.drop_column("companies", "syslog_port")
    op.drop_column("companies", "syslog_host")
    op.drop_column("companies", "syslog_enabled")
