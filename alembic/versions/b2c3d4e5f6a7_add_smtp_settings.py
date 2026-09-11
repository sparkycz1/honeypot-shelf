"""add SMTP relay settings (config only, no sending yet)

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-09-11

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b2c3d4e5f6a7"
down_revision: str | None = "a1b2c3d4e5f6"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    smtp_encryption = sa.Enum("none", "starttls", "ssl_tls", name="smtp_encryption")
    smtp_encryption.create(op.get_bind(), checkfirst=True)

    op.add_column(
        "app_settings",
        sa.Column("smtp_enabled", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column("app_settings", sa.Column("smtp_host", sa.String(length=255), nullable=True))
    op.add_column(
        "app_settings",
        sa.Column("smtp_port", sa.Integer(), nullable=False, server_default="587"),
    )
    op.add_column(
        "app_settings",
        sa.Column("smtp_encryption", smtp_encryption, nullable=False, server_default="starttls"),
    )
    op.add_column(
        "app_settings", sa.Column("smtp_username", sa.String(length=255), nullable=True)
    )
    op.add_column(
        "app_settings", sa.Column("smtp_password_encrypted", sa.LargeBinary(), nullable=True)
    )
    op.add_column(
        "app_settings", sa.Column("smtp_from_address", sa.String(length=255), nullable=True)
    )
    op.add_column(
        "app_settings", sa.Column("smtp_from_name", sa.String(length=255), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("app_settings", "smtp_from_name")
    op.drop_column("app_settings", "smtp_from_address")
    op.drop_column("app_settings", "smtp_password_encrypted")
    op.drop_column("app_settings", "smtp_username")
    op.drop_column("app_settings", "smtp_encryption")
    op.drop_column("app_settings", "smtp_port")
    op.drop_column("app_settings", "smtp_host")
    op.drop_column("app_settings", "smtp_enabled")

    sa.Enum(name="smtp_encryption").drop(op.get_bind(), checkfirst=True)
