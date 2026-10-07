"""MAC address change: the manufacturer list and a honeypot's chosen address

Revision ID: a7b9c1d3e5f8
Revises: f6a8b0c2d4e7
Create Date: 2026-10-07

One new table and nullable/defaulted columns; nothing existing is touched.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a7b9c1d3e5f8"
down_revision: str | None = "f6a8b0c2d4e7"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "mac_vendors",
        sa.Column("oui", sa.String(length=6), nullable=False),
        sa.Column("vendor", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("oui"),
    )
    op.create_index("ix_mac_vendors_vendor", "mac_vendors", ["vendor"])

    op.add_column(
        "app_settings", sa.Column("mac_vendor_list_url", sa.String(length=1000), nullable=True)
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "mac_vendor_refresh_interval_hours",
            sa.Integer(),
            server_default="168",
            nullable=False,
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column("mac_vendor_list_updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "app_settings",
        sa.Column("mac_vendor_list_attempted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("app_settings", sa.Column("mac_vendor_list_error", sa.Text(), nullable=True))

    op.add_column(
        "honeypots", sa.Column("mac_address_override", sa.String(length=17), nullable=True)
    )
    op.add_column(
        "honeypots", sa.Column("mac_address_vendor", sa.String(length=255), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("honeypots", "mac_address_vendor")
    op.drop_column("honeypots", "mac_address_override")
    op.drop_column("app_settings", "mac_vendor_list_error")
    op.drop_column("app_settings", "mac_vendor_list_attempted_at")
    op.drop_column("app_settings", "mac_vendor_list_updated_at")
    op.drop_column("app_settings", "mac_vendor_refresh_interval_hours")
    op.drop_column("app_settings", "mac_vendor_list_url")
    op.drop_index("ix_mac_vendors_vendor", table_name="mac_vendors")
    op.drop_table("mac_vendors")
