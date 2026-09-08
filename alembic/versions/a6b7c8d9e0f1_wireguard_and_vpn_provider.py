"""vpn_provider + wireguard_config_encrypted on app_settings; drop
netbird_enabled (superseded by vpn_provider — see VpnProvider's docstring)

Revision ID: a6b7c8d9e0f1
Revises: f5a6b7c8d9e0
Create Date: 2026-09-08

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a6b7c8d9e0f1"
down_revision: str | None = "f5a6b7c8d9e0"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    # Unlike every other enum column in this app's migrations (all added
    # via `create_table`, which creates the Postgres enum TYPE as a side
    # effect), `add_column` on an existing table does not — the type has
    # to be created explicitly first, or the ALTER TABLE below fails with
    # `type "vpn_provider" does not exist`.
    vpn_provider_enum = sa.Enum("none", "netbird", "wireguard", name="vpn_provider")
    vpn_provider_enum.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "app_settings",
        sa.Column(
            "vpn_provider",
            vpn_provider_enum,
            server_default="none",
            nullable=False,
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column("wireguard_config_encrypted", sa.LargeBinary(), nullable=True),
    )
    # Backfill: a row that already had NetBird enabled keeps showing as
    # connected/active after this migration, rather than silently
    # reverting to "none" and looking disconnected until someone notices.
    op.execute(
        "UPDATE app_settings SET vpn_provider = 'netbird' WHERE netbird_enabled IS TRUE"
    )
    op.drop_column("app_settings", "netbird_enabled")


def downgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column("netbird_enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.execute(
        "UPDATE app_settings SET netbird_enabled = TRUE WHERE vpn_provider = 'netbird'"
    )
    op.drop_column("app_settings", "wireguard_config_encrypted")
    op.drop_column("app_settings", "vpn_provider")
    sa.Enum(name="vpn_provider").drop(op.get_bind(), checkfirst=True)
