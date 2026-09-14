"""GeoIP: app_settings config, geoip_database, event/audit-entry geo columns

Revision ID: 96c7650d79fb
Revises: d1014b3d3921
Create Date: 2026-09-14 15:23:48.456081

"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '96c7650d79fb'
down_revision: str | None = 'd1014b3d3921'
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        'geoip_database',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('mmdb_data', sa.LargeBinary(), nullable=True),
        sa.Column('source', sa.String(length=16), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_attempted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_geoip_database')),
    )
    op.add_column(
        'app_settings',
        sa.Column('geoip_enabled', sa.Boolean(), nullable=False, server_default='false'),
    )
    op.add_column(
        'app_settings', sa.Column('geoip_primary_url_encrypted', sa.LargeBinary(), nullable=True)
    )
    op.add_column(
        'app_settings', sa.Column('geoip_backup_url_encrypted', sa.LargeBinary(), nullable=True)
    )
    op.add_column(
        'app_settings',
        sa.Column(
            'geoip_refresh_interval_hours', sa.Integer(), nullable=False, server_default='168'
        ),
    )
    op.add_column(
        'audit_log_entries', sa.Column('source_country_code', sa.String(length=2), nullable=True)
    )
    op.add_column(
        'audit_log_entries',
        sa.Column('source_country_name', sa.String(length=255), nullable=True),
    )
    op.add_column(
        'audit_log_entries', sa.Column('source_city_name', sa.String(length=255), nullable=True)
    )
    op.add_column(
        'honeypot_events', sa.Column('src_country_code', sa.String(length=2), nullable=True)
    )
    op.add_column(
        'honeypot_events', sa.Column('src_country_name', sa.String(length=255), nullable=True)
    )
    op.add_column(
        'honeypot_events', sa.Column('src_city_name', sa.String(length=255), nullable=True)
    )
    op.add_column('honeypot_events', sa.Column('src_latitude', sa.Float(), nullable=True))
    op.add_column('honeypot_events', sa.Column('src_longitude', sa.Float(), nullable=True))
    op.create_index(
        op.f('ix_honeypot_events_src_country_code'),
        'honeypot_events',
        ['src_country_code'],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_honeypot_events_src_country_code'), table_name='honeypot_events')
    op.drop_column('honeypot_events', 'src_longitude')
    op.drop_column('honeypot_events', 'src_latitude')
    op.drop_column('honeypot_events', 'src_city_name')
    op.drop_column('honeypot_events', 'src_country_name')
    op.drop_column('honeypot_events', 'src_country_code')
    op.drop_column('audit_log_entries', 'source_city_name')
    op.drop_column('audit_log_entries', 'source_country_name')
    op.drop_column('audit_log_entries', 'source_country_code')
    op.drop_column('app_settings', 'geoip_refresh_interval_hours')
    op.drop_column('app_settings', 'geoip_backup_url_encrypted')
    op.drop_column('app_settings', 'geoip_primary_url_encrypted')
    op.drop_column('app_settings', 'geoip_enabled')
    op.drop_table('geoip_database')
