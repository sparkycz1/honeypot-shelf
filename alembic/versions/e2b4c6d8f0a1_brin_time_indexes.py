"""BRIN indexes on the time columns of the sample tables.

honeypot_monitoring_samples.sampled_at and
honeypot_reachability_samples.checked_at get a BRIN index (rows arrive in
time order, so a few pages cover millions of rows). Ported from debcontrol
0.127.0.

Indexes only, no data change. Building a BRIN index is one sequential scan.

Revision ID: e2b4c6d8f0a1
Revises: d1e3f5a7b9c4
Create Date: 2026-10-30
"""

from collections.abc import Sequence

from alembic import op

revision: str = "e2b4c6d8f0a1"
down_revision: str | None = "d1e3f5a7b9c4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_honeypot_monitoring_samples_sampled_at_brin",
        "honeypot_monitoring_samples",
        ["sampled_at"],
        postgresql_using="brin",
    )
    op.create_index(
        "ix_honeypot_reachability_samples_checked_at_brin",
        "honeypot_reachability_samples",
        ["checked_at"],
        postgresql_using="brin",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_honeypot_reachability_samples_checked_at_brin",
        table_name="honeypot_reachability_samples",
    )
    op.drop_index(
        "ix_honeypot_monitoring_samples_sampled_at_brin",
        table_name="honeypot_monitoring_samples",
    )
