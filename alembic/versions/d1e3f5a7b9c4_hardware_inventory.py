"""Hardware inventory and warranties

Revision ID: d1e3f5a7b9c4
Revises: c9d1e3f5a7b2
Create Date: 2026-10-14

Eight nullable columns on honeypots (what the hardware says it is, and
what a person records about it), the rule switch for a warranty that ends
soon with its number of days, and the notification kind. Vendor, model
and serial appear after each honeypot's next facts refresh; no rule sends
anything until someone turns the switch on.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d1e3f5a7b9c4"
down_revision: str | None = "c9d1e3f5a7b2"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TYPE notification_kind ADD VALUE IF NOT EXISTS 'warranty_ending'")
    op.add_column("honeypots", sa.Column("hw_vendor", sa.String(length=128), nullable=True))
    op.add_column("honeypots", sa.Column("hw_model", sa.String(length=128), nullable=True))
    op.add_column("honeypots", sa.Column("hw_serial", sa.String(length=128), nullable=True))
    op.add_column("honeypots", sa.Column("is_physical", sa.Boolean(), nullable=True))
    op.add_column("honeypots", sa.Column("asset_serial", sa.String(length=128), nullable=True))
    op.add_column("honeypots", sa.Column("purchase_date", sa.Date(), nullable=True))
    op.add_column("honeypots", sa.Column("warranty_until", sa.Date(), nullable=True))
    op.add_column("honeypots", sa.Column("asset_note", sa.String(length=255), nullable=True))
    op.add_column(
        "notification_rules",
        sa.Column(
            "notify_on_warranty_ending", sa.Boolean(), server_default="false", nullable=False
        ),
    )
    op.add_column(
        "notification_rules",
        sa.Column("warranty_notice_days", sa.Integer(), server_default="60", nullable=False),
    )


def downgrade() -> None:
    # The enum value stays: Postgres cannot drop a value from a type.
    op.drop_column("notification_rules", "warranty_notice_days")
    op.drop_column("notification_rules", "notify_on_warranty_ending")
    for column in (
        "asset_note",
        "warranty_until",
        "purchase_date",
        "asset_serial",
        "is_physical",
        "hw_serial",
        "hw_model",
        "hw_vendor",
    ):
        op.drop_column("honeypots", column)
