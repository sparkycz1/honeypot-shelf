"""notification rule multi-company/honeypot scope

Replaces the old single, nullable `notification_rules.company_id`/
`honeypot_id` columns with two plain many-to-many link tables —
`notification_rule_companies` and `notification_rule_honeypots` — same
pattern as `honeypot_companies` (see d4e5f6a7b8c9). A rule's `scope` still
says which *kind* of target it holds; it can now hold any number of them
instead of exactly one. Data is backfilled before the old columns are
dropped: every existing `(rule, company_id)`/`(rule, honeypot_id)` becomes
one link-table row — nothing is lost, every rule keeps the single
company/honeypot it had before this migration, just expressed as a link
row instead of a column.

Revision ID: 9a1b2c3d4e5f
Revises: 5ce48ec7720d
Create Date: 2026-09-18
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "9a1b2c3d4e5f"
down_revision: str | None = "5ce48ec7720d"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "notification_rule_companies",
        sa.Column("rule_id", sa.Uuid(), nullable=False),
        sa.Column("company_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["rule_id"], ["notification_rules.id"],
            name=op.f("fk_notification_rule_companies_rule_id_notification_rules"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["company_id"], ["companies.id"],
            name=op.f("fk_notification_rule_companies_company_id_companies"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "rule_id", "company_id", name=op.f("pk_notification_rule_companies")
        ),
    )
    op.create_table(
        "notification_rule_honeypots",
        sa.Column("rule_id", sa.Uuid(), nullable=False),
        sa.Column("honeypot_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["rule_id"], ["notification_rules.id"],
            name=op.f("fk_notification_rule_honeypots_rule_id_notification_rules"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["honeypot_id"], ["honeypots.id"],
            name=op.f("fk_notification_rule_honeypots_honeypot_id_honeypots"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "rule_id", "honeypot_id", name=op.f("pk_notification_rule_honeypots")
        ),
    )

    # --- Backfill from the old single-target columns, before dropping them ---
    op.execute(
        """
        INSERT INTO notification_rule_companies (rule_id, company_id)
        SELECT id, company_id FROM notification_rules WHERE company_id IS NOT NULL
        """
    )
    op.execute(
        """
        INSERT INTO notification_rule_honeypots (rule_id, honeypot_id)
        SELECT id, honeypot_id FROM notification_rules WHERE honeypot_id IS NOT NULL
        """
    )

    # --- Drop the old single-target columns ---
    op.drop_index(op.f("ix_notification_rules_company_id"), table_name="notification_rules")
    op.drop_constraint(
        op.f("fk_notification_rules_company_id_companies"),
        "notification_rules", type_="foreignkey",
    )
    op.drop_column("notification_rules", "company_id")

    op.drop_index(op.f("ix_notification_rules_honeypot_id"), table_name="notification_rules")
    op.drop_constraint(
        op.f("fk_notification_rules_honeypot_id_honeypots"),
        "notification_rules", type_="foreignkey",
    )
    op.drop_column("notification_rules", "honeypot_id")


def downgrade() -> None:
    # One-way in practice (a rule with 0 or 2+ targets has no single value
    # to collapse back to) — restores the old shape and backfills from
    # each rule's *first* linked row only, best-effort.
    op.add_column("notification_rules", sa.Column("company_id", sa.Uuid(), nullable=True))
    op.add_column("notification_rules", sa.Column("honeypot_id", sa.Uuid(), nullable=True))

    op.execute(
        """
        UPDATE notification_rules r
        SET company_id = c.company_id
        FROM (
            SELECT DISTINCT ON (rule_id) rule_id, company_id
            FROM notification_rule_companies
        ) c
        WHERE c.rule_id = r.id
        """
    )
    op.execute(
        """
        UPDATE notification_rules r
        SET honeypot_id = h.honeypot_id
        FROM (
            SELECT DISTINCT ON (rule_id) rule_id, honeypot_id
            FROM notification_rule_honeypots
        ) h
        WHERE h.rule_id = r.id
        """
    )

    op.create_index(
        op.f("ix_notification_rules_company_id"), "notification_rules", ["company_id"]
    )
    op.create_foreign_key(
        op.f("fk_notification_rules_company_id_companies"),
        "notification_rules", "companies", ["company_id"], ["id"], ondelete="CASCADE",
    )
    op.create_index(
        op.f("ix_notification_rules_honeypot_id"), "notification_rules", ["honeypot_id"]
    )
    op.create_foreign_key(
        op.f("fk_notification_rules_honeypot_id_honeypots"),
        "notification_rules", "honeypots", ["honeypot_id"], ["id"], ondelete="CASCADE",
    )

    op.drop_table("notification_rule_honeypots")
    op.drop_table("notification_rule_companies")
