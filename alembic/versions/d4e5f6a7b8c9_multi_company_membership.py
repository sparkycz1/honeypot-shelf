"""Multi-company membership for users and honeypots

Replaces the old single required `company_id` FK on `User` and `Honeypot`
(and the denormalized `company_id` on `HoneypotEvent`) with proper
many-to-many relationships:

- `company_memberships` (new table) — one row per (user, company), each
  with its own `access_level`. Replaces `User.company_id`/
  `User.access_level`. A user can now hold membership in any number of
  companies, each independently `READ` or `READ_WRITE`.
- `honeypot_companies` (new table) — a plain link table, no columns of
  its own. Replaces `Honeypot.company_id`. A honeypot can now belong to
  any number of companies, including zero (superadmin-visible only).
- `HoneypotEvent.company_id` is dropped outright — an event's company
  scope is now derived by joining through its honeypot's own companies
  (`app.auth.scope`), since a shared honeypot's events belong to every
  company it's attached to, not one.

Data is backfilled before the old columns are dropped: every existing
`(user, company_id, access_level)` becomes one `company_memberships` row,
and every existing `(honeypot, company_id)` becomes one `honeypot_companies`
row — nothing is lost, every account/honeypot keeps exactly the single
company/level it had before this migration, just expressed as a
membership row instead of a column.

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-09-11
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "d4e5f6a7b8c9"
down_revision: str | None = "c3d4e5f6a7b8"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    # --- New tables ---
    op.create_table(
        "company_memberships",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("company_id", sa.Uuid(), nullable=False),
        sa.Column(
            "access_level",
            # Reuses the enum type "access_level" already created by the
            # initial migration for the (now-dropped) users.access_level
            # column — create_type=False so this doesn't try to create it
            # again (see wiki/Architecture.md's "Postgres enum reuse"
            # pattern, also used for syslog_protocol).
            postgresql.ENUM("read", "read_write", name="access_level", create_type=False),
            nullable=False,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"],
            name=op.f("fk_company_memberships_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["company_id"], ["companies.id"],
            name=op.f("fk_company_memberships_company_id_companies"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_company_memberships")),
        sa.UniqueConstraint("user_id", "company_id", name="uq_company_membership_user_company"),
    )
    op.create_index(
        op.f("ix_company_memberships_user_id"), "company_memberships", ["user_id"], unique=False
    )
    op.create_index(
        op.f("ix_company_memberships_company_id"), "company_memberships", ["company_id"],
        unique=False,
    )

    op.create_table(
        "honeypot_companies",
        sa.Column("honeypot_id", sa.Uuid(), nullable=False),
        sa.Column("company_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["honeypot_id"], ["honeypots.id"],
            name=op.f("fk_honeypot_companies_honeypot_id_honeypots"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["company_id"], ["companies.id"],
            name=op.f("fk_honeypot_companies_company_id_companies"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("honeypot_id", "company_id", name=op.f("pk_honeypot_companies")),
    )

    # --- Backfill from the old single-company columns, before dropping them ---
    op.execute(
        """
        INSERT INTO company_memberships (id, user_id, company_id, access_level, created_at)
        SELECT gen_random_uuid(), id, company_id, access_level, now()
        FROM users
        WHERE company_id IS NOT NULL AND access_level IS NOT NULL
        """
    )
    op.execute(
        """
        INSERT INTO honeypot_companies (honeypot_id, company_id)
        SELECT id, company_id FROM honeypots WHERE company_id IS NOT NULL
        """
    )

    # --- Drop the old single-company columns/constraints ---
    op.drop_constraint(op.f("ck_users_superadmin_xor_company_scope"), "users", type_="check")
    op.drop_constraint(op.f("fk_users_company_id_companies"), "users", type_="foreignkey")
    op.drop_column("users", "company_id")
    op.drop_column("users", "access_level")

    op.drop_index(op.f("ix_honeypots_company_id"), table_name="honeypots")
    op.drop_constraint(op.f("fk_honeypots_company_id_companies"), "honeypots", type_="foreignkey")
    op.drop_column("honeypots", "company_id")

    op.drop_index(op.f("ix_honeypot_events_company_id"), table_name="honeypot_events")
    op.drop_constraint(
        op.f("fk_honeypot_events_company_id_companies"), "honeypot_events", type_="foreignkey"
    )
    op.drop_column("honeypot_events", "company_id")


def downgrade() -> None:
    # One-way in practice (a user/honeypot with 0 or 2+ memberships has no
    # single value to collapse back to) — restores the old shape and
    # backfills from each row's *first* membership only, best-effort.
    op.add_column("honeypot_events", sa.Column("company_id", sa.Uuid(), nullable=True))
    op.add_column("honeypots", sa.Column("company_id", sa.Uuid(), nullable=True))
    op.add_column("users", sa.Column("company_id", sa.Uuid(), nullable=True))
    op.add_column(
        "users",
        sa.Column(
            "access_level",
            postgresql.ENUM("read", "read_write", name="access_level", create_type=False),
            nullable=True,
        ),
    )

    op.execute(
        """
        UPDATE users u
        SET company_id = m.company_id, access_level = m.access_level
        FROM (
            SELECT DISTINCT ON (user_id) user_id, company_id, access_level
            FROM company_memberships
            ORDER BY user_id, created_at
        ) m
        WHERE m.user_id = u.id
        """
    )
    op.execute(
        """
        UPDATE honeypots h
        SET company_id = c.company_id
        FROM (
            SELECT DISTINCT ON (honeypot_id) honeypot_id, company_id
            FROM honeypot_companies
        ) c
        WHERE c.honeypot_id = h.id
        """
    )
    op.execute("DELETE FROM honeypots WHERE company_id IS NULL")
    op.execute(
        """
        UPDATE honeypot_events e
        SET company_id = h.company_id
        FROM honeypots h
        WHERE h.id = e.honeypot_id
        """
    )
    op.execute("DELETE FROM honeypot_events WHERE company_id IS NULL")

    op.alter_column("honeypot_events", "company_id", nullable=False)
    op.alter_column("honeypots", "company_id", nullable=False)

    op.create_index(op.f("ix_honeypot_events_company_id"), "honeypot_events", ["company_id"])
    op.create_foreign_key(
        op.f("fk_honeypot_events_company_id_companies"),
        "honeypot_events", "companies", ["company_id"], ["id"], ondelete="CASCADE",
    )
    op.create_index(op.f("ix_honeypots_company_id"), "honeypots", ["company_id"])
    op.create_foreign_key(
        op.f("fk_honeypots_company_id_companies"),
        "honeypots", "companies", ["company_id"], ["id"], ondelete="CASCADE",
    )
    op.create_foreign_key(
        op.f("fk_users_company_id_companies"),
        "users", "companies", ["company_id"], ["id"], ondelete="RESTRICT",
    )
    op.create_check_constraint(
        "superadmin_xor_company_scope",
        "users",
        "(is_superadmin AND company_id IS NULL AND access_level IS NULL) "
        "OR (NOT is_superadmin AND company_id IS NOT NULL AND access_level IS NOT NULL)",
    )

    op.drop_table("honeypot_companies")
    op.drop_index(op.f("ix_company_memberships_company_id"), table_name="company_memberships")
    op.drop_index(op.f("ix_company_memberships_user_id"), table_name="company_memberships")
    op.drop_table("company_memberships")
