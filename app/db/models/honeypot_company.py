"""The `Honeypot` ↔ `Company` association: a plain many-to-many link table,
no columns of its own. A honeypot can belong to any number of companies —
including zero (an unassigned honeypot, visible only to a superadmin) —
unlike `CompanyMembership` (`app.db.models.company_membership`), which
carries a per-row `access_level` and so needs to be a real model, this one
doesn't, so it's a plain `Table` used as a relationship's `secondary=`.

Replaces the old `Honeypot.company_id` (a required single FK) — see
`app.db.models.honeypot`/`app.db.models.company` for the relationships
built on top of this, and `app.auth.scope` for how it's queried.
"""

from __future__ import annotations

from sqlalchemy import Column, ForeignKey, Table

from app.db.base import Base

honeypot_companies = Table(
    "honeypot_companies",
    Base.metadata,
    Column(
        "honeypot_id", ForeignKey("honeypots.id", ondelete="CASCADE"), primary_key=True
    ),
    Column(
        "company_id", ForeignKey("companies.id", ondelete="CASCADE"), primary_key=True
    ),
)
