"""`NotificationRule` ↔ `Company`/`Honeypot`: two plain many-to-many link
tables, no columns of their own — same pattern as `honeypot_companies`
(`app.db.models.honeypot_company`). Replaces the old single, nullable
`NotificationRule.company_id`/`honeypot_id` columns: a rule's `scope`
still says which kind of target it holds (company or honeypot — never
both, never neither `Company`/`Honeypot` row), but now any number of
them, not just one — see `app.db.models.notification_rule`'s module
docstring.
"""

from __future__ import annotations

from sqlalchemy import Column, ForeignKey, Table

from app.db.base import Base

notification_rule_companies = Table(
    "notification_rule_companies",
    Base.metadata,
    Column("rule_id", ForeignKey("notification_rules.id", ondelete="CASCADE"), primary_key=True),
    Column("company_id", ForeignKey("companies.id", ondelete="CASCADE"), primary_key=True),
)

notification_rule_honeypots = Table(
    "notification_rule_honeypots",
    Base.metadata,
    Column("rule_id", ForeignKey("notification_rules.id", ondelete="CASCADE"), primary_key=True),
    Column("honeypot_id", ForeignKey("honeypots.id", ondelete="CASCADE"), primary_key=True),
)
