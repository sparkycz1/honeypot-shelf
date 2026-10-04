"""Per-(`NotificationRule`, `Honeypot`) unavailable/recovered debounce
state — the reason this is a separate table rather than two columns on
`NotificationRule` itself (which is how the single-honeypot predecessor,
`HoneypotNotificationSubscription`, did it): a company-scoped rule covers
every honeypot in that company, and each one goes up/down independently,
so "have we already sent the 'it's down' notification for the *current*
outage" has to be tracked per honeypot, not once per rule. A honeypot-
scoped rule just ends up with exactly one state row.

State machine (see `app.tasks.jobs._evaluate_unavailability_notifications`
for where this is actually driven):

- `unavailable_notified_at` is set the moment "it's down" is sent for the
  current outage (once `Honeypot.unreachable_since` has aged past the
  rule's own `unavailable_after_minutes`), and cleared back to `None` the
  moment the honeypot is reachable again — so one continuous outage past
  the threshold sends at most one "it's down" notification, and the next
  outage can trigger a fresh one.
- `recovered_notified_at` is set the moment "it's back" is sent (once
  `Honeypot.reachable_since` has aged past the rule's own
  `recovered_after_minutes` — only when a "down" notification had
  actually gone out for this outage, `unavailable_notified_at` was set
  right before it was cleared), and cleared back to `None` the moment the
  honeypot goes unreachable again, ready for the next outage/recovery
  cycle.
- `alert_notified_at` / `alerts_held_back` are the rule's alert throttle
  window for this honeypot (`app.services.notifications.notify_alert`).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Integer, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class NotificationRuleState(Base):
    __tablename__ = "notification_rule_states"
    __table_args__ = (
        UniqueConstraint("rule_id", "honeypot_id", name="uq_notification_rule_state_rule_honeypot"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("notification_rules.id", ondelete="CASCADE"), nullable=False, index=True
    )
    honeypot_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    unavailable_notified_at: Mapped[datetime | None] = mapped_column(nullable=True)
    recovered_notified_at: Mapped[datetime | None] = mapped_column(nullable=True)
    # The rule's alert throttle window for this honeypot: when the last
    # alert notification went out, and how many alerts were held back
    # since (see `NotificationRule.alert_throttle_minutes`).
    alert_notified_at: Mapped[datetime | None] = mapped_column(nullable=True)
    alerts_held_back: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )

    rule: Mapped[NotificationRule] = relationship()
    honeypot: Mapped[Honeypot] = relationship()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"NotificationRuleState(rule_id={self.rule_id!r}, honeypot_id={self.honeypot_id!r})"
        )


# Imported last, and only for type checking: every class above is already
# defined by the time this module points back at the models it relates
# to, so no import cycle can leave a class half-defined (CodeQL's
# "Module-level cyclic import"). SQLAlchemy resolves the relationship
# targets by name through its registry, never through these imports.
if TYPE_CHECKING:
    from app.db.models.honeypot import Honeypot
    from app.db.models.notification_rule import NotificationRule
