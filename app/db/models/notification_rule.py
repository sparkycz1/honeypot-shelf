"""`NotificationRule` — a named, self-service alert a user sets up for
any number of `Company`/`Honeypot` rows they can see. Open to **any**
logged-in user regardless of access level, same as the feature it
replaces (`HoneypotNotificationSubscription`) — see
`app.web.routes.notifications`'s module docstring.

**Scope**: `scope` says which *kind* of target this rule holds — every
row in `companies` (a `COMPANY`-scoped rule) or every row in `honeypots`
(a `HONEYPOT`-scoped rule), never a mix of both, never zero (see
`app.db.models.notification_rule_scope` for the two plain link tables
this is built on) — a superadmin can add any company/honeypot, anyone
else only ones they already have access to (see `app.auth.scope`). Each
company-scoped target applies to every honeypot currently in that company
(re-resolved on every sweep — adding a honeypot to the company covers it
automatically, no rule edit needed) plus, unlike a plain per-honeypot
subscription, needs its own **per-honeypot** debounce state, since a
company can hold many honeypots that each go up/down independently — see
`NotificationRuleState`.

**Delivery**: `delivery_channel` picks email (default) or a webhook POST
(`app.services.webhook`, SSRF-guarded — see that module's docstring, since
a webhook URL here is entered by any user, not just an admin). For email,
`target_email` overrides the rule owner's own account email (`User.email`)
when set; left `None` it just uses that. For webhook, `webhook_url` is
required.

**Events and their wording**: each of the three kinds (`notify_on_alert`,
`notify_on_unavailable`, `notify_on_recovered`) can be toggled
independently. `unavailable_after_minutes`/`recovered_after_minutes` are
this rule's own debounce thresholds (not a global setting) — how long a
honeypot must be continuously unreachable before "it's down" fires, and
how long it must be continuously reachable again before "it's back"
fires (so one flapping blip doesn't immediately claim recovery).

Wording is per-rule, not instance-wide (there used to be a single
superadmin-edited template per event, Settings → Notifications — removed
in favor of this): `{kind}_subject`/`{kind}_body` (`alert_*`,
`unavailable_*`, `recovered_*`) hold this rule's own override, `None`
meaning "use the built-in default" — rendered in the rule *owner's own
current* `User.locale` at send time, not whatever locale was active when
the rule was created, so translating the UI later also updates the
default text a still-uncustomized rule sends. See
`app.services.notifications.render_template`.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.notification_log import NotificationChannel
from app.db.models.notification_rule_scope import (
    notification_rule_companies,
    notification_rule_honeypots,
)
from app.db.pg_enum import pg_enum

if TYPE_CHECKING:
    from app.db.models.company import Company
    from app.db.models.honeypot import Honeypot
    from app.db.models.user import User

# Sane bounds for the debounce fields — generous on both ends (a minute is
# a legitimate "tell me the second it drops" choice for a critical
# honeypot; a week is a legitimate "only bug me if it's truly abandoned/
# only count it recovered once it's clearly stable" choice for a flaky
# one). Enforced in the web route, not here — a bare DB column has no
# CHECK constraint for this, same convention as every other bounded
# integer setting in this app.
MIN_DEBOUNCE_MINUTES = 1
MAX_DEBOUNCE_MINUTES = 10_080  # 7 days


class NotificationScope(enum.StrEnum):
    COMPANY = "company"
    HONEYPOT = "honeypot"


class NotificationRule(Base):
    __tablename__ = "notification_rules"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    scope: Mapped[NotificationScope] = mapped_column(
        pg_enum(NotificationScope, name="notification_scope"), nullable=False
    )

    delivery_channel: Mapped[NotificationChannel] = mapped_column(
        pg_enum(NotificationChannel, name="notification_channel"),
        default=NotificationChannel.EMAIL,
        nullable=False,
    )
    target_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    webhook_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    notify_on_alert: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notify_on_unavailable: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    unavailable_after_minutes: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    notify_on_recovered: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    recovered_after_minutes: Mapped[int] = mapped_column(Integer, default=5, nullable=False)

    # Per-rule wording override, one (subject, body) pair per event kind —
    # `None` means "use the built-in default, in this rule's owner's
    # current UI language" (see `app.services.notifications.
    # render_template`). Replaces the old instance-wide, superadmin-only
    # template (Settings → Notifications).
    alert_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    alert_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    unavailable_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    unavailable_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    recovered_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    recovered_body: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    user: Mapped[User] = relationship(back_populates="notification_rules")
    companies: Mapped[list[Company]] = relationship(
        secondary=notification_rule_companies, order_by="Company.name", lazy="selectin"
    )
    honeypots: Mapped[list[Honeypot]] = relationship(
        secondary=notification_rule_honeypots, order_by="Honeypot.name", lazy="selectin"
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"NotificationRule(id={self.id!r}, name={self.name!r}, scope={self.scope!r})"
