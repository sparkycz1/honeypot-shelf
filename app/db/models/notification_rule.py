"""`NotificationRule` — a named, self-service alert a user sets up for
either an entire `Company` they can see, or a single `Honeypot`. Open to
**any** logged-in user regardless of access level, same as the feature it
replaces (`HoneypotNotificationSubscription`) — see
`app.web.routes.notifications`'s module docstring.

**Scope**: exactly one of `company_id`/`honeypot_id` is set (`scope` says
which), never both, never neither — a superadmin can scope to any company/
honeypot, anyone else only to one they already have access to (see
`app.auth.scope`). A company-scoped rule applies to every honeypot
currently in that company (re-resolved on every sweep — adding a honeypot
to the company covers it automatically, no rule edit needed) plus, unlike
a plain per-honeypot subscription, needs its own **per-honeypot** debounce
state, since a company can hold many honeypots that each go up/down
independently — see `NotificationRuleState`.

**Delivery**: `delivery_channel` picks email (default) or a webhook POST
(`app.services.webhook`, SSRF-guarded — see that module's docstring, since
a webhook URL here is entered by any user, not just an admin). For email,
`target_email` overrides the rule owner's own resolved address
(`User.notification_target_email`) when set; left `None` it just uses
that. For webhook, `webhook_url` is required.

**Events**: each of the three kinds (`notify_on_alert`,
`notify_on_unavailable`, `notify_on_recovered`) can be toggled
independently; the shared instance-wide template per kind
(`AppSettings.notification_*_subject/body`, Settings → Notifications,
superadmin-only) is what actually gets sent — see
`app.services.notifications`. `unavailable_after_minutes`/
`recovered_after_minutes` are this rule's own debounce thresholds (not a
global setting) — how long a honeypot must be continuously unreachable
before "it's down" fires, and how long it must be continuously reachable
again before "it's back" fires (so one flapping blip doesn't immediately
claim recovery).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.notification_log import NotificationChannel
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
    company_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("companies.id", ondelete="CASCADE"), nullable=True, index=True
    )
    honeypot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=True, index=True
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

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    user: Mapped[User] = relationship(back_populates="notification_rules")
    company: Mapped[Company | None] = relationship()
    honeypot: Mapped[Honeypot | None] = relationship()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"NotificationRule(id={self.id!r}, name={self.name!r}, scope={self.scope!r})"
