"""A `User`'s notification preference for one `Honeypot` — "email me on
alerts", "email me when it goes unreachable (and when it comes back)".

Self-service, per (user, honeypot) — any user, regardless of access
level, manages their own row for any honeypot they can see (see
`app.web.routes.notifications`); there is no admin approval step and no
role/permission gate beyond ordinary company scoping. This is deliberately
much simpler than debcontrol's own `NotificationRule` (admin-authored,
role-targeted, condition-based) — see `app.services.notifications`'s
module docstring for the full reasoning behind that difference.

Where the email actually goes: `User.notification_email` if set,
otherwise `User.email` — see `User.notification_target_email`. A user
with neither set simply can't receive a notification yet; the account/
honeypot subscription UI both surface that plainly rather than silently
dropping it.

**Unavailability debounce**: `unavailable_after_minutes` is this row's
own threshold, not a global one — one user might want to know the
instant a honeypot drops, another might only care after it's been down
for an hour (a flaky home connection, say). `unavailable_notified_at`
tracks whether *this subscription* already sent the "it's down" email
for the *current* outage — set when that email goes out, cleared back
to `None` once the honeypot is reachable again (whether or not a
"back online" email is also sent), so a single continuous outage past
the threshold only ever sends one "it's down" email, not one per
reachability sweep. See `app.tasks.jobs._ping_all_honeypots`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Integer, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.honeypot import Honeypot
    from app.db.models.user import User


class HoneypotNotificationSubscription(Base):
    __tablename__ = "honeypot_notification_subscriptions"
    __table_args__ = (
        UniqueConstraint(
            "user_id", "honeypot_id", name="uq_honeypot_notification_subscription_user_honeypot"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    honeypot_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=False, index=True
    )

    user: Mapped[User] = relationship(back_populates="notification_subscriptions")
    honeypot: Mapped[Honeypot] = relationship()

    # Email on every new OpenCanary alert ingested for this honeypot (see
    # app.tasks.jobs._poll_honeypot_canary_log) — one email per event, no
    # batching/digest, matching the simplified spec this feature was built
    # to (debcontrol's own condition/threshold engine was deliberately not
    # ported — see app.services.notifications's module docstring).
    notify_on_alert: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Email when this honeypot goes unreachable for at least
    # `unavailable_after_minutes`, and again when it's reachable once more
    # — see app.tasks.jobs._ping_all_honeypots.
    notify_on_unavailable: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    unavailable_after_minutes: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    unavailable_notified_at: Mapped[datetime | None] = mapped_column(nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"HoneypotNotificationSubscription(user_id={self.user_id!r}, "
            f"honeypot_id={self.honeypot_id!r})"
        )
