"""One row per actual Notifications send attempt (real or "Send test"),
success or failure — `app.services.notifications` writes one here every
time it tries to deliver an alert/unavailable/recovered email or webhook.

Ported from an identical debcontrol feature (`NotificationLog`), adapted
for this app's much simpler self-service subscription model: there is no
`NotificationRule` here, so each row is tied to the `(user, honeypot)`
subscription it came from instead of a rule id, and — since Notifications
here has no admin/superadmin gate at all (see
`app.web.routes.notifications`'s module docstring) — a user can only ever
see *their own* send history, never anyone else's
(`GET /account/notifications/history`).

Purged on its own configurable retention
(`AppSettings.notification_log_retention_days`), same convention as every
other retention setting in this app (`app.tasks.jobs.
purge_old_notification_logs`).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.pg_enum import pg_enum

if TYPE_CHECKING:
    from app.db.models.honeypot import Honeypot
    from app.db.models.user import User


class NotificationKind(enum.StrEnum):
    ALERT = "alert"
    UNAVAILABLE = "unavailable"
    RECOVERED = "recovered"
    TEST = "test"


class NotificationChannel(enum.StrEnum):
    EMAIL = "email"
    WEBHOOK = "webhook"


class NotificationLog(Base):
    __tablename__ = "notification_logs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    honeypot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("honeypots.id", ondelete="SET NULL"), nullable=True, index=True
    )
    kind: Mapped[NotificationKind] = mapped_column(
        pg_enum(NotificationKind, name="notification_kind"), nullable=False
    )
    channel: Mapped[NotificationChannel] = mapped_column(
        pg_enum(NotificationChannel, name="notification_channel"), nullable=False
    )
    # The email address or webhook URL this attempt was sent to — kept even
    # if the subscription/user is later deleted or changed, so a past log
    # entry still shows what actually happened at send time.
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Fired via the "Send test" button rather than a real event/outage —
    # kept in the same log (so "did my webhook actually work" is
    # answerable from one place) but flagged, never mixed up with a real
    # delivery in the UI.
    is_test: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # honeypot_name is denormalized (kept even after honeypot_id goes NULL
    # on delete) for the same "history stays readable" reason as `target`
    # above — a purged/deleted honeypot's past notifications shouldn't turn
    # into blank rows.
    honeypot_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    user: Mapped[User] = relationship()
    honeypot: Mapped[Honeypot | None] = relationship()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"NotificationLog(user_id={self.user_id!r}, kind={self.kind!r}, "
            f"channel={self.channel!r}, success={self.success!r})"
        )
