"""Notifications: per-user, per-honeypot email/webhook alerts — "email me
on honeypot alerts", "email me when it goes unreachable (and when it's
back)", or send either to a webhook instead.

Deliberately much simpler than debcontrol's own Notifications (admin-
authored rules, role-targeted recipients, CPU/RAM/disk condition
thresholds, custom per-rule templates) — this app has no roles/groups at
all (see `app.db.models.user`'s module docstring), and the explicit
product decision behind this feature was self-service and flat: *any*
user, regardless of access level, manages their own subscriptions for any
honeypot they can see (`app.db.models.honeypot_notification_subscription
.HoneypotNotificationSubscription`, `app/web/routes/notifications.py`),
targeting their own account email or a manually-entered address
(`User.notification_target_email`) — or, per-subscription, a webhook URL
instead (`HoneypotNotificationSubscription.delivery_channel`/
`webhook_url` — see `app.services.webhook`, ported from an identical
debcontrol feature). The only admin-configurable part is the shared email
wording (`AppSettings.notification_*_subject/body`, Settings →
Notifications, superadmin-only) — one global template per event, not per
rule; a webhook payload carries the same fields as plain JSON instead.

Two trigger points, both fired from existing sweeps rather than a new
one:
- `app.tasks.jobs._poll_honeypot_canary_log` calls `notify_alert` once
  per newly ingested, non-internal `HoneypotEvent`.
- `app.tasks.jobs._ping_all_honeypots` calls `notify_unavailable`/
  `notify_recovered` for every subscription on a honeypot whose
  reachability just changed (or is still down past that subscription's
  own debounce).

Every failure here — SMTP/webhook not configured or reachable, a
recipient with no email set, the relay itself refusing the connection —
is caught and logged (both to the app log and, since the debcontrol-
ported webhook/history round, to `NotificationLog`), never raised: a
notification that fails to send must never break the background job that
triggered it, the same "best-effort, never load-bearing" spirit
`app.audit_syslog.forward_to_syslog` already has for the audit log's own
external mirror.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.app_settings import AppSettings
from app.db.models.honeypot import Honeypot
from app.db.models.notification_log import NotificationChannel, NotificationKind, NotificationLog
from app.db.models.user import User
from app.i18n import DEFAULT_LOCALE_CODE
from app.services.smtp import SmtpNotConfiguredError, send_email
from app.services.webhook import UnsafeWebhookTargetError, send_webhook

if TYPE_CHECKING:
    from app.db.models.honeypot_notification_subscription import (
        HoneypotNotificationSubscription,
    )

logger = logging.getLogger(__name__)

# Built-in (subject, body) used whenever an admin hasn't overridden one of
# `AppSettings.notification_*_subject`/`_body` — also what the Settings →
# Notifications page shows as a placeholder/starting point, and what
# "Reset to default" puts back. Keyed by locale code (same codes as
# `app.i18n`); a locale with no entry falls back to English. Unlike
# debcontrol's per-recipient-locale rendering, these are rendered once in
# a fixed *server* locale (see `render_template`) since there's exactly
# one shared template per event here, not a per-rule one an admin already
# writes in their own language — see this module's own docstring for why
# recipient-locale rendering wasn't ported.
_DEFAULT_TEMPLATES: dict[str, dict[str, tuple[str, str]]] = {
    "en": {
        "alert": (
            "Honeypot Shelf: new alert on {honeypot_name}",
            "{honeypot_name} logged a new {event_type} alert at {timestamp} "
            "(source: {src_ip}).\n\n{details}",
        ),
        "unavailable": (
            "Honeypot Shelf: {honeypot_name} is unreachable",
            "{honeypot_name} has been unreachable for at least {threshold_minutes} "
            "minute(s) as of {timestamp}.",
        ),
        "recovered": (
            "Honeypot Shelf: {honeypot_name} is reachable again",
            "{honeypot_name} responded to a reachability check again at {timestamp}, "
            "after previously being unreachable.",
        ),
    },
    "cs": {
        "alert": (
            "Honeypot Shelf: nový alert na {honeypot_name}",
            "{honeypot_name} zaznamenal nový alert typu {event_type} v {timestamp} "
            "(zdroj: {src_ip}).\n\n{details}",
        ),
        "unavailable": (
            "Honeypot Shelf: {honeypot_name} je nedostupný",
            "{honeypot_name} je nedostupný nejméně {threshold_minutes} minut, "
            "stav k {timestamp}.",
        ),
        "recovered": (
            "Honeypot Shelf: {honeypot_name} je opět dostupný",
            "{honeypot_name} znovu reagoval na kontrolu dostupnosti v {timestamp}, "
            "poté co byl nedostupný.",
        ),
    },
}


class _SafeDict(dict[str, str]):
    """Used with `str.format_map` so a placeholder an admin-edited template
    doesn't recognize (a typo, or a context key this event type doesn't
    provide) is left as literal text instead of raising `KeyError` and
    losing the whole notification."""

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def default_template(kind: str, locale: str = DEFAULT_LOCALE_CODE) -> tuple[str, str]:
    """The built-in (subject, body) for `kind` ("alert"/"unavailable"/
    "recovered") in `locale` — used whenever `AppSettings` doesn't
    override it, and as the Settings page's own placeholder text."""
    return _DEFAULT_TEMPLATES.get(locale, _DEFAULT_TEMPLATES[DEFAULT_LOCALE_CODE])[kind]


def render_template(
    kind: str, app_settings: AppSettings, context: dict[str, Any]
) -> tuple[str, str]:
    """Subject and body for one notification, substituting `{placeholder}`
    values from `context` — plain `str.format_map`, not a template engine,
    so an admin-edited body can never execute code or reach outside its
    own string. Missing placeholders are left as literal text rather than
    raising."""
    subject_tpl = getattr(app_settings, f"notification_{kind}_subject", None)
    body_tpl = getattr(app_settings, f"notification_{kind}_body", None)
    if subject_tpl is None or body_tpl is None:
        default_subject, default_body = default_template(kind)
        subject_tpl = subject_tpl or default_subject
        body_tpl = body_tpl or default_body
    safe_context = _SafeDict({k: "" if v is None else str(v) for k, v in context.items()})
    return subject_tpl.format_map(safe_context), body_tpl.format_map(safe_context)


async def _log(
    db: AsyncSession | None,
    *,
    user_id: Any,
    honeypot: Honeypot | None,
    kind: NotificationKind,
    channel: NotificationChannel,
    target: str,
    success: bool,
    error: str | None,
    is_test: bool = False,
) -> None:
    """Best-effort `NotificationLog` write — `db` is optional (some call
    sites, like `notify_alert`'s per-event loop, share one caller-managed
    session across several sends) and a logging failure must never mask
    the send outcome it's trying to record, so this never raises."""
    if db is None:
        return
    try:
        db.add(
            NotificationLog(
                user_id=user_id,
                honeypot_id=honeypot.id if honeypot else None,
                honeypot_name=honeypot.name if honeypot else None,
                kind=kind,
                channel=channel,
                target=target,
                success=success,
                error=error,
                is_test=is_test,
            )
        )
        await db.commit()
    except Exception:
        logger.warning("Failed to write NotificationLog", exc_info=True)


async def _deliver(
    app_settings: AppSettings,
    db: AsyncSession | None,
    *,
    user_id: Any,
    honeypot: Honeypot | None,
    kind: NotificationKind,
    channel: NotificationChannel,
    target: str,
    subject: str,
    body: str,
    webhook_payload: dict[str, Any],
    is_test: bool = False,
) -> None:
    """Send one notification through `channel` and log the outcome —
    the single choke point every public `notify_*`/`send_test_notification`
    function in this module funnels through."""
    error: str | None = None
    success = False
    try:
        if channel == NotificationChannel.WEBHOOK:
            await asyncio.to_thread(send_webhook, target, webhook_payload)
        else:
            await asyncio.to_thread(
                send_email, app_settings, to_address=target, subject=subject, body=body
            )
        success = True
    except SmtpNotConfiguredError:
        logger.debug("Skipping notification email to %s: SMTP not configured", target)
        error = "SMTP not configured"
    except UnsafeWebhookTargetError as exc:
        logger.warning("Refusing unsafe webhook target %s: %s", target, exc)
        error = str(exc)
    except Exception as exc:
        logger.warning("Failed to send %s notification to %s", channel.value, target, exc_info=True)
        error = str(exc) or exc.__class__.__name__
    await _log(
        db,
        user_id=user_id,
        honeypot=honeypot,
        kind=kind,
        channel=channel,
        target=target,
        success=success,
        error=error,
        is_test=is_test,
    )


async def notify_alert(
    db_app_settings: AppSettings,
    *,
    subscriptions: list[HoneypotNotificationSubscription],
    honeypot: Honeypot,
    event_type: str,
    event_label: str,
    src_ip: str | None,
    occurred_at: datetime,
    db: AsyncSession | None = None,
) -> None:
    """Notify every subscribed, addressable recipient about one newly
    ingested OpenCanary event. `subscriptions` should already be filtered
    to `notify_on_alert=True` for this honeypot — see
    `app.tasks.jobs._poll_honeypot_canary_log`."""
    email_context = {
        "honeypot_name": honeypot.name,
        "event_type": event_label,
        "src_ip": src_ip or "?",
        "timestamp": occurred_at.isoformat(),
        "details": "",
    }
    subject, body = render_template("alert", db_app_settings, email_context)
    webhook_payload = {
        "kind": "alert",
        "honeypot_id": str(honeypot.id),
        "honeypot_name": honeypot.name,
        "event_type": event_type,
        "src_ip": src_ip,
        "occurred_at": occurred_at.isoformat(),
    }
    for sub in subscriptions:
        if sub.delivery_channel == NotificationChannel.WEBHOOK:
            if not sub.webhook_url:
                continue
            await _deliver(
                db_app_settings,
                db,
                user_id=sub.user_id,
                honeypot=honeypot,
                kind=NotificationKind.ALERT,
                channel=NotificationChannel.WEBHOOK,
                target=sub.webhook_url,
                subject=subject,
                body=body,
                webhook_payload=webhook_payload,
            )
            continue
        if not db_app_settings.smtp_enabled:
            continue
        target = sub.user.notification_target_email
        if not target:
            continue
        await _deliver(
            db_app_settings,
            db,
            user_id=sub.user_id,
            honeypot=honeypot,
            kind=NotificationKind.ALERT,
            channel=NotificationChannel.EMAIL,
            target=target,
            subject=subject,
            body=body,
            webhook_payload=webhook_payload,
        )


async def notify_unavailable(
    db_app_settings: AppSettings,
    *,
    subscription: HoneypotNotificationSubscription,
    honeypot: Honeypot,
    threshold_minutes: int,
    db: AsyncSession | None = None,
) -> None:
    """Notify one subscriber that `honeypot` has been unreachable for at
    least `threshold_minutes` — see `app.tasks.jobs._ping_all_honeypots`
    for the debounce/transition logic that decides when to call this."""
    email_context = {
        "honeypot_name": honeypot.name,
        "threshold_minutes": threshold_minutes,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    subject, body = render_template("unavailable", db_app_settings, email_context)
    webhook_payload = {
        "kind": "unavailable",
        "honeypot_id": str(honeypot.id),
        "honeypot_name": honeypot.name,
        "threshold_minutes": threshold_minutes,
        "timestamp": email_context["timestamp"],
    }
    await _dispatch_subscription(
        db_app_settings,
        db,
        subscription=subscription,
        honeypot=honeypot,
        kind=NotificationKind.UNAVAILABLE,
        subject=subject,
        body=body,
        webhook_payload=webhook_payload,
    )


async def notify_recovered(
    db_app_settings: AppSettings,
    *,
    subscription: HoneypotNotificationSubscription,
    honeypot: Honeypot,
    db: AsyncSession | None = None,
) -> None:
    """Notify one subscriber that `honeypot` is reachable again, after
    previously being unreachable — only called for a subscription that
    actually received the matching `notify_unavailable` notification first
    (see `app.tasks.jobs._ping_all_honeypots`)."""
    email_context = {"honeypot_name": honeypot.name, "timestamp": datetime.now(UTC).isoformat()}
    subject, body = render_template("recovered", db_app_settings, email_context)
    webhook_payload = {
        "kind": "recovered",
        "honeypot_id": str(honeypot.id),
        "honeypot_name": honeypot.name,
        "timestamp": email_context["timestamp"],
    }
    await _dispatch_subscription(
        db_app_settings,
        db,
        subscription=subscription,
        honeypot=honeypot,
        kind=NotificationKind.RECOVERED,
        subject=subject,
        body=body,
        webhook_payload=webhook_payload,
    )


async def _dispatch_subscription(
    db_app_settings: AppSettings,
    db: AsyncSession | None,
    *,
    subscription: HoneypotNotificationSubscription,
    honeypot: Honeypot,
    kind: NotificationKind,
    subject: str,
    body: str,
    webhook_payload: dict[str, Any],
) -> None:
    if subscription.delivery_channel == NotificationChannel.WEBHOOK:
        if not subscription.webhook_url:
            return
        await _deliver(
            db_app_settings,
            db,
            user_id=subscription.user_id,
            honeypot=honeypot,
            kind=kind,
            channel=NotificationChannel.WEBHOOK,
            target=subscription.webhook_url,
            subject=subject,
            body=body,
            webhook_payload=webhook_payload,
        )
        return
    if not db_app_settings.smtp_enabled:
        return
    target = subscription.user.notification_target_email
    if not target:
        return
    await _deliver(
        db_app_settings,
        db,
        user_id=subscription.user_id,
        honeypot=honeypot,
        kind=kind,
        channel=NotificationChannel.EMAIL,
        target=target,
        subject=subject,
        body=body,
        webhook_payload=webhook_payload,
    )


async def send_test_notification(
    db: AsyncSession,
    db_app_settings: AppSettings,
    *,
    user: User,
    honeypot: Honeypot,
    channel: NotificationChannel,
    target: str,
) -> str | None:
    """Fire one synthetic "alert" notification through `channel` straight
    to `target`, bypassing any subscription/recipient list — the "Send
    test" button on the Notifications page. Returns `None` on success, or
    a short error string on failure (also always logged to
    `NotificationLog` with `is_test=True`, same as a real send). Unlike a
    real alert, this ignores `AppSettings.smtp_enabled` for an email
    target too — if SMTP isn't configured at all, `send_email` itself
    raises `SmtpNotConfiguredError`, which is exactly the useful "no, it
    isn't set up" result this button exists to surface."""
    context = {
        "honeypot_name": honeypot.name,
        "event_type": "test",
        "src_ip": "203.0.113.1",
        "timestamp": datetime.now(UTC).isoformat(),
        "details": "This is a test notification sent from Honeypot Shelf.",
    }
    subject, body = render_template("alert", db_app_settings, context)
    webhook_payload = {
        "kind": "test",
        "honeypot_id": str(honeypot.id),
        "honeypot_name": honeypot.name,
        "sent_at": context["timestamp"],
    }
    error: str | None = None
    success = False
    try:
        if channel == NotificationChannel.WEBHOOK:
            await asyncio.to_thread(send_webhook, target, webhook_payload)
        else:
            await asyncio.to_thread(
                send_email, db_app_settings, to_address=target, subject=subject, body=body
            )
        success = True
    except (SmtpNotConfiguredError, UnsafeWebhookTargetError) as exc:
        error = str(exc)
    except Exception as exc:
        logger.warning("Test notification to %s failed", target, exc_info=True)
        error = str(exc) or exc.__class__.__name__
    await _log(
        db,
        user_id=user.id,
        honeypot=honeypot,
        kind=NotificationKind.TEST,
        channel=channel,
        target=target,
        success=success,
        error=error,
        is_test=True,
    )
    return error


__all__ = [
    "default_template",
    "notify_alert",
    "notify_recovered",
    "notify_unavailable",
    "render_template",
    "send_test_notification",
]
