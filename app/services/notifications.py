"""Notifications: per-user, per-honeypot email alerts — "email me on
honeypot alerts", "email me when it goes unreachable (and when it's back)".

Deliberately much simpler than debcontrol's own Notifications (admin-
authored rules, role-targeted recipients, CPU/RAM/disk condition
thresholds, custom per-rule templates) — this app has no roles/groups at
all (see `app.db.models.user`'s module docstring), and the explicit
product decision behind this feature was self-service and flat: *any*
user, regardless of access level, manages their own subscriptions for any
honeypot they can see (`app.db.models.honeypot_notification_subscription
.HoneypotNotificationSubscription`, `app/web/routes/notifications.py`),
targeting their own account email or a manually-entered address
(`User.notification_target_email`). The only admin-configurable part is
the shared email wording (`AppSettings.notification_*_subject/body`,
Settings → Notifications, superadmin-only) — one global template per
event, not per rule.

Two trigger points, both fired from existing sweeps rather than a new
one:
- `app.tasks.jobs._poll_honeypot_canary_log` calls `notify_alert` once
  per newly ingested, non-internal `HoneypotEvent`.
- `app.tasks.jobs._ping_all_honeypots` calls `notify_unavailable` for
  every subscription on a honeypot whose reachability just changed (or
  is still down past that subscription's own debounce).

Every failure here — SMTP not configured, a recipient with no email set,
the relay itself refusing the connection — is caught and logged, never
raised: a notification that fails to send must never break the
background job that triggered it, the same "best-effort, never
load-bearing" spirit `app.audit_syslog.forward_to_syslog` already has for
the audit log's own external mirror.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from app.db.models.app_settings import AppSettings
from app.db.models.honeypot import Honeypot
from app.db.models.user import User
from app.i18n import DEFAULT_LOCALE_CODE
from app.services.smtp import SmtpNotConfiguredError, send_email

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


async def _send(app_settings: AppSettings, *, to_address: str, subject: str, body: str) -> None:
    try:
        await asyncio.to_thread(
            send_email, app_settings, to_address=to_address, subject=subject, body=body
        )
    except SmtpNotConfiguredError:
        logger.debug("Skipping notification email to %s: SMTP not configured", to_address)
    except Exception:
        logger.warning("Failed to send notification email to %s", to_address, exc_info=True)


async def notify_alert(
    db_app_settings: AppSettings,
    *,
    recipients: list[User],
    honeypot: Honeypot,
    event_type: str,
    event_label: str,
    src_ip: str | None,
    occurred_at: datetime,
) -> None:
    """Email every subscribed, addressable recipient about one newly
    ingested OpenCanary event. `recipients` should already be filtered to
    users with `notify_on_alert=True` for this honeypot — see
    `app.tasks.jobs._poll_honeypot_canary_log`."""
    if not db_app_settings.smtp_enabled:
        return
    context = {
        "honeypot_name": honeypot.name,
        "event_type": event_label,
        "src_ip": src_ip or "?",
        "timestamp": occurred_at.isoformat(),
        "details": "",
    }
    subject, body = render_template("alert", db_app_settings, context)
    for user in recipients:
        target = user.notification_target_email
        if not target:
            continue
        await _send(db_app_settings, to_address=target, subject=subject, body=body)


async def notify_unavailable(
    db_app_settings: AppSettings,
    *,
    user: User,
    honeypot: Honeypot,
    threshold_minutes: int,
) -> None:
    """Email one subscriber that `honeypot` has been unreachable for at
    least `threshold_minutes` — see `app.tasks.jobs._ping_all_honeypots`
    for the debounce/transition logic that decides when to call this."""
    if not db_app_settings.smtp_enabled:
        return
    target = user.notification_target_email
    if not target:
        return
    context = {
        "honeypot_name": honeypot.name,
        "threshold_minutes": threshold_minutes,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    subject, body = render_template("unavailable", db_app_settings, context)
    await _send(db_app_settings, to_address=target, subject=subject, body=body)


async def notify_recovered(
    db_app_settings: AppSettings,
    *,
    user: User,
    honeypot: Honeypot,
) -> None:
    """Email one subscriber that `honeypot` is reachable again, after
    previously being unreachable — only called for a subscription that
    actually received the matching `notify_unavailable` email first (see
    `app.tasks.jobs._ping_all_honeypots`)."""
    if not db_app_settings.smtp_enabled:
        return
    target = user.notification_target_email
    if not target:
        return
    context = {"honeypot_name": honeypot.name, "timestamp": datetime.now(UTC).isoformat()}
    subject, body = render_template("recovered", db_app_settings, context)
    await _send(db_app_settings, to_address=target, subject=subject, body=body)


__all__ = [
    "default_template",
    "notify_alert",
    "notify_recovered",
    "notify_unavailable",
    "render_template",
]
