"""Notifications: named, self-service alert rules — "tell me about alerts
on this company/honeypot", "tell me when it goes unreachable (and when
it's back)", by email or webhook.

Deliberately much simpler than debcontrol's own Notifications (admin-
authored rules, role-targeted recipients, CPU/RAM/disk condition
thresholds) — this app has no roles/groups at all (see
`app.db.models.user`'s module docstring), and the explicit product
decision behind this feature was self-service and flat: *any* user,
regardless of access level, creates their own named `NotificationRule`s
(`app.db.models.notification_rule`, `app/web/routes/notifications.py`),
each scoped to either a `Company` or a single `Honeypot` they can already
see, targeting their own account email (or a manually-entered override),
or a webhook URL instead (`NotificationRule.delivery_channel`/
`target_email`/`webhook_url` — see `app.services.webhook`, SSRF-guarded
since any user can set one). Wording is per-rule too
(`NotificationRule.{kind}_subject`/`{kind}_body`) — there used to be a
single superadmin-edited template per event (Settings → Notifications);
removed in favor of a per-rule override, defaulting to built-in text
rendered in the rule owner's own current UI language — see
`render_template`.

Two trigger points, both fired from existing sweeps rather than a new
one:
- `app.tasks.jobs._poll_honeypot_canary_log` calls `notify_alert` once
  per newly ingested, non-internal `HoneypotEvent`, for every rule that
  matches that honeypot (directly, or via its company).
- `app.tasks.jobs._ping_all_honeypots` calls `notify_unavailable`/
  `notify_recovered` for every (rule, honeypot) pair whose debounce
  threshold (`NotificationRule.unavailable_after_minutes`/
  `recovered_after_minutes`) has just been crossed — see
  `app.db.models.notification_rule_state` for the state machine.

Every failure here — SMTP/webhook not configured or reachable, a
recipient with no email set, the relay itself refusing the connection —
is caught and logged (both to the app log and to `NotificationLog`),
never raised: a notification that fails to send must never break the
background job that triggered it, the same "best-effort, never
load-bearing" spirit `app.audit_syslog.forward_to_syslog` already has for
the audit log's own external mirror.
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
from app.i18n import DEFAULT_LOCALE_CODE
from app.services.live_updates import publish_notifications_event
from app.services.smtp import SmtpNotConfiguredError, send_email
from app.services.webhook import UnsafeWebhookTargetError, send_webhook

if TYPE_CHECKING:
    from app.db.models.notification_rule import NotificationRule

logger = logging.getLogger(__name__)

# Built-in (subject, body) used whenever a rule hasn't overridden one of
# its own `{kind}_subject`/`{kind}_body` fields — also what the rule
# form shows as a placeholder/starting point. Keyed by locale code (same
# codes as `app.i18n`); a locale with no entry falls back to English.
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
            "{honeypot_name} has been reachable again for at least "
            "{threshold_minutes} minute(s) as of {timestamp}, after previously "
            "being unreachable.",
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
            "{honeypot_name} je opět dostupný nejméně {threshold_minutes} minut, "
            "stav k {timestamp}, poté co byl nedostupný.",
        ),
    },
}


class _SafeDict(dict[str, str]):
    """Used with `str.format_map` so a placeholder a user-edited template
    doesn't recognize (a typo, or a context key this event type doesn't
    provide) is left as literal text instead of raising `KeyError` and
    losing the whole notification."""

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def default_template(kind: str, locale: str = DEFAULT_LOCALE_CODE) -> tuple[str, str]:
    """The built-in (subject, body) for `kind` ("alert"/"unavailable"/
    "recovered") in `locale` — used whenever a rule doesn't override it,
    and as the rule form's own placeholder text."""
    return _DEFAULT_TEMPLATES.get(locale, _DEFAULT_TEMPLATES[DEFAULT_LOCALE_CODE])[kind]


def render_template(kind: str, rule: NotificationRule, context: dict[str, Any]) -> tuple[str, str]:
    """Subject and body for one notification, substituting `{placeholder}`
    values from `context` — plain `str.format_map`, not a template engine,
    so a user-edited body can never execute code or reach outside its own
    string. `rule`'s own `{kind}_subject`/`{kind}_body` win when set;
    otherwise the built-in default, rendered in the rule *owner's*
    current `User.locale` (`rule.user` must already be loaded) — so a
    still-uncustomized rule's wording follows its owner's UI language,
    not whatever was active when the rule was created. Missing
    placeholders are left as literal text rather than raising."""
    subject_tpl = getattr(rule, f"{kind}_subject", None)
    body_tpl = getattr(rule, f"{kind}_body", None)
    if subject_tpl is None or body_tpl is None:
        default_subject, default_body = default_template(
            kind, rule.user.locale or DEFAULT_LOCALE_CODE
        )
        subject_tpl = subject_tpl or default_subject
        body_tpl = body_tpl or default_body
    safe_context = _SafeDict({k: "" if v is None else str(v) for k, v in context.items()})
    return subject_tpl.format_map(safe_context), body_tpl.format_map(safe_context)


def resolve_target(rule: NotificationRule) -> str | None:
    """Where `rule` actually sends to: its own `webhook_url` for a webhook
    rule; for an email rule, `target_email` (the rule's own override) if
    set, else the owning user's own account email — `None` if there's
    nowhere to send yet. `rule.user` must already be loaded (selectinload)."""
    if rule.delivery_channel == NotificationChannel.WEBHOOK:
        return rule.webhook_url
    return rule.target_email or rule.user.email


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
    sites share one caller-managed session across several sends) and a
    logging failure must never mask the send outcome it's trying to
    record, so this never raises."""
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
        await publish_notifications_event(str(user_id))
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


async def _dispatch_rule(
    db_app_settings: AppSettings,
    db: AsyncSession | None,
    *,
    rule: NotificationRule,
    honeypot: Honeypot,
    kind: NotificationKind,
    template_kind: str,
    context: dict[str, Any],
    webhook_payload: dict[str, Any],
) -> None:
    channel = rule.delivery_channel
    target = resolve_target(rule)
    if not target:
        return
    if channel == NotificationChannel.EMAIL and not db_app_settings.smtp_enabled:
        return
    subject, body = render_template(template_kind, rule, context)
    await _deliver(
        db_app_settings,
        db,
        user_id=rule.user_id,
        honeypot=honeypot,
        kind=kind,
        channel=channel,
        target=target,
        subject=subject,
        body=body,
        webhook_payload=webhook_payload,
    )


async def notify_alert(
    db_app_settings: AppSettings,
    *,
    rules: list[NotificationRule],
    honeypot: Honeypot,
    event_type: str,
    event_label: str,
    src_ip: str | None,
    occurred_at: datetime,
    db: AsyncSession | None = None,
) -> None:
    """Notify every matching rule about one newly ingested OpenCanary
    event. `rules` should already be filtered to `notify_on_alert=True`
    and scoped to this honeypot (directly, or via its company) — see
    `app.tasks.jobs._poll_honeypot_canary_log`. Each rule's own `user`
    relationship must already be loaded (selectinload) — wording is
    rendered per rule, since each can have its own override/locale."""
    context = {
        "honeypot_name": honeypot.name,
        "event_type": event_label,
        "src_ip": src_ip or "?",
        "timestamp": occurred_at.isoformat(),
        "details": "",
    }
    webhook_payload = {
        "kind": "alert",
        "honeypot_id": str(honeypot.id),
        "honeypot_name": honeypot.name,
        "event_type": event_type,
        "src_ip": src_ip,
        "occurred_at": occurred_at.isoformat(),
    }
    for rule in rules:
        await _dispatch_rule(
            db_app_settings,
            db,
            rule=rule,
            honeypot=honeypot,
            kind=NotificationKind.ALERT,
            template_kind="alert",
            context=context,
            webhook_payload=webhook_payload,
        )


async def notify_unavailable(
    db_app_settings: AppSettings,
    *,
    rule: NotificationRule,
    honeypot: Honeypot,
    threshold_minutes: int,
    db: AsyncSession | None = None,
) -> None:
    """Notify one rule's target that `honeypot` has been unreachable for
    at least `threshold_minutes` — see
    `app.tasks.jobs._evaluate_unavailability_notifications` for the
    debounce/transition logic that decides when to call this."""
    context = {
        "honeypot_name": honeypot.name,
        "threshold_minutes": threshold_minutes,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    webhook_payload = {
        "kind": "unavailable",
        "honeypot_id": str(honeypot.id),
        "honeypot_name": honeypot.name,
        "threshold_minutes": threshold_minutes,
        "timestamp": context["timestamp"],
    }
    await _dispatch_rule(
        db_app_settings,
        db,
        rule=rule,
        honeypot=honeypot,
        kind=NotificationKind.UNAVAILABLE,
        template_kind="unavailable",
        context=context,
        webhook_payload=webhook_payload,
    )


async def notify_recovered(
    db_app_settings: AppSettings,
    *,
    rule: NotificationRule,
    honeypot: Honeypot,
    threshold_minutes: int,
    db: AsyncSession | None = None,
) -> None:
    """Notify one rule's target that `honeypot` has been reachable again
    for at least `threshold_minutes`, after previously being unreachable —
    only called for a (rule, honeypot) pair that actually had a matching
    `notify_unavailable` notification sent first (see
    `app.tasks.jobs._evaluate_unavailability_notifications`)."""
    context = {
        "honeypot_name": honeypot.name,
        "threshold_minutes": threshold_minutes,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    webhook_payload = {
        "kind": "recovered",
        "honeypot_id": str(honeypot.id),
        "honeypot_name": honeypot.name,
        "threshold_minutes": threshold_minutes,
        "timestamp": context["timestamp"],
    }
    await _dispatch_rule(
        db_app_settings,
        db,
        rule=rule,
        honeypot=honeypot,
        kind=NotificationKind.RECOVERED,
        template_kind="recovered",
        context=context,
        webhook_payload=webhook_payload,
    )


async def send_test_notification(
    db: AsyncSession,
    db_app_settings: AppSettings,
    *,
    rule: NotificationRule,
    honeypot: Honeypot,
    channel: NotificationChannel,
    target: str,
) -> str | None:
    """Fire one synthetic "alert" notification through `channel` straight
    to `target`, bypassing rule matching entirely — the "Send test"
    button on a rule's own row. Uses `rule`'s own alert wording (or its
    owner's language default) same as a real alert would. Returns `None`
    on success, or a short error string on failure (also always logged to
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
    subject, body = render_template("alert", rule, context)
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
        user_id=rule.user_id,
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
    "resolve_target",
    "send_test_notification",
]
