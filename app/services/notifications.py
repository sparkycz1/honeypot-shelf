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
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import DecryptionError, decrypt_secret
from app.db.models.app_settings import AppSettings
from app.db.models.honeypot import Honeypot
from app.db.models.notification_log import NotificationChannel, NotificationKind, NotificationLog
from app.db.models.notification_rule_state import NotificationRuleState
from app.i18n import DEFAULT_LOCALE_CODE
from app.services import acknowledgements, maintenance_windows, push_channels
from app.services.honeypot_status import as_aware_utc
from app.services.live_updates import publish_notifications_event
from app.services.smtp import SmtpNotConfiguredError, send_email
from app.services.webhook import UnsafeWebhookTargetError, redact_url, send_webhook

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
        "disk_full": (
            "Honeypot Shelf: {honeypot_name} is running out of disk space",
            "At the current rate these will soon be full on {honeypot_name}: {details}. "
            "As of {timestamp}.",
        ),
        "service_failed": (
            "Honeypot Shelf: a service failed on {honeypot_name}",
            "systemd units that failed on {honeypot_name}: {details}. As of {timestamp}.",
        ),
        "reboot_required": (
            "Honeypot Shelf: {honeypot_name} needs a reboot",
            "{honeypot_name} reports a reboot is pending after an update. As of {timestamp}.",
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
            "{honeypot_name} je nedostupný nejméně {threshold_minutes} minut, stav k {timestamp}.",
        ),
        "recovered": (
            "Honeypot Shelf: {honeypot_name} je opět dostupný",
            "{honeypot_name} je opět dostupný nejméně {threshold_minutes} minut, "
            "stav k {timestamp}, poté co byl nedostupný.",
        ),
        "disk_full": (
            "Honeypot Shelf: na {honeypot_name} dochází místo na disku",
            "Na {honeypot_name} se podle současného tempa brzy zaplní: {details}. "
            "Stav k {timestamp}.",
        ),
        "service_failed": (
            "Honeypot Shelf: na {honeypot_name} selhala služba",
            "Na {honeypot_name} selhaly služby systemd: {details}. Stav k {timestamp}.",
        ),
        "reboot_required": (
            "Honeypot Shelf: {honeypot_name} potřebuje restart",
            "{honeypot_name} hlásí, že po aktualizaci čeká na restart. Stav k {timestamp}.",
        ),
    },
}

# The `{details}` placeholder text "Send test" fills in on its synthetic
# alert (real alerts leave `details` blank — see `notify_alert`) — kept
# separate from `_DEFAULT_TEMPLATES` since it's not part of a rule's own
# overridable wording, just a fixed sentence explaining the email/webhook
# itself is a test. Keyed and looked up the same way (rule owner's own
# locale, falling back to the instance's `default_language`) so this
# doesn't end up English-only inside an otherwise-localized test send.
_TEST_DETAILS_TEXT: dict[str, str] = {
    "en": "This is a test notification sent from Honeypot Shelf.",
    "cs": "Toto je testovací notifikace odeslaná z Honeypot Shelf.",
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
    not whatever was active when the rule was created. A `None`
    `User.locale` (never explicitly set) falls back to the instance's own
    `default_language` setting, same as `request.state.locale` does for
    that user's actual page views (`app.auth.middleware`) — falling back
    to the hardcoded `DEFAULT_LOCALE_CODE` (English) here instead would
    silently ignore a non-English `default_language` and send every
    still-uncustomized rule's email in English regardless of the
    instance's configured language. Missing placeholders are left as
    literal text rather than raising."""
    subject_tpl = getattr(rule, f"{kind}_subject", None)
    body_tpl = getattr(rule, f"{kind}_body", None)
    if subject_tpl is None or body_tpl is None:
        default_subject, default_body = default_template(
            kind, rule.user.locale or get_settings().default_language
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
    channel = rule.delivery_channel.value
    if channel in push_channels.URL_CHANNELS:
        return rule.webhook_url
    if channel in push_channels.RECIPIENT_CHANNELS:
        return rule.channel_recipient
    return rule.target_email or rule.user.email


def rule_token(rule: NotificationRule) -> str | None:
    """A push rule's channel token, decrypted — `None` if it has none (or
    it can't be decrypted any more, which the send then reports)."""
    if rule.channel_token_encrypted is None:
        return None
    try:
        return decrypt_secret(rule.channel_token_encrypted)
    except DecryptionError:
        return None


async def _send_push(
    channel: NotificationChannel, target: str, *, token: str | None, subject: str, body: str
) -> tuple[str | None, str]:
    """(error or None, what the history shows as the target)."""
    url = target if channel.value in push_channels.URL_CHANNELS else None
    recipient = None if url else target
    error = await push_channels.send(
        channel.value, url=url, token=token, recipient=recipient, subject=subject, body=body
    )
    return error, push_channels.delivery_target(channel.value, url, recipient)


def _loggable(channel: NotificationChannel, target: str) -> str:
    """A target as it may appear in the server log: a webhook URL without
    its secret path, an email address as is."""
    return redact_url(target) if channel.value in push_channels.URL_CHANNELS else target


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
    muted_by: str | None = None,
) -> None:
    """Best-effort `NotificationLog` write — `db` is optional (some call
    sites share one caller-managed session across several sends) and a
    logging failure must never mask the send outcome it's trying to
    record, so this never raises."""
    if db is None:
        return
    if channel.value in push_channels.URL_CHANNELS:
        # The history keeps where a webhook went, never its secret path.
        shown = redact_url(target)
        error = error.replace(target, shown) if error else error
        target = shown
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
                muted_by=muted_by,
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
    token: str | None = None,
) -> None:
    """Send one notification through `channel` and log the outcome —
    the single choke point every public `notify_*`/`send_test_notification`
    function in this module funnels through."""
    error: str | None = None
    success = False
    if channel.value in push_channels.PUSH_CHANNELS:
        error, shown = await _send_push(channel, target, token=token, subject=subject, body=body)
        if error:
            logger.warning("Failed to send %s notification to %s: %s", channel.value, shown, error)
        await _log(
            db,
            user_id=user_id,
            honeypot=honeypot,
            kind=kind,
            channel=channel,
            target=shown,
            success=error is None,
            error=error,
            is_test=is_test,
        )
        return
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
        logger.warning("Refusing unsafe webhook target %s: %s", redact_url(target), exc)
        error = str(exc)
    except Exception as exc:
        logger.warning(
            "Failed to send %s notification to %s",
            channel.value,
            _loggable(channel, target),
            exc_info=True,
        )
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
    body_suffix: str = "",
) -> bool:
    """Send one rule's notification. False when nothing was attempted (no
    target, SMTP off, or muted by a maintenance window)."""
    channel = rule.delivery_channel
    target = resolve_target(rule)
    if not target:
        return False
    if channel == NotificationChannel.EMAIL and not db_app_settings.smtp_enabled:
        return False
    if db is not None:
        # A honeypot inside an active maintenance window: nothing is sent,
        # but the delivery history says so, naming the window.
        window = await maintenance_windows.muting_window(db, honeypot, kind)
        muted_by = window.name if window is not None else None
        if (
            muted_by is None
            and acknowledgements.withholds(kind)
            and acknowledgements.is_active(honeypot)
        ):
            # Someone acknowledged the problem: same treatment, own reason.
            muted_by = acknowledgements.muted_by(honeypot)
        if muted_by is not None:
            shown = (
                push_channels.delivery_target(
                    channel.value, rule.webhook_url, rule.channel_recipient
                )
                if channel.value in push_channels.PUSH_CHANNELS
                else target
            )
            await _log(
                db,
                user_id=rule.user_id,
                honeypot=honeypot,
                kind=kind,
                channel=channel,
                target=shown,
                success=False,
                error=None,
                muted_by=muted_by,
            )
            return False
    subject, body = render_template(template_kind, rule, context)
    body += body_suffix
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
        token=rule_token(rule),
    )
    return True


_HELD_BACK_NOTE = {
    "en": "{count} more alert(s) from this honeypot were held back since {since} (throttled).",
    "cs": "Od {since} bylo zadrženo {count} dalších alertů z tohoto honeypotu (tlumení).",
}


async def _alert_throttle_state(
    db: AsyncSession, rule: NotificationRule, honeypot: Honeypot
) -> NotificationRuleState:
    state = (
        await db.execute(
            select(NotificationRuleState).where(
                NotificationRuleState.rule_id == rule.id,
                NotificationRuleState.honeypot_id == honeypot.id,
            )
        )
    ).scalar_one_or_none()
    if state is None:
        state = NotificationRuleState(rule_id=rule.id, honeypot_id=honeypot.id, alerts_held_back=0)
        db.add(state)
    return state


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
    webhook_payload: dict[str, Any] = {
        "kind": "alert",
        "honeypot_id": str(honeypot.id),
        "honeypot_name": honeypot.name,
        "event_type": event_type,
        "src_ip": src_ip,
        "occurred_at": occurred_at.isoformat(),
    }
    now = datetime.now(UTC)
    for rule in rules:
        # The throttle window lives in the database; a caller without a
        # session (none today) simply isn't throttled.
        state: NotificationRuleState | None = None
        suffix = ""
        payload = webhook_payload
        if rule.alert_throttle_minutes and db is not None:
            state = await _alert_throttle_state(db, rule, honeypot)
            last = (
                as_aware_utc(state.alert_notified_at) if state.alert_notified_at else None
            )
            if last is not None and last > now - timedelta(minutes=rule.alert_throttle_minutes):
                state.alerts_held_back += 1
                await db.commit()
                continue
            if state.alerts_held_back and last is not None:
                locale = rule.user.locale or DEFAULT_LOCALE_CODE
                template = _HELD_BACK_NOTE.get(locale, _HELD_BACK_NOTE[DEFAULT_LOCALE_CODE])
                suffix = "\n\n" + template.format(
                    count=state.alerts_held_back, since=last.strftime("%Y-%m-%d %H:%M UTC")
                )
                payload = {**webhook_payload, "held_back": state.alerts_held_back}
        sent = await _dispatch_rule(
            db_app_settings,
            db,
            rule=rule,
            honeypot=honeypot,
            kind=NotificationKind.ALERT,
            template_kind="alert",
            context=context,
            webhook_payload=payload,
            body_suffix=suffix,
        )
        if sent and state is not None and db is not None:
            state.alert_notified_at = now
            state.alerts_held_back = 0
            await db.commit()


async def notify_health(
    db_app_settings: AppSettings,
    *,
    rules: list[NotificationRule],
    honeypot: Honeypot,
    kind: NotificationKind,
    details: str,
    db: AsyncSession | None = None,
) -> None:
    """Tell `rules` about a health problem that just appeared on `honeypot`
    (`kind` is DISK_FULL, SERVICE_FAILED or REBOOT_REQUIRED; `details` names
    the mounts or units). The caller decides *when* — see
    `app.tasks.jobs._announce_health`."""
    timestamp = datetime.now(UTC).isoformat()
    context = {"honeypot_name": honeypot.name, "details": details, "timestamp": timestamp}
    webhook_payload: dict[str, Any] = {
        "kind": kind.value,
        "honeypot_id": str(honeypot.id),
        "honeypot_name": honeypot.name,
        "details": details,
        "timestamp": timestamp,
    }
    for rule in rules:
        await _dispatch_rule(
            db_app_settings,
            db,
            rule=rule,
            honeypot=honeypot,
            kind=kind,
            template_kind=kind.value,
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
    locale = rule.user.locale or get_settings().default_language
    context = {
        "honeypot_name": honeypot.name,
        "event_type": "test",
        "src_ip": "203.0.113.1",
        "timestamp": datetime.now(UTC).isoformat(),
        "details": _TEST_DETAILS_TEXT.get(locale, _TEST_DETAILS_TEXT[DEFAULT_LOCALE_CODE]),
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
    if channel.value in push_channels.PUSH_CHANNELS:
        error, shown = await _send_push(
            channel, target, token=rule_token(rule), subject=subject, body=body
        )
        await _log(
            db,
            user_id=rule.user_id,
            honeypot=honeypot,
            kind=NotificationKind.TEST,
            channel=channel,
            target=shown,
            success=error is None,
            error=error,
            is_test=True,
        )
        return error
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
        logger.warning("Test notification to %s failed", _loggable(channel, target), exc_info=True)
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
    "rule_token",
    "send_test_notification",
]
