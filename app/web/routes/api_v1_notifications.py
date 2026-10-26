"""REST API for the token owner's own notification rules and delivery
history — mirrors `app/web/routes/notifications.py`.

Same rules as the web page: open to every account whatever its access
level, only ever the caller's own rules (someone else's rule is a 404),
and the companies/honeypots a rule names must be ones the caller may see.
Validation is the web form's own (`_parse_rule_form`/`_authorize_scope`),
so the two can never disagree on what a valid rule is. The channel token
is write-only: a response says whether one is stored (`has_channel_token`),
never what it is, and leaving it out of an update keeps the stored one.
"""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.datastructures import FormData, UploadFile

from app.audit import log_event
from app.auth.dependencies import get_api_token_user
from app.core.app_settings import get_or_create_app_settings
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.notification_log import NotificationChannel, NotificationLog
from app.db.models.notification_rule import NotificationRule
from app.db.models.user import User
from app.db.session import get_db
from app.services.notifications import resolve_target, send_test_notification
from app.services.opencanary_logtypes import alert_logtypes, logtype_label
from app.web.routes.notifications import (
    _authorize_scope,
    _get_own_rule,
    _parse_rule_form,
    _representative_honeypot,
)

router = APIRouter(prefix="/api/v1/notifications")

_HISTORY_LIMIT = 200


class NotificationRuleSave(BaseModel):
    """One rule, as `POST`/`PUT` take it. `scope` picks which of
    `company_ids`/`honeypot_ids` counts (the other is ignored). An empty
    `alert_event_types` means every alert type; `null` wording fields use
    the built-in text in the owner's language."""

    name: str = Field(min_length=1, max_length=255)
    scope: Literal["company", "honeypot"]
    company_ids: list[uuid.UUID] = Field(default_factory=list)
    honeypot_ids: list[uuid.UUID] = Field(default_factory=list)
    delivery_channel: NotificationChannel = NotificationChannel.EMAIL
    target_email: str | None = None
    webhook_url: str | None = None
    channel_token: str | None = Field(
        default=None, description="Write-only; leave out on update to keep the stored one."
    )
    channel_recipient: str | None = None
    notify_on_alert: bool = False
    alert_event_types: list[str] = Field(default_factory=list)
    alert_throttle_minutes: int | None = None
    notify_on_unavailable: bool = False
    unavailable_after_minutes: int = 10
    notify_on_recovered: bool = False
    recovered_after_minutes: int = 5
    notify_on_disk_full: bool = False
    notify_on_service_failed: bool = False
    notify_on_reboot_required: bool = False
    notify_on_file_changed: bool = False
    notify_on_warranty_ending: bool = False
    warranty_notice_days: int = 60
    alert_subject: str | None = None
    alert_body: str | None = None
    unavailable_subject: str | None = None
    unavailable_body: str | None = None
    recovered_subject: str | None = None
    recovered_body: str | None = None


_FLAGS = (
    "notify_on_alert",
    "notify_on_unavailable",
    "notify_on_recovered",
    "notify_on_disk_full",
    "notify_on_service_failed",
    "notify_on_reboot_required",
    "notify_on_file_changed",
    "notify_on_warranty_ending",
)
_TEXTS = (
    "name",
    "target_email",
    "webhook_url",
    "channel_token",
    "channel_recipient",
    "alert_subject",
    "alert_body",
    "unavailable_subject",
    "unavailable_body",
    "recovered_subject",
    "recovered_body",
)


def _as_form(payload: NotificationRuleSave) -> FormData:
    """The payload as the web form would post it, for `_parse_rule_form`."""
    items: list[tuple[str, str | UploadFile]] = [
        ("scope", payload.scope),
        ("delivery_channel", payload.delivery_channel.value),
        ("unavailable_after_minutes", str(payload.unavailable_after_minutes)),
        ("recovered_after_minutes", str(payload.recovered_after_minutes)),
        ("warranty_notice_days", str(payload.warranty_notice_days)),
        (
            "alert_throttle_minutes",
            "" if payload.alert_throttle_minutes is None else str(payload.alert_throttle_minutes),
        ),
    ]
    items += [(field, getattr(payload, field) or "") for field in _TEXTS]
    items += [(field, "on") for field in _FLAGS if getattr(payload, field)]
    items += [("company_ids", str(i)) for i in payload.company_ids]
    items += [("honeypot_ids", str(i)) for i in payload.honeypot_ids]
    items += [("alert_event_types", value) for value in payload.alert_event_types]
    return FormData(items)


def _rule_to_dict(rule: NotificationRule) -> dict[str, object]:
    return {
        "id": str(rule.id),
        "name": rule.name,
        "scope": rule.scope.value,
        "company_ids": [str(c.id) for c in rule.companies],
        "honeypot_ids": [str(h.id) for h in rule.honeypots],
        "delivery_channel": rule.delivery_channel.value,
        "target_email": rule.target_email,
        "webhook_url": rule.webhook_url,
        "has_channel_token": rule.channel_token_encrypted is not None,
        "channel_recipient": rule.channel_recipient,
        "notify_on_alert": rule.notify_on_alert,
        "alert_event_types": rule.alert_event_types or [],
        "alert_throttle_minutes": rule.alert_throttle_minutes,
        "notify_on_unavailable": rule.notify_on_unavailable,
        "unavailable_after_minutes": rule.unavailable_after_minutes,
        "notify_on_recovered": rule.notify_on_recovered,
        "recovered_after_minutes": rule.recovered_after_minutes,
        "notify_on_disk_full": rule.notify_on_disk_full,
        "notify_on_service_failed": rule.notify_on_service_failed,
        "notify_on_reboot_required": rule.notify_on_reboot_required,
        "notify_on_file_changed": rule.notify_on_file_changed,
        "notify_on_warranty_ending": rule.notify_on_warranty_ending,
        "warranty_notice_days": rule.warranty_notice_days,
        "alert_subject": rule.alert_subject,
        "alert_body": rule.alert_body,
        "unavailable_subject": rule.unavailable_subject,
        "unavailable_body": rule.unavailable_body,
        "recovered_subject": rule.recovered_subject,
        "recovered_body": rule.recovered_body,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
    }


async def _validated(
    db: AsyncSession, user: User, payload: NotificationRuleSave, *, has_token: bool
) -> tuple[dict[str, object], list[Company], list[Honeypot]]:
    values, company_ids, honeypot_ids, errors = _parse_rule_form(
        _as_form(payload), has_token=has_token
    )
    if errors:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=errors)
    companies, honeypots, errors = await _authorize_scope(db, user, company_ids, honeypot_ids)
    if errors:
        # Not visible to this account: the same 404 as any other
        # out-of-scope id, never a hint that it exists.
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=errors)
    return values, companies, honeypots


@router.get("/alert-types")
async def list_alert_types_api(
    user: User = Depends(get_api_token_user),
) -> list[dict[str, str]]:
    """The OpenCanary alert types a rule's `alert_event_types` can name."""
    return [{"value": value, "label": logtype_label(value)} for value in alert_logtypes()]


@router.get("/rules")
async def list_notification_rules_api(
    db: AsyncSession = Depends(get_db), user: User = Depends(get_api_token_user)
) -> list[dict[str, object]]:
    """The token owner's own rules, by name."""
    result = await db.execute(
        select(NotificationRule)
        .where(NotificationRule.user_id == user.id)
        .order_by(NotificationRule.name)
    )
    return [_rule_to_dict(rule) for rule in result.scalars()]


@router.post("/rules", status_code=status.HTTP_201_CREATED)
async def create_notification_rule_api(
    request: Request,
    payload: NotificationRuleSave,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    values, companies, honeypots = await _validated(db, user, payload, has_token=False)
    rule = NotificationRule(user_id=user.id, companies=companies, honeypots=honeypots, **values)
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    await log_event(
        db,
        request=request,
        action="user.notifications.rule.create",
        summary=f'"{user.username}" created notification rule "{rule.name}"',
        target_type="notification_rule",
        target_id=rule.id,
        target_label=rule.name,
    )
    return _rule_to_dict(rule)


@router.get("/rules/{rule_id}")
async def get_notification_rule_api(
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    return _rule_to_dict(await _get_own_rule(db, user, rule_id))


@router.put("/rules/{rule_id}")
async def update_notification_rule_api(
    request: Request,
    rule_id: uuid.UUID,
    payload: NotificationRuleSave,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Replaces the whole rule (a field left out takes its default), except
    `channel_token`, which is kept when left out."""
    rule = await _get_own_rule(db, user, rule_id)
    values, companies, honeypots = await _validated(
        db, user, payload, has_token=rule.channel_token_encrypted is not None
    )
    for key, value in values.items():
        setattr(rule, key, value)
    rule.companies = companies
    rule.honeypots = honeypots
    await db.commit()
    await db.refresh(rule)
    await log_event(
        db,
        request=request,
        action="user.notifications.rule.update",
        summary=f'"{user.username}" updated notification rule "{rule.name}"',
        target_type="notification_rule",
        target_id=rule.id,
        target_label=rule.name,
    )
    return _rule_to_dict(rule)


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_notification_rule_api(
    request: Request,
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    rule = await _get_own_rule(db, user, rule_id)
    name = rule.name
    await db.delete(rule)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="user.notifications.rule.delete",
        summary=f'"{user.username}" deleted notification rule "{name}"',
        target_type="notification_rule",
        target_id=rule_id,
        target_label=name,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/rules/{rule_id}/test")
async def send_test_notification_api(
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """"Send test": one made-up alert through the rule's channel, about a
    real honeypot in its scope. `sent` is false with the reason in `error`
    when it could not be delivered."""
    rule = await _get_own_rule(db, user, rule_id, with_user=True)
    honeypot = await _representative_honeypot(db, rule)
    error: str | None
    if honeypot is None:
        error = "That company has no honeypot yet to send a test notification for."
    elif not resolve_target(rule):
        error = "No destination (email address, URL or recipient) is set for this rule."
    else:
        app_settings = await get_or_create_app_settings(db)
        error = await send_test_notification(
            db,
            app_settings,
            rule=rule,
            honeypot=honeypot,
            channel=rule.delivery_channel,
            target=resolve_target(rule) or "",
        )
    return {"sent": error is None, "error": error}


@router.get("/history")
async def notification_history_api(
    db: AsyncSession = Depends(get_db), user: User = Depends(get_api_token_user)
) -> list[dict[str, object]]:
    """The token owner's own last 200 send attempts, newest first — real
    and test, delivered, failed or muted by a maintenance window."""
    result = await db.execute(
        select(NotificationLog)
        .where(NotificationLog.user_id == user.id)
        .order_by(NotificationLog.created_at.desc())
        .limit(_HISTORY_LIMIT)
    )
    return [
        {
            "id": str(entry.id),
            "created_at": entry.created_at.isoformat(),
            "kind": entry.kind.value,
            "channel": entry.channel.value,
            "target": entry.target,
            "honeypot_id": str(entry.honeypot_id) if entry.honeypot_id else None,
            "honeypot_name": entry.honeypot_name,
            "success": entry.success,
            "error": entry.error,
            "is_test": entry.is_test,
            "muted_by": entry.muted_by,
        }
        for entry in result.scalars()
    ]

