"""Notifications: self-service, per-user, per-honeypot email preferences —
"email me on alerts", "email me when it goes unreachable." Deliberately
open to **any** logged-in user regardless of access level (not gated
behind `require_write`) — this only ever reads/writes that user's own
subscriptions, scoped to honeypots they can already see
(`app.auth.scope.honeypots_visible_to`), never anyone else's. See
`app.services.notifications`'s module docstring for the full design and
how this differs from debcontrol's own, much larger Notifications system.
"""

from __future__ import annotations

import uuid
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.auth.scope import can_see_honeypot, honeypots_visible_to
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_notification_subscription import HoneypotNotificationSubscription
from app.db.models.notification_log import NotificationChannel, NotificationLog
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.user import looks_like_email
from app.services.notifications import send_test_notification
from app.services.webhook import UnsafeWebhookTargetError, validate_webhook_url
from app.web.templating import templates

router = APIRouter(prefix="/account/notifications")

# Sane bounds for the per-subscription debounce field — generous on both
# ends (a minute is a legitimate "tell me the second it drops" choice for
# a critical honeypot; a week is a legitimate "only bug me if it's truly
# abandoned" choice for a flaky one).
_MIN_UNAVAILABLE_AFTER_MINUTES = 1
_MAX_UNAVAILABLE_AFTER_MINUTES = 10_080  # 7 days


async def _visible_honeypots(db: AsyncSession, user: User) -> list[Honeypot]:
    result = await db.execute(honeypots_visible_to(user).order_by(Honeypot.name))
    return list(result.scalars().all())


async def _own_subscriptions(
    db: AsyncSession, user_id: uuid.UUID
) -> dict[uuid.UUID, HoneypotNotificationSubscription]:
    result = await db.execute(
        select(HoneypotNotificationSubscription).where(
            HoneypotNotificationSubscription.user_id == user_id
        )
    )
    return {sub.honeypot_id: sub for sub in result.scalars().all()}


@router.get("")
async def list_notification_subscriptions(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    saved: str = "",
    test_sent: str = "",
    test_error: str = "",
) -> Response:
    user = await db.get(User, current_user.id)
    assert user is not None
    honeypots = await _visible_honeypots(db, user)
    subscriptions = await _own_subscriptions(db, user.id)

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "notifications/list.html",
        {
            "user": user,
            "honeypots": honeypots,
            "subscriptions": subscriptions,
            "min_minutes": _MIN_UNAVAILABLE_AFTER_MINUTES,
            "max_minutes": _MAX_UNAVAILABLE_AFTER_MINUTES,
            "csrf_token": csrf_token,
            "saved": bool(saved),
            "test_sent": bool(test_sent),
            "test_error": test_error or None,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/email", dependencies=[Depends(verify_csrf)])
async def update_notification_email(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    form = await request.form()
    notification_email = str(form.get("notification_email") or "").strip()
    if notification_email and not looks_like_email(notification_email):
        honeypots = await _visible_honeypots(db, current_user)
        subscriptions = await _own_subscriptions(db, current_user.id)
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "notifications/list.html",
            {
                "user": current_user,
                "honeypots": honeypots,
                "subscriptions": subscriptions,
                "min_minutes": _MIN_UNAVAILABLE_AFTER_MINUTES,
                "max_minutes": _MAX_UNAVAILABLE_AFTER_MINUTES,
                "csrf_token": csrf_token,
                "saved": False,
                "errors": ["That doesn't look like a valid email address."],
            },
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    user = await db.get(User, current_user.id)
    assert user is not None
    user.notification_email = notification_email or None
    await db.commit()
    await log_event(
        db,
        request=request,
        action="user.notifications.email.update",
        summary=f'"{user.username}" updated their notification email',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return RedirectResponse(
        url="/account/notifications?saved=1", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("", dependencies=[Depends(verify_csrf)])
async def update_notification_subscriptions(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Saves every subscription row at once from the single page's form —
    one `alert_{id}`/`unavailable_{id}`/`minutes_{id}` triplet of fields
    per honeypot the user can see. A honeypot with neither box checked
    gets its row deleted rather than kept around as an all-`False` no-op,
    so this table only ever holds subscriptions someone actually wants."""
    user = await db.get(User, current_user.id)
    assert user is not None
    honeypots = await _visible_honeypots(db, user)
    existing = await _own_subscriptions(db, user.id)

    form = await request.form()
    changed_count = 0
    errors: list[str] = []
    for honeypot in honeypots:
        key = str(honeypot.id)
        wants_alert = form.get(f"alert_{key}") == "on"
        wants_unavailable = form.get(f"unavailable_{key}") == "on"
        raw_minutes = str(form.get(f"minutes_{key}") or "").strip()
        try:
            minutes = int(raw_minutes) if raw_minutes else 10
        except ValueError:
            minutes = 10
        minutes = max(_MIN_UNAVAILABLE_AFTER_MINUTES, min(minutes, _MAX_UNAVAILABLE_AFTER_MINUTES))

        sub = existing.get(honeypot.id)
        if not wants_alert and not wants_unavailable:
            if sub is not None:
                await db.delete(sub)
                changed_count += 1
            continue

        raw_channel = str(form.get(f"channel_{key}") or "email").strip().lower()
        channel = (
            NotificationChannel.WEBHOOK
            if raw_channel == "webhook"
            else NotificationChannel.EMAIL
        )
        webhook_url = str(form.get(f"webhook_{key}") or "").strip() or None
        if channel == NotificationChannel.WEBHOOK:
            if not webhook_url:
                errors.append(
                    f'"{honeypot.name}": a webhook URL is required when the channel is webhook.'
                )
                continue
            try:
                validate_webhook_url(webhook_url)
            except UnsafeWebhookTargetError as exc:
                errors.append(f'"{honeypot.name}": {exc}')
                continue

        if sub is None:
            sub = HoneypotNotificationSubscription(user_id=user.id, honeypot_id=honeypot.id)
            db.add(sub)
        sub.notify_on_alert = wants_alert
        sub.notify_on_unavailable = wants_unavailable
        sub.unavailable_after_minutes = minutes
        sub.delivery_channel = channel
        sub.webhook_url = webhook_url
        if not wants_unavailable:
            sub.unavailable_notified_at = None
        changed_count += 1

    if errors:
        # Deliberately no explicit `db.rollback()` here: nothing has been
        # committed yet, and rolling back would expire every attribute on
        # `user` (SQLAlchemy's default post-rollback behavior) — the
        # template's own `user.email`/`user.notification_target_email`
        # access would then try to lazy-load outside an async-safe
        # context and raise `MissingGreenlet`. The request's own `db`
        # session is discarded uncommitted at teardown regardless (see
        # `app.db.session.get_db`).
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "notifications/list.html",
            {
                "user": user,
                "honeypots": honeypots,
                "subscriptions": existing,
                "min_minutes": _MIN_UNAVAILABLE_AFTER_MINUTES,
                "max_minutes": _MAX_UNAVAILABLE_AFTER_MINUTES,
                "csrf_token": csrf_token,
                "saved": False,
                "errors": errors,
            },
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    await db.commit()
    if changed_count:
        await log_event(
            db,
            request=request,
            action="user.notifications.subscriptions.update",
            summary=f'"{user.username}" updated their honeypot notification subscriptions',
            target_type="user",
            target_id=user.id,
            target_label=user.username,
        )
    return RedirectResponse(
        url="/account/notifications?saved=1", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/test/{honeypot_id}", dependencies=[Depends(verify_csrf)])
async def send_test(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """"Send test" button — fires one synthetic alert notification through
    the channel/target the submitted form's own row for this honeypot
    currently shows (so it tests what's about to be saved, unsaved changes
    included), falling back to the user's existing saved subscription for
    this honeypot, and finally to their plain resolved email if neither
    applies. Out-of-scope (a honeypot this user can't see, or that no
    longer exists) 404s rather than leaking existence, same as every other
    honeypot-scoped route — see `app.auth.scope`'s module docstring."""
    user = await db.get(User, current_user.id)
    assert user is not None
    honeypot = await db.get(Honeypot, honeypot_id)
    if honeypot is None or not can_see_honeypot(user, honeypot):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    form = await request.form()
    key = str(honeypot_id)
    raw_channel = str(form.get(f"channel_{key}") or "").strip().lower()
    webhook_url = str(form.get(f"webhook_{key}") or "").strip() or None
    existing = (await _own_subscriptions(db, user.id)).get(honeypot_id)

    channel: NotificationChannel
    target: str | None
    if raw_channel == "webhook" and webhook_url:
        channel, target = NotificationChannel.WEBHOOK, webhook_url
    elif raw_channel == "email":
        channel, target = NotificationChannel.EMAIL, user.notification_target_email
    elif existing is not None:
        channel = existing.delivery_channel
        target = (
            existing.webhook_url
            if channel == NotificationChannel.WEBHOOK
            else user.notification_target_email
        )
    else:
        channel, target = NotificationChannel.EMAIL, user.notification_target_email

    error: str | None
    if not target:
        error = "No email address or webhook URL is set for this honeypot."
    else:
        app_settings = await get_or_create_app_settings(db)
        error = await send_test_notification(
            db, app_settings, user=user, honeypot=honeypot, channel=channel, target=target
        )

    query = "test_sent=1" if not error else f"test_error={quote(error, safe='')}"
    return RedirectResponse(
        url=f"/account/notifications?{query}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/history")
async def notification_history(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The current user's own last 200 notification send attempts (real or
    test) — never another user's, since this whole feature has no
    admin/superadmin gate (see this module's docstring)."""
    result = await db.execute(
        select(NotificationLog)
        .where(NotificationLog.user_id == current_user.id)
        .order_by(NotificationLog.created_at.desc())
        .limit(200)
    )
    entries = list(result.scalars().all())
    return templates.TemplateResponse(request, "notifications/history.html", {"entries": entries})
