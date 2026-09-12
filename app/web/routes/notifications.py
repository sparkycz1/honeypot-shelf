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

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.auth.scope import honeypots_visible_to
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_notification_subscription import HoneypotNotificationSubscription
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.user import looks_like_email
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

        if sub is None:
            sub = HoneypotNotificationSubscription(user_id=user.id, honeypot_id=honeypot.id)
            db.add(sub)
        sub.notify_on_alert = wants_alert
        sub.notify_on_unavailable = wants_unavailable
        sub.unavailable_after_minutes = minutes
        if not wants_unavailable:
            sub.unavailable_notified_at = None
        changed_count += 1

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
