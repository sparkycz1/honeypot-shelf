"""Notifications: named, self-service alert rules — "tell me about alerts
on this company/honeypot", "tell me when it goes unreachable (and when
it's back)". Deliberately open to **any** logged-in user regardless of
access level (not gated behind `require_write`) — this only ever reads/
writes that user's own rules, scoped to a company or honeypot they can
already see (`app.auth.scope`), never anyone else's. See
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
from sqlalchemy.orm import selectinload
from starlette.datastructures import FormData

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.auth.scope import can_see_honeypot, companies_visible_to, honeypots_visible_to
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.notification_log import NotificationChannel, NotificationLog
from app.db.models.notification_rule import (
    MAX_DEBOUNCE_MINUTES,
    MIN_DEBOUNCE_MINUTES,
    NotificationRule,
    NotificationScope,
)
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.user import looks_like_email
from app.services.notifications import default_template, resolve_target, send_test_notification
from app.services.webhook import UnsafeWebhookTargetError, validate_webhook_url
from app.web.templating import templates

router = APIRouter(prefix="/account/notifications")


async def _visible_companies(db: AsyncSession, user: User) -> list[Company]:
    result = await db.execute(companies_visible_to(user).order_by(Company.name))
    return list(result.scalars().all())


async def _visible_honeypots(db: AsyncSession, user: User) -> list[Honeypot]:
    result = await db.execute(honeypots_visible_to(user).order_by(Honeypot.name))
    return list(result.scalars().all())


async def _own_rules(db: AsyncSession, user_id: uuid.UUID) -> list[NotificationRule]:
    # `companies`/`honeypots` are `lazy="selectin"` on the model itself, so
    # no explicit `.options()` is needed to avoid N+1 here.
    result = await db.execute(
        select(NotificationRule)
        .where(NotificationRule.user_id == user_id)
        .order_by(NotificationRule.name)
    )
    return list(result.scalars().all())


async def _get_own_rule(
    db: AsyncSession, user: User, rule_id: uuid.UUID, *, with_user: bool = False
) -> NotificationRule:
    """A rule owned by `user`, or a 404 — never leaks whether a rule with
    this id exists under a different owner (this feature has no admin
    override at all — see the module docstring). `with_user=True` eager-
    loads `rule.user` (needed by `resolve_target`) — skipped by default
    since most callers already know it's `user`."""
    options = [selectinload(NotificationRule.user)] if with_user else []
    rule = await db.get(NotificationRule, rule_id, options=options)
    if rule is None or rule.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return rule


async def _representative_honeypot(db: AsyncSession, rule: NotificationRule) -> Honeypot | None:
    """A real `Honeypot` to render a "Send test" preview against — the
    alphabetically-first of `rule.honeypots` for a honeypot-scoped rule, or
    the alphabetically-first honeypot currently in any of `rule.companies`
    for a company-scoped one (`None` if none of them has a honeypot yet)."""
    if rule.scope == NotificationScope.HONEYPOT:
        return rule.honeypots[0] if rule.honeypots else None
    company_ids = [company.id for company in rule.companies]
    if not company_ids:
        return None
    result = await db.execute(
        select(Honeypot)
        .where(Honeypot.companies.any(Company.id.in_(company_ids)))
        .order_by(Honeypot.name)
        .limit(1)
    )
    return result.scalars().first()


async def _render_list(
    request: Request,
    db: AsyncSession,
    user: User,
    *,
    saved: bool = False,
    test_sent: bool = False,
    test_error: str | None = None,
    errors: list[str] | None = None,
) -> Response:
    rules = await _own_rules(db, user.id)
    companies = await _visible_companies(db, user)
    honeypots = await _visible_honeypots(db, user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    template_defaults = {
        kind: default_template(kind, request.state.locale.code)
        for kind in ("alert", "unavailable", "recovered")
    }
    response = templates.TemplateResponse(
        request,
        "notifications/list.html",
        {
            "user": user,
            "rules": rules,
            "companies": companies,
            "honeypots": honeypots,
            "template_defaults": template_defaults,
            "min_minutes": MIN_DEBOUNCE_MINUTES,
            "max_minutes": MAX_DEBOUNCE_MINUTES,
            "csrf_token": csrf_token,
            "saved": saved,
            "test_sent": test_sent,
            "test_error": test_error,
            "errors": errors or [],
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("")
async def list_notification_rules(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    saved: str = "",
    test_sent: str = "",
    test_error: str = "",
) -> Response:
    user = await db.get(User, current_user.id)
    assert user is not None
    return await _render_list(
        request,
        db,
        user,
        saved=bool(saved),
        test_sent=bool(test_sent),
        test_error=test_error or None,
    )


def _parse_ids(form: FormData, field: str) -> tuple[list[uuid.UUID], bool]:
    """Every value submitted under `field` (a multi-select posts one
    form entry per selected `<option>`), parsed as a UUID — `(ids,
    all_valid)`, where `all_valid` is `False` if any submitted value
    wasn't a valid UUID (a stale form, or a tampered request)."""
    ids: list[uuid.UUID] = []
    all_valid = True
    for raw in form.getlist(field):
        raw = str(raw).strip()
        if not raw:
            continue
        try:
            ids.append(uuid.UUID(raw))
        except ValueError:
            all_valid = False
    return ids, all_valid


def _parse_rule_form(
    form: FormData,
) -> tuple[dict[str, object], list[uuid.UUID], list[uuid.UUID], list[str]]:
    """Shared parse/validate for both create and edit — returns a dict of
    plain column values ready to assign onto a `NotificationRule`, the
    submitted company/honeypot ids (kept separate since they're
    relationships, not plain columns — see `_authorize_scope`), and a list
    of human-readable errors (empty means valid)."""
    errors: list[str] = []
    get = form.get

    name = str(get("name") or "").strip()
    if not name:
        errors.append("Name is required.")

    raw_scope = str(get("scope") or "").strip().lower()
    scope = NotificationScope.COMPANY if raw_scope == "company" else NotificationScope.HONEYPOT
    company_ids, companies_valid = _parse_ids(form, "company_ids")
    honeypot_ids, honeypots_valid = _parse_ids(form, "honeypot_ids")
    if scope == NotificationScope.COMPANY:
        if not companies_valid:
            errors.append("Invalid company.")
        elif not company_ids:
            errors.append("Choose at least one company.")
        honeypot_ids = []
    else:
        if not honeypots_valid:
            errors.append("Invalid honeypot.")
        elif not honeypot_ids:
            errors.append("Choose at least one honeypot.")
        company_ids = []

    raw_channel = str(get("delivery_channel") or "").strip().lower()
    channel = (
        NotificationChannel.WEBHOOK if raw_channel == "webhook" else NotificationChannel.EMAIL
    )
    target_email = str(get("target_email") or "").strip() or None
    webhook_url = str(get("webhook_url") or "").strip() or None
    if channel == NotificationChannel.EMAIL:
        if target_email and not looks_like_email(target_email):
            errors.append("That doesn't look like a valid email address.")
        webhook_url = None
    else:
        if not webhook_url:
            errors.append("A webhook URL is required when the channel is webhook.")
        else:
            try:
                validate_webhook_url(webhook_url)
            except UnsafeWebhookTargetError as exc:
                errors.append(str(exc))
        target_email = None

    notify_on_alert = get("notify_on_alert") == "on"
    notify_on_unavailable = get("notify_on_unavailable") == "on"
    notify_on_recovered = get("notify_on_recovered") == "on"
    if not (notify_on_alert or notify_on_unavailable or notify_on_recovered):
        errors.append("Pick at least one event to notify on.")

    def _minutes(field: str, default: int) -> int:
        raw = str(get(field) or "").strip()
        try:
            value = int(raw) if raw else default
        except ValueError:
            value = default
        return max(MIN_DEBOUNCE_MINUTES, min(value, MAX_DEBOUNCE_MINUTES))

    unavailable_after_minutes = _minutes("unavailable_after_minutes", 10)
    recovered_after_minutes = _minutes("recovered_after_minutes", 5)

    def _text_override(field: str) -> str | None:
        return str(get(field) or "").strip() or None

    values: dict[str, object] = {
        "name": name,
        "scope": scope,
        "delivery_channel": channel,
        "target_email": target_email,
        "webhook_url": webhook_url,
        "notify_on_alert": notify_on_alert,
        "notify_on_unavailable": notify_on_unavailable,
        "unavailable_after_minutes": unavailable_after_minutes,
        "notify_on_recovered": notify_on_recovered,
        "recovered_after_minutes": recovered_after_minutes,
        "alert_subject": _text_override("alert_subject"),
        "alert_body": _text_override("alert_body"),
        "unavailable_subject": _text_override("unavailable_subject"),
        "unavailable_body": _text_override("unavailable_body"),
        "recovered_subject": _text_override("recovered_subject"),
        "recovered_body": _text_override("recovered_body"),
    }
    return values, company_ids, honeypot_ids, errors


async def _authorize_scope(
    db: AsyncSession, user: User, company_ids: list[uuid.UUID], honeypot_ids: list[uuid.UUID]
) -> tuple[list[Company], list[Honeypot], list[str]]:
    """Re-checks every submitted company/honeypot id against `user`'s own
    scope server-side — the picker options in the form are already
    filtered to what they can see, but a client can submit any id, so this
    is the actual enforcement, not just UX. Returns the resolved
    `Company`/`Honeypot` rows (ready to assign onto the rule's
    relationships) alongside any errors — a submitted id that doesn't
    exist, or isn't visible to `user`, is a plain error, not a silent
    drop."""
    errors: list[str] = []

    companies: list[Company] = []
    if company_ids:
        result = await db.execute(select(Company).where(Company.id.in_(company_ids)))
        found = {company.id: company for company in result.scalars().all()}
        for company_id in company_ids:
            company = found.get(company_id)
            if company is None or not (user.is_superadmin or company_id in user.company_ids()):
                errors.append("You don't have access to that company.")
            else:
                companies.append(company)

    honeypots: list[Honeypot] = []
    if honeypot_ids:
        hp_result = await db.execute(
            select(Honeypot)
            .options(selectinload(Honeypot.companies))
            .where(Honeypot.id.in_(honeypot_ids))
        )
        found_hp = {honeypot.id: honeypot for honeypot in hp_result.scalars().all()}
        for honeypot_id in honeypot_ids:
            honeypot = found_hp.get(honeypot_id)
            if honeypot is None or not can_see_honeypot(user, honeypot):
                errors.append("You don't have access to that honeypot.")
            else:
                honeypots.append(honeypot)

    return companies, honeypots, errors


@router.post("", dependencies=[Depends(verify_csrf)])
async def create_notification_rule(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    user = await db.get(User, current_user.id)
    assert user is not None
    form = await request.form()
    values, company_ids, honeypot_ids, errors = _parse_rule_form(form)
    companies: list[Company] = []
    honeypots: list[Honeypot] = []
    if not errors:
        companies, honeypots, errors = await _authorize_scope(db, user, company_ids, honeypot_ids)

    if errors:
        return await _render_list(request, db, user, errors=errors)

    rule = NotificationRule(user_id=user.id, companies=companies, honeypots=honeypots, **values)
    db.add(rule)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="user.notifications.rule.create",
        summary=f'"{user.username}" created notification rule "{rule.name}"',
        target_type="notification_rule",
        target_id=rule.id,
        target_label=rule.name,
    )
    return RedirectResponse(
        url="/account/notifications?saved=1", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/{rule_id}/edit", dependencies=[Depends(verify_csrf)])
async def update_notification_rule(
    request: Request,
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    user = await db.get(User, current_user.id)
    assert user is not None
    rule = await _get_own_rule(db, user, rule_id)
    form = await request.form()
    values, company_ids, honeypot_ids, errors = _parse_rule_form(form)
    companies: list[Company] = []
    honeypots: list[Honeypot] = []
    if not errors:
        companies, honeypots, errors = await _authorize_scope(db, user, company_ids, honeypot_ids)

    if errors:
        return await _render_list(request, db, user, errors=errors)

    for key, value in values.items():
        setattr(rule, key, value)
    rule.companies = companies
    rule.honeypots = honeypots
    await db.commit()
    await log_event(
        db,
        request=request,
        action="user.notifications.rule.update",
        summary=f'"{user.username}" updated notification rule "{rule.name}"',
        target_type="notification_rule",
        target_id=rule.id,
        target_label=rule.name,
    )
    return RedirectResponse(
        url="/account/notifications?saved=1", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/{rule_id}/delete", dependencies=[Depends(verify_csrf)])
async def delete_notification_rule(
    request: Request,
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    user = await db.get(User, current_user.id)
    assert user is not None
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
    return RedirectResponse(
        url="/account/notifications?saved=1", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/{rule_id}/test", dependencies=[Depends(verify_csrf)])
async def send_test(
    request: Request,
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """"Send test" button — fires one synthetic alert notification through
    this rule's own current channel/target, against a real honeypot in its
    scope (see `_representative_honeypot`)."""
    user = await db.get(User, current_user.id)
    assert user is not None
    rule = await _get_own_rule(db, user, rule_id, with_user=True)

    honeypot = await _representative_honeypot(db, rule)
    error: str | None
    if honeypot is None:
        error = "That company has no honeypot yet to send a test notification for."
    else:
        target = resolve_target(rule)
        if not target:
            error = "No email address or webhook URL is set for this rule."
        else:
            app_settings = await get_or_create_app_settings(db)
            error = await send_test_notification(
                db,
                app_settings,
                rule=rule,
                honeypot=honeypot,
                channel=rule.delivery_channel,
                target=target,
            )

    query = "test_sent=1" if not error else f"test_error={quote(error, safe='')}"
    return RedirectResponse(
        url=f"/account/notifications?{query}", status_code=status.HTTP_303_SEE_OTHER
    )


async def _build_notification_history_context(
    db: AsyncSession, current_user: User
) -> dict[str, object]:
    result = await db.execute(
        select(NotificationLog)
        .where(NotificationLog.user_id == current_user.id)
        .order_by(NotificationLog.created_at.desc())
        .limit(200)
    )
    entries = list(result.scalars().all())
    return {"entries": entries}


@router.get("/history")
async def notification_history(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The current user's own last 200 notification send attempts (real or
    test) — never another user's, since this whole feature has no
    admin/superadmin gate (see this module's docstring)."""
    context = await _build_notification_history_context(db, current_user)
    return templates.TemplateResponse(request, "notifications/history.html", context)


@router.get("/history/panel")
async def notification_history_panel(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The live-refreshed table's own fetch target (see
    notifications/history.html) — same query as the full page, rendering
    just the inner partial."""
    context = await _build_notification_history_context(db, current_user)
    return templates.TemplateResponse(
        request, "partials/_notification_history_content.html", context
    )
