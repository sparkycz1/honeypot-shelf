"""Managed honeypots — CRUD, host key pinning, connection testing, facts."""

from __future__ import annotations

import asyncio
import contextlib
import csv
import io
import json
import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Any

# NOT the builtin `TimeoutError` — `celery.exceptions.TimeoutError` does not
# subclass it, so catching the builtin around `AsyncResult.get(timeout=...)`
# would silently never match and the timeout branches below would be dead code.
from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased, selectinload

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_write
from app.auth.scope import (
    companies_visible_to,
    has_company_access,
    honeypots_visible_to,
    visible_honeypots_by_ids,
)
from app.core.app_settings import get_or_create_app_settings
from app.core.config import Settings, get_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.core.security import encrypt_secret
from app.db.models.audit_log import AuditOutcome
from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.honeypot_monitoring_sample import HoneypotMonitoringSample
from app.db.models.honeypot_package import HoneypotPackage
from app.db.models.honeypot_reachability_sample import HoneypotReachabilitySample
from app.db.models.honeypot_service import HoneypotService
from app.db.models.honeypot_tag import Tag
from app.db.models.honeypot_update_run import HoneypotUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.pending_honeypot import PendingHoneypot
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.honeypot import HoneypotCreate, HoneypotUpdate
from app.schemas.honeypot_config import HoneypotConfigExport
from app.services import canary_activity_history, monitoring_history
from app.services.honeypot_actions import (
    send_power_to_honeypots,
    trigger_check_updates,
    trigger_updates,
)
from app.services.honeypot_config import export_honeypot_config, import_honeypot_config
from app.services.honeypot_status import as_aware_utc
from app.services.honeypot_tags import (
    add_tags_to_honeypots,
    parse_tag_names_from_text,
    remove_tags_from_honeypots,
    set_honeypot_tags,
)
from app.services.opencanary_logtypes import logtype_label
from app.services.saved_views import (
    DuplicateViewNameError,
    build_query_string,
    create_saved_view,
    delete_saved_view,
    list_saved_views,
)
from app.ssh import logs as ssh_logs
from app.ssh.client import discover_host_key_fingerprint
from app.ssh.exceptions import SSHConnectionError
from app.ssh.opencanary_config import (
    OPENCANARY_MODULES,
    apply_form_to_config,
    field_value,
    module_enabled,
)
from app.ssh.packages import PackageSource
from app.ssh.power import PowerAction
from app.ssh.updates import PendingPackage

# Imported as a module, not name-by-name: this file already has a route
# function called `preview_honeypot_update`, which would shadow the task of
# the same name.
from app.tasks import jobs as tasks
from app.web.honeypot_search import apply_tag_filter, honeypot_search_clause
from app.web.routes.audit import _csv_safe
from app.web.templating import t, templates

# Typed phrase to confirm a power action against an arbitrary ad-hoc
# selection from the honeypot list — unlike a group or "All honeypots", a
# selection doesn't have a name of its own to ask someone to type.
_BULK_POWER_CONFIRM_PHRASE = "SELECTED HONEYPOTS"

# The honeypot list's display density — a per-browser cosmetic preference,
# not per-account data worth a DB column (unlike saved views/tags, which
# are meaningful to look up or share across a session). Same plain,
# long-lived, non-httponly-adjacent cookie pattern `app.web.routes.theme`
# already uses for the light/dark toggle.
HONEYPOTS_VIEW_COOKIE_NAME = "honeypots_view"
_HONEYPOTS_VIEW_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 365
_HONEYPOT_VIEW_MODES = ("table", "list", "cards")

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/honeypots")
# debcontrol gates updates/power/terminal behind their own separate
# Permissions; this app has only one write tier (READ_WRITE on the
# honeypot's company — see app.db.models.user's module docstring), so all
# four collapse into the same dependency. Kept as separate names anyway —
# matching every route below exactly the way it matched debcontrol's own
# four — so a future re-introduction of finer-grained tiers touches only
# this one spot.
_manage = Depends(require_write)
_updates = Depends(require_write)
_power = Depends(require_write)
_terminal = Depends(require_write)

# Fingerprint shaped like "SHA256:<base64...>", as returned by AsyncSSH/OpenSSH.
_FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9]+:[A-Za-z0-9+/=_-]+$")


def _honeypot_tabs(request: Request, honeypot: Honeypot, user: User) -> list[tuple[str, str, str]]:
    """The (key, label, url) tabs shown on every one of this honeypot's own
    pages — same set and order everywhere, so `partials/_tabnav.html` always
    highlights the right one. Terminal is left out entirely for a
    read-only user, same as it was hidden inline before this page had
    tabs at all."""
    base = f"/honeypots/{honeypot.id}"
    tabs = [
        ("overview", t(request, "honeypots.tabs.overview"), base),
        ("monitoring", t(request, "honeypots.tabs.monitoring"), f"{base}/monitoring"),
        # Read-only too, unlike the write-gated tabs below — a read-only
        # account can already see what OpenCanary has actually caught on
        # this honeypot without being able to manage it.
        ("status", t(request, "honeypots.tabs.activity"), f"{base}/status"),
    ]
    if user.can_write():
        tabs.append(("updates", t(request, "honeypots.tabs.updates"), f"{base}/updates"))
        tabs.append(("terminal", t(request, "honeypots.tabs.terminal"), f"{base}/terminal"))
        # Logs/Config/Settings all share Terminal's write gate rather than
        # being available to a read-only account — see the "Logs" route's
        # own docstring for why.
        tabs.append(("logs", t(request, "honeypots.tabs.logs"), f"{base}/logs"))
        tabs.append(("config", t(request, "honeypots.tabs.config"), f"{base}/config"))
        # No separate "Power" tab any more — reboot/shut down live directly
        # on Overview now (see `honeypot_detail`'s own template), the same
        # one-page placement this honeypot's other one-off actions (test
        # connection, discover host key) already have, rather than a whole
        # tab for two buttons. `GET /{id}/power` itself still redirects
        # there for anyone with the old URL bookmarked/linked — see
        # `power_tab`.
        tabs.append(("settings", t(request, "honeypots.tabs.settings"), f"{base}/edit"))
    return tabs


async def _get_honeypot_or_404(honeypot_id: uuid.UUID, db: AsyncSession, user: User) -> Honeypot:
    """The honeypot, or a 404 — including when it exists but is outside
    `user`'s company scope (`app.services.access_scope`). 404, never
    403, for the same reason `app/web/routes/ai.py`'s `_get_conversation`
    uses one: a 403 would confirm that a honeypot with that id exists."""
    # Eager-load `company` — templates read `honeypot.company` and the async
    # ORM can't lazy-load relationships outside of an `await` (it would
    # raise MissingGreenlet during template rendering). (`Honeypot.company`
    # is already `lazy="joined"` on the model — this `selectinload` is
    # belt-and-suspenders against that ever changing.)
    query = honeypots_visible_to(user)
    result = await db.execute(
        query.options(selectinload(Honeypot.company)).where(Honeypot.id == honeypot_id)
    )
    honeypot = result.scalar_one_or_none()
    if honeypot is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Honeypot not found.")
    return honeypot


async def _get_companies(db: AsyncSession, user: User) -> list[Company]:
    """The companies offered in the honeypot form's company `<select>` —
    a superadmin sees every company; a company-scoped user only ever sees
    (and the form only ever offers) their own single company."""
    query = companies_visible_to(user)
    result = await db.execute(query.order_by(Company.name))
    return list(result.scalars().all())


async def _get_all_tags(db: AsyncSession) -> list[Tag]:
    """Every tag currently in use, alphabetical — the honeypot list's filter
    dropdown and the create/edit forms' autocomplete `<datalist>`. Not
    scoped by company access: a tag *name* existing isn't fleet
    data, and a restricted account typing a tag another honeypot happens to
    use just filters to nothing, the same as typing a free-text search
    term that doesn't match anything in scope."""
    result = await db.execute(select(Tag).order_by(Tag.name))
    return list(result.scalars().all())


async def _get_pending_honeypots(db: AsyncSession) -> list[PendingHoneypot]:
    result = await db.execute(select(PendingHoneypot).order_by(PendingHoneypot.created_at.desc()))
    return list(result.scalars().all())


async def _get_latest_monitoring_by_honeypot(
    db: AsyncSession, honeypot_ids: list[uuid.UUID]
) -> dict[uuid.UUID, HoneypotMonitoringSample]:
    """The single most recent monitoring sample for each honeypot in
    `honeypot_ids` — the Cards view's small CPU/RAM indicator. One query
    (a `row_number() OVER (PARTITION BY honeypot_id ...)` window, filtered
    to rank 1), not one query per honeypot — this runs against the current
    page's honeypots only (at most `_HONEYPOT_LIST_PAGE_SIZE`), so it scales
    the same way the page itself does. Deliberately just the latest
    reading, not a historical sparkline: a real trend line would mean
    fetching every sample in a time window for up to a page's worth of
    honeypots at once, the same "don't fan out per honeypot" scale concern
    `wiki/Development.md` calls out elsewhere — see the Monitoring tab
    (`GET /honeypots/{id}/monitoring`) for actual trend charts, one honeypot
    at a time."""
    if not honeypot_ids:
        return {}
    ranked = (
        select(
            HoneypotMonitoringSample,
            func.row_number()
            .over(
                partition_by=HoneypotMonitoringSample.honeypot_id,
                order_by=HoneypotMonitoringSample.sampled_at.desc(),
            )
            .label("rn"),
        )
        .where(HoneypotMonitoringSample.honeypot_id.in_(honeypot_ids))
        .subquery()
    )
    latest = aliased(HoneypotMonitoringSample, ranked)
    result = await db.execute(select(latest).where(ranked.c.rn == 1))
    return {sample.honeypot_id: sample for sample in result.scalars().all()}


async def _get_package_counts(honeypot_id: uuid.UUID, db: AsyncSession) -> dict[str, int]:
    result = await db.execute(
        select(HoneypotPackage.source, func.count())
        .where(HoneypotPackage.honeypot_id == honeypot_id)
        .group_by(HoneypotPackage.source)
    )
    counts = {source.value: 0 for source in PackageSource}
    total = 0
    for source, count in result.all():
        counts[source.value] = count
        total += count
    counts["total"] = total
    return counts


async def _get_held_count(honeypot_id: uuid.UUID, db: AsyncSession) -> int:
    return (
        await db.scalar(
            select(func.count())
            .select_from(HoneypotPackage)
            .where(HoneypotPackage.honeypot_id == honeypot_id, HoneypotPackage.held.is_(True))
        )
    ) or 0


async def _get_packages(
    honeypot_id: uuid.UUID,
    db: AsyncSession,
    *,
    pkg_q: str,
    pkg_source: str,
    held_only: bool = False,
) -> list[HoneypotPackage]:
    query = select(HoneypotPackage).where(HoneypotPackage.honeypot_id == honeypot_id)
    if pkg_q.strip():
        query = query.where(HoneypotPackage.name.ilike(f"%{pkg_q.strip()}%"))
    if pkg_source in {source.value for source in PackageSource}:
        query = query.where(HoneypotPackage.source == PackageSource(pkg_source))
    if held_only:
        query = query.where(HoneypotPackage.held.is_(True))
    result = await db.execute(query.order_by(HoneypotPackage.source, HoneypotPackage.name))
    return list(result.scalars().all())


async def _get_service_counts(honeypot_id: uuid.UUID, db: AsyncSession) -> dict[str, int]:
    result = await db.execute(
        select(func.count())
        .select_from(HoneypotService)
        .where(HoneypotService.honeypot_id == honeypot_id)
    )
    total = result.scalar_one()
    failed_result = await db.execute(
        select(func.count())
        .select_from(HoneypotService)
        .where(
            HoneypotService.honeypot_id == honeypot_id, HoneypotService.active_state == "failed"
        )
    )
    return {"total": total, "failed": failed_result.scalar_one()}


async def _get_services(
    honeypot_id: uuid.UUID, db: AsyncSession, *, svc_q: str, svc_state: str
) -> list[HoneypotService]:
    query = select(HoneypotService).where(HoneypotService.honeypot_id == honeypot_id)
    if svc_q.strip():
        query = query.where(HoneypotService.unit.ilike(f"%{svc_q.strip()}%"))
    if svc_state:
        query = query.where(HoneypotService.active_state == svc_state)
    result = await db.execute(query.order_by(HoneypotService.unit))
    return list(result.scalars().all())


_UPDATE_HISTORY_PAGE_SIZE = 50

# The honeypots list used to load every row unconditionally — fine at a
# handful of honeypots, but at fleet sizes in the hundreds/thousands this
# page was one unbounded `SELECT *` and a multi-thousand-row HTML response
# on every visit. Same offset/limit-plus-one-extra-row convention as
# `/audit` and the update-run history: fetch one row past the page size to
# know whether a "Next" page exists, without a separate COUNT(*) query.
_HONEYPOT_LIST_PAGE_SIZE = 100


async def _get_update_run_or_404(run_id: uuid.UUID, db: AsyncSession) -> HoneypotUpdateRun:
    run = await db.get(HoneypotUpdateRun, run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Update run not found.")
    return run


@router.get("")
async def list_honeypots(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    q: str = "",
    tag: list[str] = Query(default=[]),
    tag_mode: str = "or",
    page: int = 1,
) -> Response:
    page = max(page, 1)
    tag_mode = tag_mode if tag_mode == "and" else "or"
    query = honeypots_visible_to(current_user).options(selectinload(Honeypot.company))
    if q.strip():
        query = query.where(honeypot_search_clause(q))
    query = apply_tag_filter(query, tag, tag_mode)

    offset = (page - 1) * _HONEYPOT_LIST_PAGE_SIZE
    result = await db.execute(
        query.order_by(Honeypot.name).offset(offset).limit(_HONEYPOT_LIST_PAGE_SIZE + 1)
    )
    honeypots = list(result.scalars().all())
    has_more = len(honeypots) > _HONEYPOT_LIST_PAGE_SIZE
    honeypots = honeypots[:_HONEYPOT_LIST_PAGE_SIZE]

    view_mode = request.cookies.get(HONEYPOTS_VIEW_COOKIE_NAME, "table")
    if view_mode not in _HONEYPOT_VIEW_MODES:
        view_mode = "table"

    latest_monitoring = (
        await _get_latest_monitoring_by_honeypot(db, [m.id for m in honeypots])
        if view_mode == "cards"
        else {}
    )

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/list.html",
        {
            "honeypots": honeypots,
            "pending_honeypots": await _get_pending_honeypots(db),
            "all_tags": await _get_all_tags(db),
            "saved_views": await list_saved_views(db, current_user.id),
            "q": q,
            "tag": tag,
            "tag_mode": tag_mode,
            "page": page,
            "has_more": has_more,
            "view_mode": view_mode,
            "latest_monitoring": latest_monitoring,
            "csrf_token": csrf_token,
            "bulk_error": request.query_params.get("bulk_error"),
            "power_skipped": request.query_params.get("power_skipped"),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


def _safe_honeypots_redirect(next_path: str) -> str:
    """Only ever redirect back into `/honeypots...` — `next` comes from a
    form field an attacker could tamper with, same reasoning
    `app.web.routes.theme._safe_redirect_target` already documents."""
    if next_path.startswith("/honeypots") and not next_path.startswith("//"):
        return next_path
    return "/honeypots"


@router.post("/view-mode", dependencies=[Depends(verify_csrf)])
async def set_honeypots_view_mode(
    view: str = Form(...), next: str = Form("/honeypots")
) -> Response:
    """The "Table" / "List" / "Cards" toggle above the honeypot list —
    remembered in a cookie, not a query param, so it carries over to the
    next visit (and every saved view/pagination link) without needing to
    be threaded through every href on the page. See
    `HONEYPOTS_VIEW_COOKIE_NAME`."""
    chosen = view if view in _HONEYPOT_VIEW_MODES else "table"
    response = RedirectResponse(
        url=_safe_honeypots_redirect(next), status_code=status.HTTP_303_SEE_OTHER
    )
    response.set_cookie(
        HONEYPOTS_VIEW_COOKIE_NAME,
        chosen,
        max_age=_HONEYPOTS_VIEW_COOKIE_MAX_AGE_SECONDS,
        httponly=True,
        samesite="lax",
        secure=get_settings().is_production,
    )
    return response


@router.post("/views", dependencies=[Depends(verify_csrf)])
async def save_honeypot_view(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    name: str = Form(...),
    q: str = Form(""),
    tag: list[str] = Form(default=[]),
    tag_mode: str = Form("or"),
) -> Response:
    """"Save this view" on the honeypot list — captures only the known
    filter fields (never an arbitrary querystring, see
    `app.services.saved_views`), so a saved view always replays as exactly
    the same filtered `GET /honeypots` request."""
    query_string = build_query_string({"q": q, "tag": tag, "tag_mode": tag_mode})
    if not name.strip():
        return RedirectResponse(
            url=f"/honeypots?{query_string}", status_code=status.HTTP_303_SEE_OTHER
        )
    try:
        await create_saved_view(db, current_user.id, name, query_string)
    except DuplicateViewNameError:
        return RedirectResponse(
            url=f"/honeypots?{query_string}&view_error=duplicate_name",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(url=f"/honeypots?{query_string}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/views/{view_id}/delete", dependencies=[Depends(verify_csrf)])
async def delete_honeypot_view(
    view_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    await delete_saved_view(db, current_user.id, view_id)
    return RedirectResponse(url="/honeypots", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/new")
async def new_honeypot_form(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/new.html",
        {
            "auth_methods": list(AuthMethod),
            "companies": await _get_companies(db, current_user),
            "all_tags": await _get_all_tags(db),
            "errors": [],
            "form": {
                "name": request.query_params.get("name", ""),
                "ip_address": request.query_params.get("ip_address", ""),
                # Pre-selects the company `<select>` when linked from that
                # company's own page ("Add honeypot") — still just a regular
                # field the operator can change before submitting.
                "company_id": request.query_params.get("company_id", ""),
            },
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("", dependencies=[_manage, Depends(verify_csrf)])
async def create_honeypot(
    request: Request,
    db: AsyncSession = Depends(get_db),
    name: str = Form(...),
    ip_address: str = Form(...),
    port: int = Form(22222),
    username: str = Form(...),
    auth_method: AuthMethod = Form(...),
    secret: str = Form(""),
    company_id: str = Form(""),
    location: str = Form(""),
    description: str = Form(""),
    runbook: str = Form(""),
    tags: str = Form(""),
    current_user: User = Depends(get_current_user),
) -> Response:
    # Every honeypot belongs to exactly one company (unlike debcontrol's
    # optional group) — a company-scoped user's own company, always,
    # ignoring whatever the form submitted for it (never trust the client
    # over the session's own scope); a superadmin must pick one explicitly.
    resolved_company_id = (
        current_user.company_id
        if not current_user.is_superadmin
        else (uuid.UUID(company_id) if company_id else None)
    )
    try:
        if resolved_company_id is None:
            raise ValueError("Pick a company for this honeypot.")
        payload = HoneypotCreate(
            name=name,
            ip_address=ip_address,
            port=port,
            username=username,
            auth_method=auth_method,
            secret=secret or None,
            company_id=resolved_company_id,
            location=location or None,
            description=description or None,
            runbook=runbook or None,
        )
    except ValueError as exc:
        await log_event(
            db,
            request=request,
            action="honeypot.create",
            summary=f'Rejected new honeypot "{name}": {exc}',
            outcome=AuditOutcome.FAILURE,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "honeypots/new.html",
            {
                "auth_methods": list(AuthMethod),
                "companies": await _get_companies(db, current_user),
                "all_tags": await _get_all_tags(db),
                "errors": [str(exc)],
                "form": {
                    "name": name,
                    "ip_address": ip_address,
                    "port": port,
                    "username": username,
                    "auth_method": auth_method,
                    "description": description,
                    "runbook": runbook,
                },
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    # A company-scoped account may only file a new honeypot into its own
    # company — a superadmin may pick any company that exists.
    if not has_company_access(current_user, payload.company_id, write=True):
        await log_event(
            db,
            request=request,
            action="honeypot.create",
            summary=f'Rejected new honeypot "{name}": company outside this account\'s access',
            outcome=AuditOutcome.DENIED,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Pick a company your account has access to.",
        )

    honeypot = Honeypot(
        name=payload.name,
        ip_address=payload.ip_address,
        port=payload.port,
        username=payload.username,
        auth_method=payload.auth_method,
        secret_encrypted=encrypt_secret(payload.secret) if payload.secret else None,
        company_id=payload.company_id,
        location=payload.location,
        description=payload.description,
        runbook=payload.runbook,
    )
    db.add(honeypot)
    await db.commit()
    await db.refresh(honeypot)

    await set_honeypot_tags(db, honeypot, parse_tag_names_from_text(tags))
    await db.commit()

    await log_event(
        db,
        request=request,
        action="honeypot.create",
        summary=f'Created honeypot "{honeypot.name}" ({honeypot.ip_address})',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
    )

    return RedirectResponse(url=f"/honeypots/{honeypot.id}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/import")
async def import_honeypots_form(request: Request) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/import.html",
        {"csrf_token": csrf_token, "errors": [], "result": None},
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/import", dependencies=[_manage, Depends(verify_csrf)])
async def import_honeypots_submit(
    request: Request, db: AsyncSession = Depends(get_db), csv_text: str = Form("")
) -> Response:
    """Bulk-add honeypots from pasted CSV — each row becomes a `PendingHoneypot`
    in the same review queue self-registration (`POST /api/inform`) uses,
    rather than a `Honeypot` directly: nothing here is trusted for connecting
    to a honeypot (no credentials, no host key), so it still goes through the
    normal add-honeypot form and mandatory host-key confirmation per honeypot.

    Expected columns (header row required): `ip_address` (required),
    `hostname` (optional). Anything else is ignored.
    """
    errors: list[str] = []
    text = csv_text.strip()
    if not text:
        errors.append("Paste some CSV text first.")
        return templates.TemplateResponse(
            request,
            "honeypots/import.html",
            {"csrf_token": request.state.csrf_token, "errors": errors, "result": None},
        )

    reader = csv.DictReader(io.StringIO(text))
    fieldnames = [f.strip().lower() for f in (reader.fieldnames or [])]
    if "ip_address" not in fieldnames:
        errors.append('The CSV needs a header row with at least an "ip_address" column.')
        return templates.TemplateResponse(
            request,
            "honeypots/import.html",
            {"csrf_token": request.state.csrf_token, "errors": errors, "result": None},
        )

    created = 0
    skipped = 0
    for row in reader:
        normalized = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items() if k}
        ip_address = normalized.get("ip_address", "")
        if not ip_address:
            skipped += 1
            continue
        db.add(
            PendingHoneypot(
                ip_address=ip_address,
                reported_hostname=normalized.get("hostname") or None,
                source_ip=None,
            )
        )
        created += 1
    await db.commit()

    await log_event(
        db,
        request=request,
        action="honeypot.bulk_import",
        summary=f"Bulk-imported {created} pending honeypot(s) from CSV ({skipped} row(s) skipped)",
        details={"created": created, "skipped": skipped},
    )
    return templates.TemplateResponse(
        request,
        "honeypots/import.html",
        {
            "csrf_token": request.state.csrf_token,
            "errors": [],
            "result": {"created": created, "skipped": skipped},
        },
    )


_CONFIG_EXPORT_CSV_FIELDS = (
    "name",
    "ip_address",
    "port",
    "username",
    "auth_method",
    "company",
    "location",
    "description",
    "tags",
    "is_active",
)


@router.get("/config/export")
async def export_honeypot_config_endpoint(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    format: str = "json",  # noqa: A002
) -> Response:
    """Export every honeypot's and company's *structural* configuration —
    deliberately never `secret_encrypted` or `host_key_fingerprint`, see
    `app.services.honeypot_config`'s module docstring. JSON includes both
    honeypots and companies; CSV (honeypots only — companies don't flatten
    to CSV sensibly) is a plain download link, same pattern as the audit
    log's export (see `app/web/routes/audit.py`)."""
    export = await export_honeypot_config(db, current_user)

    await log_event(
        db,
        request=request,
        action="honeypot.config_export",
        summary=(
            f"Exported configuration for {len(export.honeypots)} honeypot(s) and "
            f"{len(export.companies)} compan{'y' if len(export.companies) == 1 else 'ies'} "
            f"as {format}"
        ),
        details={
            "honeypot_count": len(export.honeypots),
            "company_count": len(export.companies),
            "format": format,
        },
    )

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    if format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=_CONFIG_EXPORT_CSV_FIELDS)
        writer.writeheader()
        for honeypot in export.honeypots:
            row = honeypot.model_dump()
            row["auth_method"] = honeypot.auth_method.value if honeypot.auth_method else ""
            row["tags"] = ", ".join(honeypot.tags)
            # Doesn't flatten sensibly into one CSV cell — JSON export is
            # the full-fidelity round-trip for a runbook, same reasoning
            # companies are CSV-honeypots-only for. See _CONFIG_EXPORT_CSV_FIELDS.
            del row["runbook"]
            writer.writerow({k: _csv_safe(v) for k, v in row.items()})
        return Response(
            content=buffer.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="honeypots-{timestamp}.csv"'
            },
        )

    return Response(
        content=export.model_dump_json(indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="honeypot-config-{timestamp}.json"'
        },
    )


@router.get("/config/import")
async def import_honeypot_config_form(request: Request) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/config_import.html",
        {"csrf_token": csrf_token, "errors": [], "result": None},
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/config/import", dependencies=[_manage, Depends(verify_csrf)])
async def import_honeypot_config_submit(
    request: Request, db: AsyncSession = Depends(get_db), json_text: str = Form("")
) -> Response:
    """Create real `Honeypot`/`Company` rows from a pasted JSON export
    (see `GET /honeypots/config/export`) — not the pending-review queue the
    CSV bulk-import above uses, since this is for restoring/migrating
    *known* configuration rather than discovering unknown hosts. See
    `app.services.honeypot_config` for the full conflict-handling and
    security policy this implements."""
    text = json_text.strip()
    if not text:
        return templates.TemplateResponse(
            request,
            "honeypots/config_import.html",
            {
                "csrf_token": request.state.csrf_token,
                "errors": ["Paste some exported JSON text first."],
                "result": None,
            },
        )

    try:
        payload = HoneypotConfigExport.model_validate_json(text)
    except ValidationError as exc:
        return templates.TemplateResponse(
            request,
            "honeypots/config_import.html",
            {
                "csrf_token": request.state.csrf_token,
                "errors": [f"Invalid configuration JSON: {exc}"],
                "result": None,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    result = await import_honeypot_config(db, payload)

    await log_event(
        db,
        request=request,
        action="honeypot.config_import",
        summary=result.summary(),
        details=result.to_dict(),
    )

    return templates.TemplateResponse(
        request,
        "honeypots/config_import.html",
        {"csrf_token": request.state.csrf_token, "errors": [], "result": result},
    )


_PACKAGE_SEARCH_LIMIT = 500


@router.get("/package-search")
async def package_search(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    q: str = "",
    pkg_source: str = "",
) -> Response:
    """Fleet-wide "who has package X installed, and what version" — the
    other direction from the per-honeypot Installed packages panel. Useful
    after a CVE announcement: search the name, see every honeypot and
    version at once instead of checking honeypots one by one."""
    results: list[HoneypotPackage] = []
    truncated = False
    if q.strip():
        # Scoped by joining the honeypot each row belongs to — a restricted
        # user searching fleet-wide must not learn which packages sit on a
        # honeypot they can't otherwise see.
        visible_ids = honeypots_visible_to(current_user).with_only_columns(Honeypot.id)
        query = (
            select(HoneypotPackage)
            .options(selectinload(HoneypotPackage.honeypot))
            .where(
                HoneypotPackage.name.ilike(f"%{q.strip()}%"),
                HoneypotPackage.honeypot_id.in_(visible_ids),
            )
        )
        if pkg_source in {source.value for source in PackageSource}:
            query = query.where(HoneypotPackage.source == PackageSource(pkg_source))
        query = query.order_by(HoneypotPackage.name).limit(_PACKAGE_SEARCH_LIMIT + 1)
        result = await db.execute(query)
        results = list(result.scalars().all())
        truncated = len(results) > _PACKAGE_SEARCH_LIMIT
        results = results[:_PACKAGE_SEARCH_LIMIT]

    return templates.TemplateResponse(
        request,
        "honeypots/package_search.html",
        {"q": q, "pkg_source": pkg_source, "results": results, "truncated": truncated},
    )


async def _get_honeypots_by_ids(
    honeypot_ids: list[uuid.UUID], db: AsyncSession, user: User
) -> list[Honeypot]:
    """The submitted selection, minus anything outside `user`'s scope.

    Client-submitted ids are never trusted here: the checkboxes were
    rendered from a scoped list, so an id outside it can only have been
    hand-crafted. Out-of-scope ids are dropped silently rather than
    rejected with an error naming them (see
    `app.services.access_scope.filter_honeypots`)."""
    return await visible_honeypots_by_ids(db, user, honeypot_ids)


@router.post("/bulk/check-updates", dependencies=[_updates, Depends(verify_csrf)])
async def bulk_check_updates(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    honeypot_ids: list[uuid.UUID] = Form(default=[]),
) -> Response:
    """Check-updates for an ad-hoc selection from the honeypot list — same
    underlying job as the group/"All honeypots" versions, just against
    whichever rows were ticked rather than a stored group."""
    honeypots = await _get_honeypots_by_ids(honeypot_ids, db, current_user)
    if not honeypots:
        return RedirectResponse(
            url="/honeypots?bulk_error=Select+at+least+one+honeypot.",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    skipped = await trigger_check_updates(honeypots)
    await log_event(
        db,
        request=request,
        action="honeypots.bulk.updates.check",
        summary=f"Checked for updates on {len(honeypots)} selected honeypot(s)",
        details={"honeypot_count": len(honeypots), "skipped": skipped},
    )
    return RedirectResponse(url="/honeypots", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/bulk/updates", dependencies=[_updates, Depends(verify_csrf)])
async def bulk_trigger_updates(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    honeypot_ids: list[uuid.UUID] = Form(default=[]),
    strategy: UpgradeStrategy = Form(...),
) -> Response:
    honeypots = await _get_honeypots_by_ids(honeypot_ids, db, current_user)
    if not honeypots:
        return RedirectResponse(
            url="/honeypots?bulk_error=Select+at+least+one+honeypot.",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    batch_id, skipped = await trigger_updates(db, honeypots, strategy)
    await log_event(
        db,
        request=request,
        action="honeypots.bulk.updates.run",
        summary=(
            f'Triggered {strategy.value.replace("_", "-")} on '
            f"{len(honeypots)} selected honeypot(s)"
        ),
        details={"strategy": strategy.value, "batch_id": str(batch_id), "skipped": skipped},
    )
    redirect_url = f"/companies/batches/{batch_id}"
    if skipped:
        redirect_url += f"?skipped={skipped}"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/bulk/power-confirm/{action}", dependencies=[_power, Depends(verify_csrf)])
async def bulk_power_confirm(
    request: Request,
    action: PowerAction,
    honeypot_ids: list[uuid.UUID] = Form(default=[]),
) -> Response:
    """Render the typed-confirmation page for a bulk power action, carrying
    the selection forward as hidden fields (there's no group/name to look
    the selection back up by, unlike the group-scoped version of this)."""
    if not honeypot_ids:
        return RedirectResponse(
            url="/honeypots?bulk_error=Select+at+least+one+honeypot.",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/bulk_power_confirm.html",
        {
            "action": action,
            "honeypot_ids": honeypot_ids,
            "target_label": f"{len(honeypot_ids)} selected honeypot(s)",
            "confirm_phrase": _BULK_POWER_CONFIRM_PHRASE,
            "action_url": f"/honeypots/bulk/power/{action.value}",
            "cancel_url": "/honeypots",
            "error": None,
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/bulk/power/{action}", dependencies=[_power, Depends(verify_csrf)])
async def bulk_power_action(
    request: Request,
    action: PowerAction,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    honeypot_ids: list[uuid.UUID] = Form(default=[]),
    confirm_name: str = Form(...),
) -> Response:
    if confirm_name.strip() != _BULK_POWER_CONFIRM_PHRASE:
        await log_event(
            db,
            request=request,
            action=f"honeypots.bulk.power.{action.value}",
            summary=(
                f"Blocked {action.value} on {len(honeypot_ids)} selected "
                "honeypot(s): confirmation mismatch"
            ),
            outcome=AuditOutcome.DENIED,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "honeypots/bulk_power_confirm.html",
            {
                "action": action,
                "honeypot_ids": honeypot_ids,
                "target_label": f"{len(honeypot_ids)} selected honeypot(s)",
                "confirm_phrase": _BULK_POWER_CONFIRM_PHRASE,
                "action_url": f"/honeypots/bulk/power/{action.value}",
                "cancel_url": "/honeypots",
                "error": (
                    f'That doesn\'t match — type "{_BULK_POWER_CONFIRM_PHRASE}" '
                    "exactly to confirm."
                ),
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    honeypots = await _get_honeypots_by_ids(honeypot_ids, db, current_user)
    skipped = await send_power_to_honeypots(honeypots, action)
    await log_event(
        db,
        request=request,
        action=f"honeypots.bulk.power.{action.value}",
        summary=f"Sent {action.value} to {len(honeypots)} selected honeypot(s)",
        details={"skipped": skipped},
    )
    redirect_url = "/honeypots"
    if skipped:
        redirect_url += f"?power_skipped={skipped}"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/bulk/tags/add", dependencies=[_manage, Depends(verify_csrf)])
async def bulk_add_tags(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    honeypot_ids: list[uuid.UUID] = Form(default=[]),
    tags: str = Form(""),
) -> Response:
    """Add one or more tags to every honeypot in an ad-hoc selection from the
    honeypot list, leaving each honeypot's other tags untouched — the bulk
    equivalent of typing into one honeypot's own tags field on Settings."""
    honeypots = await _get_honeypots_by_ids(honeypot_ids, db, current_user)
    names = parse_tag_names_from_text(tags)
    if not honeypots or not names:
        return RedirectResponse(
            url="/honeypots?bulk_error=Select+at+least+one+honeypot+and+tag.",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    await add_tags_to_honeypots(db, [m.id for m in honeypots], names)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="honeypots.bulk.tags.add",
        summary=(
            f'Added tag(s) {", ".join(names)} to {len(honeypots)} selected honeypot(s)'
        ),
        details={"tags": names, "honeypot_count": len(honeypots)},
    )
    return RedirectResponse(url="/honeypots", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/bulk/tags/remove", dependencies=[_manage, Depends(verify_csrf)])
async def bulk_remove_tags(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    honeypot_ids: list[uuid.UUID] = Form(default=[]),
    tags: str = Form(""),
) -> Response:
    """Remove one or more tags from every honeypot in an ad-hoc selection —
    a no-op for any honeypot that didn't have a given tag in the first
    place, never an error."""
    honeypots = await _get_honeypots_by_ids(honeypot_ids, db, current_user)
    names = parse_tag_names_from_text(tags)
    if not honeypots or not names:
        return RedirectResponse(
            url="/honeypots?bulk_error=Select+at+least+one+honeypot+and+tag.",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    await remove_tags_from_honeypots(db, [m.id for m in honeypots], names)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="honeypots.bulk.tags.remove",
        summary=(
            f'Removed tag(s) {", ".join(names)} from {len(honeypots)} selected honeypot(s)'
        ),
        details={"tags": names, "honeypot_count": len(honeypots)},
    )
    return RedirectResponse(url="/honeypots", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/bulk/delete", dependencies=[_manage, Depends(verify_csrf)])
async def bulk_delete_honeypots(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    honeypot_ids: list[uuid.UUID] = Form(default=[]),
) -> Response:
    """The "Delete" bulk action on the Honeypots list — same permanent,
    unrecoverable delete as a single honeypot's own Settings tab (`POST
    /{honeypot_id}/delete`), just for an ad-hoc multi-selection at once.
    Declared before `/{honeypot_id}/...` for the same routing-order
    reason every other `/bulk/...` route here already is — see
    `app/web/routes/users.py`'s own `/bulk/...` routes for the identical
    convention and the bug it avoids."""
    honeypots = await _get_honeypots_by_ids(honeypot_ids, db, current_user)
    if not honeypots:
        return RedirectResponse(
            url="/honeypots?bulk_error=Select+at+least+one+honeypot.",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    names = [honeypot.name for honeypot in honeypots]
    for honeypot in honeypots:
        await db.delete(honeypot)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="honeypots.bulk.delete",
        summary=f"Deleted {len(honeypots)} selected honeypot(s): {', '.join(names)}",
        details={"honeypot_names": names},
    )
    return RedirectResponse(url="/honeypots", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{honeypot_id}")
async def honeypot_detail(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/detail.html",
        {
            "honeypot": honeypot,
            "csrf_token": csrf_token,
            "tabs": _honeypot_tabs(request, honeypot, current_user),
            "active_tab": "overview",
            # The package *rows* themselves are deliberately not fetched
            # here — a honeypot can easily have several hundred installed
            # packages, and rendering them inline made this page slow and
            # cluttered. Only the cheap aggregate counts are needed for the
            # summary line; the full listing loads lazily into a modal (see
            # the "Show installed packages" button and
            # GET /honeypots/{id}/packages below).
            "package_counts": await _get_package_counts(honeypot_id, db),
            "held_count": await _get_held_count(honeypot_id, db),
            # One-time notice after a power action redirect — not persisted
            # anywhere, just echoed back from the query string (see
            # `power_action`'s own redirect).
            "power_sent": request.query_params.get("power_sent"),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


#: Shared by monitoring.html/status.html and the -panel/refresh routes
#: below that render partials/honeypot_{monitoring,activity}_content.html
#: directly (no including template to inherit a template-level `{% set %}`
#: from) — same rotating palette for chart series without one fixed color.
_CHART_PALETTE = [
    "#5b8fff", "#46bf8a", "#e0ab4a", "#f0685f", "#a970ff", "#38bdf8", "#f472b6", "#facc15",
]


def _normalize_range_key(range_key: str) -> str:
    valid_range_keys = {key for key, _label, _delta in monitoring_history.TIME_RANGES}
    return range_key if range_key in valid_range_keys else monitoring_history.DEFAULT_TIME_RANGE


async def _build_monitoring_context(
    honeypot: Honeypot, range_key: str, db: AsyncSession
) -> dict[str, Any]:
    """The Monitoring tab's own data, shared by the first-paint route, the
    auto-refresh/live-update panel route, and the "Refresh now" route —
    see partials/honeypot_monitoring_content.html's own comment for why
    these three routes all funnel through the one partial."""
    range_key = _normalize_range_key(range_key)
    since = datetime.now(UTC) - monitoring_history.time_range_delta(range_key)
    result = await db.execute(
        select(HoneypotMonitoringSample)
        .where(
            HoneypotMonitoringSample.honeypot_id == honeypot.id,
            HoneypotMonitoringSample.sampled_at >= since,
        )
        .order_by(HoneypotMonitoringSample.sampled_at)
        .limit(monitoring_history.MAX_RAW_SAMPLES)
    )
    samples = list(result.scalars().all())
    history = monitoring_history.build_monitoring_history(samples, range_key)

    reachability_result = await db.execute(
        select(HoneypotReachabilitySample)
        .where(
            HoneypotReachabilitySample.honeypot_id == honeypot.id,
            HoneypotReachabilitySample.checked_at >= since,
        )
        .order_by(HoneypotReachabilitySample.checked_at)
        .limit(monitoring_history.MAX_RAW_SAMPLES)
    )
    reachability_samples = list(reachability_result.scalars().all())
    availability = monitoring_history.build_availability_history(reachability_samples, range_key)

    # One unified "last checked" for the whole tab, rather than a separate
    # timestamp per graph (CPU/RAM/OpenCanary all share one round trip's
    # `monitoring_updated_at`; Availability's own reachability check runs
    # independently) — the more recent of the two, so the header always
    # reflects whichever check actually ran most recently. Both need
    # `as_aware_utc` first: SQLite (tests) drops tzinfo on round-trip,
    # real Postgres columns never do (see app.services.honeypot_status).
    candidates = [
        as_aware_utc(t)
        for t in (honeypot.monitoring_updated_at, honeypot.last_ping_at)
        if t is not None
    ]
    last_checked_at = max(candidates) if candidates else None

    return {
        "honeypot": honeypot,
        "history": history,
        "availability": availability,
        "time_ranges": monitoring_history.TIME_RANGES,
        "range_key": range_key,
        "service_counts": await _get_service_counts(honeypot.id, db),
        "last_checked_at": last_checked_at,
        "palette": _CHART_PALETTE,
    }


@router.get("/{honeypot_id}/monitoring")
async def honeypot_monitoring(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    range_key: str = monitoring_history.DEFAULT_TIME_RANGE,
    current_user: User = Depends(get_current_user),
) -> Response:
    """CPU/RAM/disk-usage trend graphs (see `app.services.monitoring_history`
    for the downsampling) plus the services summary/modal trigger.
    `range_key` is one of `monitoring_history.TIME_RANGES`'s keys — an
    unrecognized value quietly falls back to the default rather than
    erroring, same tolerance `status_filter` on the Updates tab already has
    for a bad query param."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    context = await _build_monitoring_context(honeypot, range_key, db)

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/monitoring.html",
        {
            **context,
            "tabs": _honeypot_tabs(request, honeypot, current_user),
            "active_tab": "monitoring",
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/{honeypot_id}/monitoring-panel")
async def honeypot_monitoring_panel(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    range_key: str = monitoring_history.DEFAULT_TIME_RANGE,
    current_user: User = Depends(get_current_user),
) -> Response:
    """The `#monitoring-content` div's own auto-poll/live-update fetch
    target (see honeypots/monitoring.html) — a plain re-read of whatever's
    currently in the DB, no SSH round trip. Distinct from `POST .../
    monitoring/refresh` below, which forces a fresh sample first."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    context = await _build_monitoring_context(honeypot, range_key, db)
    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request, "partials/honeypot_monitoring_content.html", {**context, "csrf_token": csrf_token}
    )


@router.post(
    "/{honeypot_id}/monitoring/refresh", dependencies=[_manage, Depends(verify_csrf)]
)
async def refresh_monitoring_endpoint(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    range_key: str = Form(monitoring_history.DEFAULT_TIME_RANGE),
    current_user: User = Depends(get_current_user),
) -> Response:
    """"Refresh now" on the Monitoring tab — forces both an immediate
    CPU/RAM/OpenCanary sample and an immediate reachability check (the
    tab's two independent data sources, see `_build_monitoring_context`),
    waits for both synchronously (same "enqueue, then block on the Celery
    result" shape `refresh_facts_endpoint` already uses), then re-renders
    the same partial the auto-poll panel does."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    settings = get_settings()

    monitoring_result = tasks.sample_honeypot_monitoring.delay(str(honeypot.id))
    reachability_result = tasks.check_honeypot_reachability.delay(str(honeypot.id))
    for async_result in (monitoring_result, reachability_result):
        try:
            await asyncio.to_thread(
                async_result.get, timeout=settings.ssh_connect_timeout + 5
            )
        except CeleryTimeoutError:
            logger.warning("refresh_monitoring_endpoint: a background job timed out")
        except Exception:
            logger.warning("refresh_monitoring_endpoint: a background job failed", exc_info=True)

    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    context = await _build_monitoring_context(honeypot, range_key, db)
    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request, "partials/honeypot_monitoring_content.html", {**context, "csrf_token": csrf_token}
    )


# --- Self-polling fragments -------------------------------------------------
#
# The Overview/Updates tabs poll these every 20-30s (see the `hx-trigger`
# attributes in detail.html/update_history.html and the templates below) so
# a periodic background sweep (reachability, facts, packages, update checks
# — all Celery Beat jobs the user never explicitly triggers) shows up on an
# already-open page without a manual reload. Each one is a plain DB read, no
# SSH round trip — cheap enough to poll on a timer, unlike the POST
# "refresh now" endpoints above/below, which do make one.


@router.get("/{honeypot_id}/status-panel")
async def honeypot_status_panel(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    return templates.TemplateResponse(
        request, "partials/honeypot_status.html", {"honeypot": honeypot}
    )


@router.get("/{honeypot_id}/facts-panel")
async def honeypot_facts_panel(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/honeypot_facts.html",
        {"honeypot": honeypot, "error": None, "csrf_token": csrf_token},
    )


@router.get("/{honeypot_id}/packages-summary-panel")
async def honeypot_packages_summary_panel(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    return templates.TemplateResponse(
        request,
        "partials/_packages_summary_inner.html",
        {
            "honeypot": honeypot,
            "package_counts": await _get_package_counts(honeypot_id, db),
            "held_count": await _get_held_count(honeypot_id, db),
        },
    )


@router.get("/{honeypot_id}/packages")
async def honeypot_packages_panel(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    pkg_q: str = "",
    pkg_source: str = "",
    held_only: bool = False,
    current_user: User = Depends(get_current_user),
) -> Response:
    """The modal body for "Show installed packages" on the honeypot detail
    page — loaded on demand via htmx rather than embedded in that page's
    initial render. Also serves the filter form's own requests, which target
    just `#packages-panel` (not the whole modal) to stay open while filtering.
    """
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "partials/honeypot_packages.html",
        {
            "honeypot": honeypot,
            "csrf_token": csrf_token,
            "packages": await _get_packages(
                honeypot_id, db, pkg_q=pkg_q, pkg_source=pkg_source, held_only=held_only
            ),
            "package_counts": await _get_package_counts(honeypot_id, db),
            "held_count": await _get_held_count(honeypot_id, db),
            "pkg_q": pkg_q,
            "pkg_source": pkg_source,
            "held_only": held_only,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/{honeypot_id}/services-summary-panel")
async def honeypot_services_summary_panel(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    return templates.TemplateResponse(
        request,
        "partials/_services_summary_inner.html",
        {"honeypot": honeypot, "service_counts": await _get_service_counts(honeypot_id, db)},
    )


@router.get("/{honeypot_id}/services")
async def honeypot_services_panel(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    svc_q: str = "",
    svc_state: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    """The modal body for "Show services" on the Monitoring tab — same
    lazily-loaded-on-open pattern as `honeypot_packages_panel`."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "partials/honeypot_services.html",
        {
            "honeypot": honeypot,
            "csrf_token": csrf_token,
            "services": await _get_services(honeypot_id, db, svc_q=svc_q, svc_state=svc_state),
            "service_counts": await _get_service_counts(honeypot_id, db),
            "svc_q": svc_q,
            "svc_state": svc_state,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/{honeypot_id}/edit", dependencies=[_manage])
async def edit_honeypot_form(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/edit.html",
        {
            "honeypot": honeypot,
            "tabs": _honeypot_tabs(request, honeypot, current_user),
            "active_tab": "settings",
            "auth_methods": list(AuthMethod),
            "companies": await _get_companies(db, current_user),
            "all_tags": await _get_all_tags(db),
            "errors": [],
            "csrf_token": csrf_token,
            "global_settings": get_settings(),
            "app_settings": await get_or_create_app_settings(db),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{honeypot_id}/run-onboarding", dependencies=[_manage, Depends(verify_csrf)])
async def run_onboarding_endpoint(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """See `app.ssh.onboarding` and `app.tasks.jobs._run_honeypot_onboarding`
    for what this actually runs. Blocks on the result (like "Test
    connection"/"Refresh facts" above) rather than polling: this is a
    single bounded SSH exec, not something a fleet-wide sweep repeats, and
    the honeypot's credential never leaves this process — the task resolves
    it itself from the DB, it is never passed as a task argument."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    settings = get_settings()

    async_result = tasks.run_honeypot_onboarding.delay(str(honeypot.id))
    error: str | None = None
    output: str | None = None
    try:
        # Comfortably above the task's own time_limit
        # (app.tasks.jobs._ONBOARDING_EXTRA_SECONDS + 15) so a real failure
        # inside the task — a bad password, a network hiccup — is what
        # this wait reports, not this endpoint giving up first.
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 120
        )
        if isinstance(result, dict):
            if result.get("ok"):
                output = str(result.get("output") or "")
            else:
                error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The setup script did not finish in time. Reload this page shortly."
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.onboarding.run",
        summary=f'Ran initial setup on "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    if error is None:
        # Confirm the setup actually took (ncurses-term, the sudoers
        # scope) rather than assuming success — fire-and-forget, the
        # banner on the Overview tab picks up the result on next load.
        tasks.check_honeypot_readiness.delay(str(honeypot.id))

    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/edit.html",
        {
            "honeypot": honeypot,
            "tabs": _honeypot_tabs(request, honeypot, current_user),
            "active_tab": "settings",
            "auth_methods": list(AuthMethod),
            "companies": await _get_companies(db, current_user),
            "all_tags": await _get_all_tags(db),
            "errors": [],
            "onboarding_error": error,
            "onboarding_output": output,
            "csrf_token": csrf_token,
            "global_settings": get_settings(),
            "app_settings": await get_or_create_app_settings(db),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{honeypot_id}/recheck-readiness", dependencies=[_manage, Depends(verify_csrf)])
async def recheck_readiness_endpoint(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The readiness banner's "Re-check" button — blocks on one SSH round
    trip, same "Test connection"-style pattern as the other on-demand
    checks on this page."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    settings = get_settings()

    async_result = tasks.check_honeypot_readiness.delay(str(honeypot.id))
    with contextlib.suppress(Exception):
        await asyncio.to_thread(async_result.get, timeout=settings.ssh_connect_timeout + 15)

    redirect_url = f"/honeypots/{honeypot.id}"
    if request.headers.get("HX-Request") == "true":
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": redirect_url})
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post(
    "/{honeypot_id}/run-onboarding-with-credential", dependencies=[_manage, Depends(verify_csrf)]
)
async def run_onboarding_with_credential_endpoint(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    username: str = Form(...),
    password: str = Form(...),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The readiness banner's "Fix it" flow for a honeypot that's *already*
    onboarded (SSH_KEY auth, as the app's own "honeyhive" identity) but
    missing something outside that identity's own sudo scope (e.g.
    `dmidecode`, added as a requirement after this honeypot was first
    onboarded) — `run_honeypot_onboarding` needs a root-equivalent login to
    (re-)grant that, and the app no longer has one stored for an
    already-onboarded honeypot.

    Reuses the exact same task a fresh, never-onboarded honeypot's "Run
    initial setup" button does (`run_honeypot_onboarding`), by temporarily
    putting this honeypot into the same shape a password-auth honeypot is
    already in — `auth_method=PASSWORD` + the submitted one-time
    credential — so the task's own existing logic (connect, run the
    script, and on success switch back to `honeyhive`/SSH_KEY/no stored
    secret) handles the rest unchanged. **On failure, this endpoint itself
    restores the honeypot's previous username/auth method** rather than
    leaving a real root password sitting in `secret_encrypted` on a
    honeypot this app otherwise treats as SSH_KEY-only — the task's own
    success-path revert never gets a chance to run when the script fails.
    """
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    settings = get_settings()

    previous_username = honeypot.username
    previous_auth_method = honeypot.auth_method
    honeypot.username = username.strip()
    honeypot.auth_method = AuthMethod.PASSWORD
    honeypot.secret_encrypted = encrypt_secret(password)
    await db.commit()

    async_result = tasks.run_honeypot_onboarding.delay(str(honeypot.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 120
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The setup script did not finish in time. Reload this page shortly."
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        error = str(exc)

    if error is not None:
        # The task never reached its own success-path revert — restore
        # this honeypot to what it was before this one-time attempt rather
        # than leaving it on password auth with a real credential stored.
        honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
        honeypot.username = previous_username
        honeypot.auth_method = previous_auth_method
        honeypot.secret_encrypted = None
        await db.commit()
    else:
        tasks.check_honeypot_readiness.delay(str(honeypot.id))

    await log_event(
        db,
        request=request,
        action="honeypot.onboarding.run_with_credential",
        summary=f'Ran initial setup (one-time credential) on "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    redirect_url = f"/honeypots/{honeypot.id}"
    if request.headers.get("HX-Request") == "true":
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": redirect_url})
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post(
    "/{honeypot_id}/fix-readiness-directly", dependencies=[_manage, Depends(verify_csrf)]
)
async def fix_readiness_directly_endpoint(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The readiness banner's "Install now" button for a honeypot connected
    as root — installs `ncurses-term` with the credential already on file,
    no one-time root login needed (there is nothing to grant sudo for: see
    `app.ssh.readiness`'s module docstring). Only ever shown for
    `username == "root"` (`app/web/templates/honeypots/detail.html`), but
    not re-checked here — a honeypot reconfigured to a different username
    between page load and this click just gets its own real error back
    from the SSH connection, same as any other stale-page race."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    settings = get_settings()

    async_result = tasks.fix_root_readiness.delay(str(honeypot.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 60
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "Timed out. Reload this page shortly."
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.readiness.fix_directly",
        summary=f'Installed missing readiness packages directly on "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    redirect_url = f"/honeypots/{honeypot.id}"
    if request.headers.get("HX-Request") == "true":
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": redirect_url})
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{honeypot_id}/edit", dependencies=[_manage, Depends(verify_csrf)])
async def update_honeypot(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    name: str = Form(...),
    ip_address: str = Form(...),
    port: int = Form(22),
    username: str = Form(...),
    auth_method: AuthMethod = Form(...),
    secret: str = Form(""),
    company_id: str = Form(""),
    location: str = Form(""),
    description: str = Form(""),
    runbook: str = Form(""),
    is_active: str = Form(""),
    reachability_check_interval_seconds: str = Form(""),
    facts_refresh_interval_seconds: str = Form(""),
    monitoring_interval_seconds: str = Form(""),
    monitoring_history_retention_days: str = Form(""),
    opencanary_log_poll_interval_seconds: str = Form(""),
    tags: str = Form(""),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)

    # A company-scoped account can't move a honeypot to a different
    # company at all (its own is the only one it can pick); a superadmin
    # may re-home it to any company that exists.
    resolved_company_id = (
        current_user.company_id
        if not current_user.is_superadmin
        else (uuid.UUID(company_id) if company_id else honeypot.company_id)
    )

    try:
        payload = HoneypotUpdate(
            name=name,
            ip_address=ip_address,
            port=port,
            username=username,
            auth_method=auth_method,
            secret=secret or None,
            company_id=resolved_company_id,
            location=location or None,
            description=description or None,
            runbook=runbook or None,
            # HTML only sends a checkbox field when it's checked.
            is_active=bool(is_active),
            reachability_check_interval_seconds=(
                int(reachability_check_interval_seconds)
                if reachability_check_interval_seconds.strip()
                else None
            ),
            facts_refresh_interval_seconds=(
                int(facts_refresh_interval_seconds)
                if facts_refresh_interval_seconds.strip()
                else None
            ),
            monitoring_interval_seconds=(
                int(monitoring_interval_seconds) if monitoring_interval_seconds.strip() else None
            ),
            monitoring_history_retention_days=(
                int(monitoring_history_retention_days)
                if monitoring_history_retention_days.strip()
                else None
            ),
            opencanary_log_poll_interval_seconds=(
                int(opencanary_log_poll_interval_seconds)
                if opencanary_log_poll_interval_seconds.strip()
                else None
            ),
        )
    except ValueError as exc:
        await log_event(
            db,
            request=request,
            action="honeypot.update",
            summary=f'Rejected update to "{honeypot.name}": {exc}',
            outcome=AuditOutcome.FAILURE,
            target_type="honeypot",
            target_id=honeypot.id,
            target_label=honeypot.name,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "honeypots/edit.html",
            {
                "honeypot": honeypot,
                "tabs": _honeypot_tabs(request, honeypot, current_user),
                "active_tab": "settings",
                "auth_methods": list(AuthMethod),
                "companies": await _get_companies(db, current_user),
                "all_tags": await _get_all_tags(db),
                "errors": [str(exc)],
                "csrf_token": csrf_token,
                "global_settings": get_settings(),
                "app_settings": await get_or_create_app_settings(db),
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    # Same scope rule as creation: a company-scoped account can't move a
    # honeypot to a company it can't see.
    if not has_company_access(current_user, payload.company_id, write=True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Pick a company your account has access to.",
        )

    # Changing where/how we connect invalidates the trust and facts we
    # previously established for whatever was at the old address — force
    # host-key re-discovery/re-confirmation rather than silently keeping
    # trust that no longer applies to the same physical/logical honeypot.
    connection_target_changed = (
        payload.ip_address != honeypot.ip_address or payload.port != honeypot.port
    )

    honeypot.name = payload.name
    honeypot.ip_address = payload.ip_address
    honeypot.port = payload.port
    honeypot.username = payload.username
    honeypot.auth_method = payload.auth_method
    honeypot.company_id = payload.company_id
    honeypot.location = payload.location
    honeypot.description = payload.description
    honeypot.runbook = payload.runbook
    honeypot.is_active = payload.is_active
    honeypot.reachability_check_interval_seconds = payload.reachability_check_interval_seconds
    honeypot.facts_refresh_interval_seconds = payload.facts_refresh_interval_seconds
    honeypot.monitoring_interval_seconds = payload.monitoring_interval_seconds
    honeypot.monitoring_history_retention_days = payload.monitoring_history_retention_days
    honeypot.opencanary_log_poll_interval_seconds = payload.opencanary_log_poll_interval_seconds

    if payload.auth_method == AuthMethod.PASSWORD:
        if payload.secret:
            honeypot.secret_encrypted = encrypt_secret(payload.secret)
        # else: keep whatever password is already stored, unchanged.
    else:
        # SSH_KEY doesn't need a per-honeypot secret — don't leave a stale
        # password sitting around encrypted but unused.
        honeypot.secret_encrypted = None

    if connection_target_changed:
        honeypot.host_key_fingerprint = None
        honeypot.discovered_hostname = None
        honeypot.os_version = None
        honeypot.os_id = None
        honeypot.kernel_version = None
        honeypot.cpu_cores = None
        honeypot.cpu_model = None
        honeypot.ram_bytes = None
        honeypot.ram_speed_mhz = None
        honeypot.disks = None
        honeypot.facts_updated_at = None

    await set_honeypot_tags(db, honeypot, parse_tag_names_from_text(tags))
    await db.commit()

    await log_event(
        db,
        request=request,
        action="honeypot.update",
        summary=f'Updated honeypot "{honeypot.name}"',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"connection_target_changed": connection_target_changed},
    )

    return RedirectResponse(url=f"/honeypots/{honeypot.id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{honeypot_id}/discover-host-key", dependencies=[_manage, Depends(verify_csrf)])
async def discover_host_key(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    settings = get_settings()
    csrf_token, new_cookie = get_or_create_csrf_token(request)

    context: dict[str, object] = {"honeypot": honeypot, "csrf_token": csrf_token}
    if not honeypot.ip_address:
        context["error"] = "This honeypot has no IP address configured."
    else:
        try:
            context["fingerprint"] = await discover_host_key_fingerprint(
                honeypot.ip_address, honeypot.port, settings.ssh_connect_timeout
            )
        except SSHConnectionError as exc:
            context["error"] = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.host_key.discover",
        summary=f'Discovered host key fingerprint for "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if "error" not in context else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": context["error"]} if "error" in context else None,
    )

    response = templates.TemplateResponse(request, "partials/host_key_discovery.html", context)
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{honeypot_id}/trust-host-key", dependencies=[_manage, Depends(verify_csrf)])
async def trust_host_key(
    request: Request,
    honeypot_id: uuid.UUID,
    fingerprint: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    fingerprint = fingerprint.strip()
    if not _FINGERPRINT_RE.match(fingerprint):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid fingerprint format."
        )
    honeypot.host_key_fingerprint = fingerprint
    await db.commit()

    await log_event(
        db,
        request=request,
        action="honeypot.host_key.trust",
        summary=f'Trusted host key fingerprint for "{honeypot.name}"',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"fingerprint": fingerprint},
    )

    # Now that the honeypot can be safely connected to, kick off an initial
    # facts gathering pass in the background — don't block the redirect on it.
    tasks.refresh_honeypot_facts.delay(str(honeypot.id))
    # Same idea for the readiness check — surfaces a banner on the Overview
    # tab if this honeypot (freshly onboarded through this app, or hand-
    # configured) is actually missing something this app's other features
    # depend on (see app.ssh.readiness).
    tasks.check_honeypot_readiness.delay(str(honeypot.id))

    redirect_url = f"/honeypots/{honeypot.id}"
    # The fingerprint-confirmation form only ever renders inside an htmx fragment —
    # a plain 3xx redirect would be silently followed by htmx and the returned HTML
    # would end up swapped into just that panel. HX-Redirect tells htmx to navigate
    # the whole page instead.
    if request.headers.get("HX-Request") == "true":
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": redirect_url})
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{honeypot_id}/test-connection", dependencies=[_manage, Depends(verify_csrf)])
async def test_connection_endpoint(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    settings = get_settings()

    async_result = tasks.test_honeypot_connection.delay(str(honeypot.id))
    result: dict[str, object] | None = None
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 5
        )
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        # Celery's `AsyncResult.get()` re-raises whatever exception happened
        # inside the task (propagate=True is the default) — we want to show
        # that to the user as a test failure, not crash the request.
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.test_connection",
        summary=f'Tested connection to "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    return templates.TemplateResponse(
        request,
        "partials/test_connection_result.html",
        {"honeypot": honeypot, "result": result, "error": error},
    )


@router.post("/{honeypot_id}/refresh-facts", dependencies=[_manage, Depends(verify_csrf)])
async def refresh_facts_endpoint(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    settings = get_settings()

    async_result = tasks.refresh_honeypot_facts.delay(str(honeypot.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 5
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    if error is None:
        # Facts were updated in the DB by the job — reload to pick them up.
        honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)

    await log_event(
        db,
        request=request,
        action="honeypot.facts.refresh",
        summary=f'Refreshed facts for "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    # The partial has its own "Refresh facts" button, which needs a CSRF
    # token too — reuse the one already set on this client rather than
    # minting (and trying to re-set) a fresh cookie from inside an htmx swap.
    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/honeypot_facts.html",
        {"honeypot": honeypot, "error": error, "csrf_token": csrf_token},
    )


@router.post("/{honeypot_id}/refresh-packages", dependencies=[_manage, Depends(verify_csrf)])
async def refresh_packages_endpoint(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    pkg_q: str = Form(""),
    pkg_source: str = Form(""),
    held_only: bool = Form(False),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    settings = get_settings()

    async_result = tasks.refresh_honeypot_packages.delay(str(honeypot.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 15
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    if error is None:
        # Packages were updated in the DB by the job — reload to pick them up.
        honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)

    await log_event(
        db,
        request=request,
        action="honeypot.packages.refresh",
        summary=f'Refreshed installed packages for "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/honeypot_packages.html",
        {
            "honeypot": honeypot,
            "error": error,
            "csrf_token": csrf_token,
            "packages": await _get_packages(
                honeypot_id, db, pkg_q=pkg_q, pkg_source=pkg_source, held_only=held_only
            ),
            "package_counts": await _get_package_counts(honeypot_id, db),
            "held_count": await _get_held_count(honeypot_id, db),
            "pkg_q": pkg_q,
            "pkg_source": pkg_source,
            "held_only": held_only,
        },
    )


@router.post("/{honeypot_id}/refresh-services", dependencies=[_manage, Depends(verify_csrf)])
async def refresh_services_endpoint(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    svc_q: str = Form(""),
    svc_state: str = Form(""),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    settings = get_settings()

    async_result = tasks.refresh_honeypot_services.delay(str(honeypot.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 15
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    if error is None:
        honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)

    await log_event(
        db,
        request=request,
        action="honeypot.services.refresh",
        summary=f'Refreshed services for "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/honeypot_services.html",
        {
            "honeypot": honeypot,
            "error": error,
            "csrf_token": csrf_token,
            "services": await _get_services(honeypot_id, db, svc_q=svc_q, svc_state=svc_state),
            "service_counts": await _get_service_counts(honeypot_id, db),
            "svc_q": svc_q,
            "svc_state": svc_state,
        },
    )


@router.post("/{honeypot_id}/check-updates", dependencies=[_updates, Depends(verify_csrf)])
async def check_updates_endpoint(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    settings = get_settings()

    async_result = tasks.check_honeypot_updates.delay(str(honeypot.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.update_timeout_seconds + 5
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    # Counts were updated in the DB by the job (even on failure, they're
    # reset to "unknown" rather than left stale) — reload either way.
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)

    await log_event(
        db,
        request=request,
        action="honeypot.updates.check",
        summary=f'Checked for updates on "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/update_availability.html",
        {"honeypot": honeypot, "error": error, "csrf_token": csrf_token},
    )


@router.get("/{honeypot_id}/updates/preview", dependencies=[_updates])
async def preview_honeypot_update(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    strategy: UpgradeStrategy = UpgradeStrategy.DIST_UPGRADE,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Simulate (via apt's dry-run mode — nothing is changed on the honeypot)
    exactly what `POST /honeypots/{id}/updates` would do, so a human can see
    what would be removed (the risky part of `autoremove`) before actually
    confirming it. A GET, not a POST: it's read-only against HoneyHive's
    own DB (nothing is persisted here, unlike "Check for updates now",
    which writes the counts/lists it finds) even though it does perform a
    real SSH round trip — same reasoning `/honeypots/package-search` and
    `/honeypots/{id}/updates` (history) already use for a GET that only
    reads, no CSRF token needed.

    This is the page the detail page's "Run update" button now sends you to
    first — the actual trigger (`trigger_honeypot_update` below) only ever
    fires from this page's own confirm button, or directly via the API for
    a scripted caller (see `app/web/routes/api_v1.py`'s module docstring for
    why the API doesn't get the same forced two-step)."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    if not honeypot.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before previewing updates.",
        )

    settings = get_settings()
    async_result = tasks.preview_honeypot_update.delay(str(honeypot.id), strategy.value)
    error: str | None = None
    to_install_or_upgrade: list[PendingPackage] = []
    to_remove: list[PendingPackage] = []
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.update_timeout_seconds + 5
        )
        if isinstance(result, dict):
            if not result.get("ok"):
                error = str(result.get("error") or "Unknown error.")
            else:
                to_install_or_upgrade = list(result.get("to_install_or_upgrade") or [])
                to_remove = list(result.get("to_remove") or [])
    except TimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/update_preview.html",
        {
            "honeypot": honeypot,
            "strategy": strategy,
            "error": error,
            "to_install_or_upgrade": to_install_or_upgrade,
            "to_remove": to_remove,
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{honeypot_id}/updates", dependencies=[_updates, Depends(verify_csrf)])
async def trigger_honeypot_update(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    strategy: UpgradeStrategy = Form(...),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    if not honeypot.host_key_fingerprint:
        await log_event(
            db,
            request=request,
            action="honeypot.updates.run",
            summary=f'Blocked update on "{honeypot.name}": no pinned host key',
            outcome=AuditOutcome.DENIED,
            target_type="honeypot",
            target_id=honeypot.id,
            target_label=honeypot.name,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before running updates.",
        )

    # apt update/upgrade can run for a long time — this only creates the
    # record and enqueues the job, it never waits for the result.
    run = HoneypotUpdateRun(honeypot_id=honeypot.id, strategy=strategy)
    db.add(run)
    await db.commit()
    await db.refresh(run)

    tasks.run_honeypot_update.delay(str(run.id))

    await log_event(
        db,
        request=request,
        action="honeypot.updates.run",
        summary=f'Triggered {strategy.value.replace("_", "-")} on "{honeypot.name}"',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"strategy": strategy.value, "run_id": str(run.id)},
    )

    return RedirectResponse(
        url=f"/honeypots/{honeypot.id}/updates/{run.id}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post(
    "/{honeypot_id}/updates/{run_id}/rollback", dependencies=[_updates, Depends(verify_csrf)]
)
async def rollback_honeypot_update_endpoint(
    request: Request,
    honeypot_id: uuid.UUID,
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Re-install exactly the package versions `run_id` snapshotted right
    before it ran, for whatever's since changed — see
    `app.tasks.jobs._rollback_honeypot_update`. Same `action.updates`-
    equivalent write scope as running an update itself (not a separate
    permission — undoing an update isn't a higher trust level than running
    one), and creates a brand new `HoneypotUpdateRun` row rather than
    mutating the source run, so both stay in the history exactly as they
    happened."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    source_run = await _get_update_run_or_404(run_id, db)
    if source_run.honeypot_id != honeypot.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Update run not found.")
    if source_run.status != UpdateRunStatus.SUCCEEDED or not source_run.package_snapshot:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This update run has no captured package snapshot to roll back to.",
        )
    if source_run.rollback_of_run_id is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Can't roll back a rollback."
        )

    rollback_run = HoneypotUpdateRun(
        honeypot_id=honeypot.id, strategy=source_run.strategy, rollback_of_run_id=source_run.id
    )
    db.add(rollback_run)
    await db.commit()
    await db.refresh(rollback_run)

    tasks.rollback_honeypot_update.delay(str(rollback_run.id))

    await log_event(
        db,
        request=request,
        action="honeypot.updates.rollback",
        summary=f'Triggered rollback of update run {source_run.id} on "{honeypot.name}"',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"source_run_id": str(source_run.id), "rollback_run_id": str(rollback_run.id)},
    )

    return RedirectResponse(
        url=f"/honeypots/{honeypot.id}/updates/{rollback_run.id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/{honeypot_id}/updates", dependencies=[_updates])
async def honeypot_update_history(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    status_filter: str = "",
    page: int = 1,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Every update run for this honeypot, newest first, paginated the same
    way `/audit` is (offset/limit, one extra row fetched to know whether an
    "Older" page exists) — the honeypot detail page's "Recent runs" table
    only ever shows the last 5; this is the full history behind it."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    page = max(page, 1)

    query = select(HoneypotUpdateRun).where(HoneypotUpdateRun.honeypot_id == honeypot_id)
    if status_filter in {s.value for s in UpdateRunStatus}:
        query = query.where(HoneypotUpdateRun.status == UpdateRunStatus(status_filter))

    offset = (page - 1) * _UPDATE_HISTORY_PAGE_SIZE
    result = await db.execute(
        query.order_by(HoneypotUpdateRun.created_at.desc())
        .offset(offset)
        .limit(_UPDATE_HISTORY_PAGE_SIZE + 1)
    )
    runs = list(result.scalars().all())
    has_older = len(runs) > _UPDATE_HISTORY_PAGE_SIZE
    runs = runs[:_UPDATE_HISTORY_PAGE_SIZE]

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/update_history.html",
        {
            "honeypot": honeypot,
            "tabs": _honeypot_tabs(request, honeypot, current_user),
            "active_tab": "updates",
            "csrf_token": csrf_token,
            "runs": runs,
            "statuses": list(UpdateRunStatus),
            "status_filter": status_filter,
            "page": page,
            "has_older": has_older,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/{honeypot_id}/update-availability-panel")
async def honeypot_update_availability_panel(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """See the module-level comment above `honeypot_status_panel` — this is
    the Updates tab's equivalent, polled by `partials/update_availability.html`."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/_update_availability_inner.html",
        {"honeypot": honeypot, "error": None, "csrf_token": csrf_token},
    )


@router.get("/{honeypot_id}/updates/{run_id}", dependencies=[_updates])
async def honeypot_update_run_detail(
    request: Request,
    honeypot_id: uuid.UUID,
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    run = await _get_update_run_or_404(run_id, db)
    if run.honeypot_id != honeypot.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Update run not found.")
    return templates.TemplateResponse(
        request, "honeypots/update_run.html", {"honeypot": honeypot, "run": run}
    )


@router.get("/{honeypot_id}/updates/{run_id}/status", dependencies=[_updates])
async def honeypot_update_run_status(
    request: Request,
    honeypot_id: uuid.UUID,
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Pollable fragment (htmx `hx-trigger="every ...s"`) showing one run's
    status/output. Once the run reaches a terminal state, the fragment stops
    including the polling attributes, so htmx naturally stops re-fetching it.
    """
    # Resolve the honeypot through the scoped helper first — this fragment
    # would otherwise expose an out-of-scope honeypot's update output to
    # anyone who could guess the pair of ids.
    await _get_honeypot_or_404(honeypot_id, db, current_user)
    run = await _get_update_run_or_404(run_id, db)
    if run.honeypot_id != honeypot_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Update run not found.")
    return templates.TemplateResponse(request, "partials/update_run_status.html", {"run": run})


@router.get("/{honeypot_id}/terminal", dependencies=[_terminal])
async def terminal_page(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The interactive web terminal's page shell — the actual byte relay
    happens over the WebSocket in `app/web/routes/terminal_ws.py`, which
    (since `app.auth.middleware` never runs for WebSocket requests) does its
    own independent session/permission check rather than relying on this
    page having already been reached. Gated behind `ACTION_TERMINAL` — see
    that permission's comment in `app/db/models/role.py` for why it's its
    own dedicated permission rather than folded into an existing one."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    if not honeypot.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before opening a terminal.",
        )
    return templates.TemplateResponse(
        request,
        "honeypots/terminal.html",
        {
            "honeypot": honeypot,
            "tabs": _honeypot_tabs(request, honeypot, current_user),
            "active_tab": "terminal",
        },
    )


@router.get("/{honeypot_id}/logs", dependencies=[_terminal])
async def honeypot_logs(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    path: str = "",
    browse: str = "",
    lines: int = ssh_logs.DEFAULT_LINE_LIMIT,
    search: str = "",
    since: str = "",
    until: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    """The Logs tab — three modes, switched with the row of links at the
    top: the journal (default, no `path`/`browse`), one allowed file
    (`path`, typically reached by clicking an entry from a `browse`
    listing — see "Honeypot logs" below for the one hardcoded shortcut),
    or a directory listing (`browse`) that turns "type the exact log path
    by hand" into "click `ls`'s own output" — the Logs tab's "browse
    picker". A live SSH round trip on every load/filter change, same
    "gated behind write access, not just being logged in" reasoning
    `app.ssh.logs`'s module docstring lays out; see that module for the
    command-building and path-restriction logic itself. Audited (which
    honeypot, journal/file/browse, search term) the same way "Refresh
    packages now"/"Test connection" are — not the returned log content
    itself, which is never stored anywhere in this app."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    settings = get_settings()

    output: str | None = None
    browse_entries: list[tuple[str, bool]] | None = None
    error: str | None = None
    if not honeypot.host_key_fingerprint:
        error = "Confirm the server's key fingerprint on the Overview tab first."
    elif browse.strip():
        try:
            async_result = tasks.list_honeypot_log_directory.delay(
                str(honeypot.id), path=browse.strip()
            )
            result = await asyncio.to_thread(
                async_result.get, timeout=settings.ssh_connect_timeout + 15
            )
            if isinstance(result, dict):
                if result.get("ok"):
                    browse_entries = result.get("entries") or []
                else:
                    error = str(result.get("error") or "Unknown error.")
        except CeleryTimeoutError:
            error = "The command did not finish in time."
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            error = str(exc)

        await log_event(
            db,
            request=request,
            action="honeypot.logs.browse",
            summary=f'Browsed "{browse.strip()}" on "{honeypot.name}"',
            outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
            target_type="honeypot",
            target_id=honeypot.id,
            target_label=honeypot.name,
        )
    else:
        clamped_lines = max(1, min(lines, ssh_logs.MAX_LINE_LIMIT))
        try:
            if path.strip():
                async_result = tasks.view_honeypot_log_file.delay(
                    str(honeypot.id), path=path.strip(), lines=clamped_lines, search=search
                )
            else:
                async_result = tasks.view_honeypot_journal.delay(
                    str(honeypot.id),
                    lines=clamped_lines,
                    search=search,
                    since=since,
                    until=until,
                )
            result = await asyncio.to_thread(
                async_result.get, timeout=settings.ssh_connect_timeout + 15
            )
            if isinstance(result, dict):
                if result.get("ok"):
                    output = str(result.get("output") or "")
                else:
                    error = str(result.get("error") or "Unknown error.")
        except CeleryTimeoutError:
            error = "The command did not finish in time."
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            error = str(exc)

        await log_event(
            db,
            request=request,
            action="honeypot.logs.view",
            summary=(
                f'Viewed log file "{path.strip()}" on "{honeypot.name}"'
                if path.strip()
                else f'Viewed journal on "{honeypot.name}"'
            ),
            outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
            target_type="honeypot",
            target_id=honeypot.id,
            target_label=honeypot.name,
            details={"search": search} if search.strip() else None,
        )

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/logs.html",
        {
            "honeypot": honeypot,
            "tabs": _honeypot_tabs(request, honeypot, current_user),
            "active_tab": "logs",
            "csrf_token": csrf_token,
            "output": output,
            "browse": browse,
            "browse_entries": browse_entries,
            "browse_root": settings.log_file_allowed_path_list[0]
            if settings.log_file_allowed_path_list
            else "/var/log",
            "honeypot_log_path": ssh_logs.HONEYPOT_LOG_PATH,
            "error": error,
            "path": path,
            "lines": lines,
            "search": search,
            "since": since,
            "until": until,
            "default_lines": ssh_logs.DEFAULT_LINE_LIMIT,
            "allowed_paths": settings.log_file_allowed_path_list,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


async def _build_activity_context(
    honeypot: Honeypot, range_key: str, db: AsyncSession
) -> dict[str, Any]:
    """The Activity tab's own data — same "shared by first-paint/panel/
    refresh routes" shape as `_build_monitoring_context`."""
    range_key = _normalize_range_key(range_key)
    now = datetime.now(UTC)
    since = now - monitoring_history.time_range_delta(range_key)
    windowed_result = await db.execute(
        select(HoneypotEvent)
        .where(HoneypotEvent.honeypot_id == honeypot.id, HoneypotEvent.occurred_at >= since)
        .order_by(HoneypotEvent.occurred_at)
        .limit(canary_activity_history.MAX_RAW_EVENTS)
    )
    windowed_events = list(windowed_result.scalars().all())
    activity = canary_activity_history.build_activity_history(windowed_events, range_key, now=now)

    recent_result = await db.execute(
        select(HoneypotEvent)
        .where(HoneypotEvent.honeypot_id == honeypot.id)
        .order_by(HoneypotEvent.occurred_at.desc())
        .limit(canary_activity_history.RECENT_EVENTS_LIMIT)
    )
    recent_events = canary_activity_history.summarize_recent_events(
        list(recent_result.scalars().all())
    )

    return {
        "honeypot": honeypot,
        "activity": activity,
        "recent_events": recent_events,
        "time_ranges": monitoring_history.TIME_RANGES,
        "range_key": range_key,
        "global_settings": get_settings(),
        "palette": _CHART_PALETTE,
    }


@router.get("/{honeypot_id}/status")
async def honeypot_status_tab(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    range_key: str = monitoring_history.DEFAULT_TIME_RANGE,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Activity tab — what OpenCanary has actually seen on this honeypot,
    read from its own log over SSH every `opencanary_log_poll_interval_
    seconds` (see `app.ssh.canary_activity`,
    `app.tasks.jobs.poll_honeypot_canary_log`) and stored as `HoneypotEvent`
    rows (`source="ssh_poll"`) exactly like a pushed ingest event. Same
    aggregate-chart-plus-recent-list shape as the Dashboard, but scoped to
    this one honeypot and with a time-range picker like the Monitoring
    tab's."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    context = await _build_activity_context(honeypot, range_key, db)

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/status.html",
        {
            **context,
            "tabs": _honeypot_tabs(request, honeypot, current_user),
            "active_tab": "status",
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/{honeypot_id}/activity-panel")
async def honeypot_activity_panel(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    range_key: str = monitoring_history.DEFAULT_TIME_RANGE,
    current_user: User = Depends(get_current_user),
) -> Response:
    """The `#activity-content` div's own auto-poll/live-update fetch
    target (see honeypots/status.html) — a plain re-read of whatever's
    currently in the DB, no SSH round trip."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    context = await _build_activity_context(honeypot, range_key, db)
    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request, "partials/honeypot_activity_content.html", {**context, "csrf_token": csrf_token}
    )


@router.post("/{honeypot_id}/status/refresh", dependencies=[_manage, Depends(verify_csrf)])
async def refresh_activity_endpoint(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    range_key: str = Form(monitoring_history.DEFAULT_TIME_RANGE),
    current_user: User = Depends(get_current_user),
) -> Response:
    """"Refresh now" on the Activity tab — forces an immediate OpenCanary
    log poll, waits for it synchronously, then re-renders the same
    partial the auto-poll panel does."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    settings = get_settings()

    async_result = tasks.poll_honeypot_canary_log.delay(str(honeypot.id))
    try:
        await asyncio.to_thread(async_result.get, timeout=settings.ssh_connect_timeout + 5)
    except CeleryTimeoutError:
        logger.warning("refresh_activity_endpoint: the background job timed out")
    except Exception:
        logger.warning("refresh_activity_endpoint: the background job failed", exc_info=True)

    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    context = await _build_activity_context(honeypot, range_key, db)
    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request, "partials/honeypot_activity_content.html", {**context, "csrf_token": csrf_token}
    )


_ACTIVITY_EXPORT_FIELDS = (
    "id",
    "occurred_at",
    "received_at",
    "event_type",
    "event_label",
    "src_ip",
    "src_port",
    "dst_port",
    "source",
)


@router.get("/{honeypot_id}/status/export")
async def export_honeypot_activity(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    range_key: str = "",
    format: str = "csv",  # noqa: A002
) -> Response:
    """Every `HoneypotEvent` for this honeypot, as CSV or JSON — same
    filter as the Activity tab's chart when `range_key` is one of
    `monitoring_history.TIME_RANGES`, or this honeypot's whole history
    when left blank. Same download-link pattern as the audit log's export
    (`app/web/routes/audit.py`) — a plain `<a href>`, not a POST."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)

    query = select(HoneypotEvent).where(HoneypotEvent.honeypot_id == honeypot_id)
    valid_range_keys = {key for key, _label, _delta in monitoring_history.TIME_RANGES}
    if range_key in valid_range_keys:
        since = datetime.now(UTC) - monitoring_history.time_range_delta(range_key)
        query = query.where(HoneypotEvent.occurred_at >= since)
    result = await db.execute(query.order_by(HoneypotEvent.occurred_at.asc()))
    events = list(result.scalars().all())

    await log_event(
        db,
        request=request,
        action="honeypot.activity_export",
        summary=f'Exported {len(events)} activity event(s) for "{honeypot.name}" as {format}',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"count": len(events), "format": format, "range_key": range_key},
    )

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    rows = [
        {
            "id": str(e.id),
            "occurred_at": e.occurred_at.isoformat(),
            "received_at": e.received_at.isoformat(),
            "event_type": e.event_type,
            "event_label": logtype_label(e.event_type),
            "src_ip": e.src_ip,
            "src_port": e.src_port,
            "dst_port": e.dst_port,
            "source": e.source,
        }
        for e in events
    ]

    filename_base = f"{honeypot.name}-activity-{timestamp}"
    if format == "json":
        return Response(
            content=json.dumps(rows, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename_base}.json"'},
        )

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_ACTIVITY_EXPORT_FIELDS)
    writer.writeheader()
    writer.writerows({k: _csv_safe(v) for k, v in row.items()} for row in rows)
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename_base}.csv"'},
    )


async def _load_readonly_state(
    honeypot: Honeypot, settings: Settings
) -> tuple[str | None, str | None]:
    """`(state, error)` — see `app.ssh.readonly`."""
    try:
        async_result = tasks.check_honeypot_readonly_status.delay(str(honeypot.id))
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 15
        )
        if isinstance(result, dict):
            if result.get("ok"):
                return str(result.get("state")), None
            return None, str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        return None, "The status check did not finish in time."
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        return None, str(exc)
    return None, "Unknown error."


async def _load_opencanary_config(
    honeypot: Honeypot, settings: Settings
) -> tuple[dict[str, Any] | None, str | None]:
    """`(config, error)` — a fresh SSH read of `opencanary.conf`, see
    `app.ssh.opencanary_config`'s module docstring for why this is never
    cached."""
    try:
        async_result = tasks.read_honeypot_opencanary_config.delay(str(honeypot.id))
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 15
        )
        if isinstance(result, dict):
            if result.get("ok"):
                config = result.get("config")
                return (config if isinstance(config, dict) else {}), None
            return None, str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        return None, "Reading the config did not finish in time."
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        return None, str(exc)
    return None, "Unknown error."


@router.get("/{honeypot_id}/config", dependencies=[_terminal])
async def honeypot_config_tab(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Honeypot config — the read-only root filesystem toggle (see
    `app.ssh.readonly`) and the OpenCanary module editor (see
    `app.ssh.opencanary_config`). Two independent live SSH round trips on
    every load, same as the Logs tab; nothing here is persisted."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    settings = get_settings()

    readonly_state: str | None = None
    opencanary_config: dict[str, Any] | None = None
    error: str | None = None
    if not honeypot.host_key_fingerprint:
        error = "Confirm the server's key fingerprint on the Overview tab first."
    else:
        readonly_state, readonly_error = await _load_readonly_state(honeypot, settings)
        opencanary_config, config_error = await _load_opencanary_config(honeypot, settings)
        error = readonly_error or config_error

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/config.html",
        {
            "honeypot": honeypot,
            "tabs": _honeypot_tabs(request, honeypot, current_user),
            "active_tab": "config",
            "csrf_token": csrf_token,
            "readonly_state": readonly_state,
            "opencanary_config": opencanary_config,
            "opencanary_modules": OPENCANARY_MODULES,
            "field_value": field_value,
            "module_enabled": module_enabled,
            "error": error,
            "saved": False,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post(
    "/{honeypot_id}/config/modules", dependencies=[_terminal, Depends(verify_csrf)]
)
async def save_honeypot_opencanary_config_endpoint(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Saves the OpenCanary module editor form — reads the current config
    fresh, merges the submitted values in (see
    `app.ssh.opencanary_config.apply_form_to_config` for exactly what
    "merges" means — every key this editor doesn't manage passes through
    untouched), writes it back, and restarts whatever needs restarting.
    Never a partial save: reading and writing both happen in this one
    request, no separate "stage changes then apply" step."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    settings = get_settings()

    error: str | None = None
    saved = False
    readonly_state: str | None = None
    opencanary_config: dict[str, Any] | None = None
    if not honeypot.host_key_fingerprint:
        error = "Confirm the server's key fingerprint on the Overview tab first."
    else:
        current_config, read_error = await _load_opencanary_config(honeypot, settings)
        if read_error or current_config is None:
            error = read_error or "Could not read the current config."
        else:
            form = await request.form()
            form_values = {k: str(v) for k, v in form.multi_items() if isinstance(v, str)}
            updated_config = apply_form_to_config(current_config, form_values)
            try:
                async_result = tasks.write_honeypot_opencanary_config.delay(
                    str(honeypot.id), updated_config
                )
                result = await asyncio.to_thread(
                    async_result.get, timeout=settings.ssh_connect_timeout + 60
                )
                if isinstance(result, dict):
                    if result.get("ok"):
                        saved = True
                        opencanary_config = updated_config
                    else:
                        error = str(result.get("error") or "Unknown error.")
            except CeleryTimeoutError:
                error = "Applying the config did not finish in time."
            except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                error = str(exc)

        readonly_state, readonly_error = await _load_readonly_state(honeypot, settings)
        error = error or readonly_error
        if opencanary_config is None:
            opencanary_config, _ = await _load_opencanary_config(honeypot, settings)

    await log_event(
        db,
        request=request,
        action="honeypot.opencanary_config.save",
        summary=f'Saved OpenCanary config on "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/config.html",
        {
            "honeypot": honeypot,
            "tabs": _honeypot_tabs(request, honeypot, current_user),
            "active_tab": "config",
            "csrf_token": csrf_token,
            "readonly_state": readonly_state,
            "opencanary_config": opencanary_config,
            "opencanary_modules": OPENCANARY_MODULES,
            "field_value": field_value,
            "module_enabled": module_enabled,
            "error": error,
            "saved": saved,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post(
    "/{honeypot_id}/config/readonly", dependencies=[_terminal, Depends(verify_csrf)]
)
async def set_honeypot_readonly_endpoint(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    enable: str = Form(...),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Toggles the read-only root filesystem — see `app.ssh.readonly`.
    `enable` is the literal string "true"/"false" from the two buttons on
    the Config tab, not a checkbox (there's nothing to check — each button
    is its own explicit, unambiguous action)."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    settings = get_settings()
    enable_bool = enable == "true"

    error: str | None = None
    if not honeypot.host_key_fingerprint:
        error = "Confirm the server's key fingerprint on the Overview tab first."
    else:
        try:
            async_result = tasks.set_honeypot_readonly.delay(str(honeypot.id), enable=enable_bool)
            result = await asyncio.to_thread(
                async_result.get, timeout=settings.ssh_connect_timeout + 30
            )
            if isinstance(result, dict) and not result.get("ok"):
                error = str(result.get("error") or "Unknown error.")
        except CeleryTimeoutError:
            error = "The command did not finish in time."
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            error = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.readonly.enable" if enable_bool else "honeypot.readonly.disable",
        summary=(
            f'{"Enabled" if enable_bool else "Disabled"} read-only root on "{honeypot.name}"'
        ),
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    redirect_url = f"/honeypots/{honeypot.id}/config"
    if request.headers.get("HX-Request") == "true":
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": redirect_url})
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{honeypot_id}/power")
async def power_tab(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The old "Power" tab's URL — reboot/shut down moved to Overview (see
    `honeypot_detail`), so this just redirects there instead of 404ing on
    whatever still links or is bookmarked here."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    query = f"?{request.url.query}" if request.url.query else ""
    return RedirectResponse(
        url=f"/honeypots/{honeypot.id}{query}", status_code=status.HTTP_301_MOVED_PERMANENTLY
    )


@router.get("/{honeypot_id}/power/{action}")
async def power_confirm_form(
    request: Request,
    honeypot_id: uuid.UUID,
    action: PowerAction,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """First confirmation step: a dedicated page stating exactly what's
    about to happen. The second step — typing the honeypot's name — is
    enforced server-side in `power_action`, not just disabled-until-typed
    in the browser."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/power_confirm.html",
        {"honeypot": honeypot, "action": action, "error": None, "csrf_token": csrf_token},
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{honeypot_id}/power", dependencies=[_power, Depends(verify_csrf)])
async def power_action(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    action: PowerAction = Form(...),
    confirm_name: str = Form(...),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)

    if confirm_name.strip() != honeypot.name:
        await log_event(
            db,
            request=request,
            action=f"honeypot.power.{action.value}",
            summary=f'Blocked {action.value} on "{honeypot.name}": confirmation mismatch',
            outcome=AuditOutcome.DENIED,
            target_type="honeypot",
            target_id=honeypot.id,
            target_label=honeypot.name,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "honeypots/power_confirm.html",
            {
                "honeypot": honeypot,
                "action": action,
                "error": f'That doesn\'t match — type "{honeypot.name}" exactly to confirm.',
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    if not honeypot.host_key_fingerprint:
        await log_event(
            db,
            request=request,
            action=f"honeypot.power.{action.value}",
            summary=f'Blocked {action.value} on "{honeypot.name}": no pinned host key',
            outcome=AuditOutcome.DENIED,
            target_type="honeypot",
            target_id=honeypot.id,
            target_label=honeypot.name,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before sending power commands.",
        )

    # Fire-and-forget, same reasoning as system updates: the connection can
    # legitimately drop once the honeypot actually reboots/shuts down, so
    # there's nothing meaningful to wait for here.
    tasks.send_honeypot_power_command.delay(str(honeypot.id), action.value)

    await log_event(
        db,
        request=request,
        action=f"honeypot.power.{action.value}",
        summary=f'Sent {action.value} to "{honeypot.name}"',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
    )

    return RedirectResponse(
        url=f"/honeypots/{honeypot.id}?power_sent={action.value}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/pending/{pending_id}/dismiss", dependencies=[_manage, Depends(verify_csrf)])
async def dismiss_pending_honeypot(
    request: Request, pending_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    pending = await db.get(PendingHoneypot, pending_id)
    if pending is not None:
        await db.delete(pending)
        await db.commit()
        await log_event(
            db,
            request=request,
            action="honeypot.pending.dismiss",
            summary=f'Dismissed pending honeypot "{pending.ip_address}"',
            target_type="pending_honeypot",
            target_id=pending_id,
            target_label=pending.ip_address,
        )
    return RedirectResponse(url="/honeypots", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{honeypot_id}/delete", dependencies=[_manage, Depends(verify_csrf)])
async def delete_honeypot(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    honeypot_name = honeypot.name
    await db.delete(honeypot)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="honeypot.delete",
        summary=f'Deleted honeypot "{honeypot_name}"',
        target_type="honeypot",
        target_id=honeypot_id,
        target_label=honeypot_name,
    )
    return RedirectResponse(url="/honeypots", status_code=status.HTTP_303_SEE_OTHER)
