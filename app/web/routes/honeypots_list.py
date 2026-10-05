"""The honeypot list and everything addressed by a fixed path under
`/honeypots`: saved views and the view mode, adding one honeypot, CSV
import, configuration export and import, the package search, the bulk
actions and dismissing a pending honeypot."""

from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, datetime
from urllib.parse import urlparse

from fastapi import Depends, Form, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased, selectinload

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.auth.scope import (
    can_write_honeypot,
    honeypots_visible_to,
    visible_honeypots_by_ids,
)
from app.core.config import get_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.core.security import encrypt_secret
from app.db.models.audit_log import AuditOutcome
from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.honeypot_monitoring_sample import HoneypotMonitoringSample
from app.db.models.honeypot_package import HoneypotPackage
from app.db.models.honeypot_update_run import UpgradeStrategy
from app.db.models.pending_honeypot import PendingHoneypot
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.honeypot import HoneypotCreate
from app.schemas.honeypot_config import HoneypotConfigExport
from app.services.honeypot_actions import (
    send_power_to_honeypots,
    trigger_check_updates,
    trigger_updates,
)
from app.services.honeypot_config import export_honeypot_config, import_honeypot_config
from app.services.honeypot_tags import (
    add_tags_to_honeypots,
    parse_tag_names_from_text,
    remove_tags_from_honeypots,
    set_honeypot_tags,
)
from app.services.saved_views import (
    DuplicateViewNameError,
    build_query_string,
    create_saved_view,
    delete_saved_view,
    list_saved_views,
)
from app.ssh.packages import PackageSource
from app.ssh.power import PowerAction
from app.web.honeypot_search import apply_tag_filter, honeypot_search_clause
from app.web.redirects import safe_local_path
from app.web.routes.audit import _csv_safe
from app.web.routes.honeypots_common import (
    _get_all_tags,
    _get_companies,
    honeypots_router,
    need_manage,
    need_power,
    need_updates,
)
from app.web.templating import templates

router = honeypots_router()


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


# The honeypots list used to load every row unconditionally — fine at a
# handful of honeypots, but at fleet sizes in the hundreds/thousands this
# page was one unbounded `SELECT *` and a multi-thousand-row HTML response
# on every visit. Same offset/limit-plus-one-extra-row convention as
# `/audit` and the update-run history: fetch one row past the page size to
# know whether a "Next" page exists, without a separate COUNT(*) query.
_HONEYPOT_LIST_PAGE_SIZE = 100


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
    query = honeypots_visible_to(current_user)
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
    # The shape static analysis recognises as safe, on top of
    # `safe_local_path`: no backslashes, no scheme and no host — so only a
    # path on this site is left.
    target = next_path.replace("\\", "")
    parsed = urlparse(target)
    if not parsed.netloc and not parsed.scheme and target.startswith("/honeypots"):
        return safe_local_path(target, "/honeypots")
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
    # Looked up, not echoed: the cookie only ever holds one of our constants.
    chosen = {mode: mode for mode in _HONEYPOT_VIEW_MODES}.get(view, "table")
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
    preselect_company_id = request.query_params.get("company_id", "")
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
            },
            # Pre-checks one company when linked from that company's own
            # page ("Add honeypot") — still just regular checkboxes the
            # operator can change before submitting.
            "preselected_company_ids": (
                {uuid.UUID(preselect_company_id)} if preselect_company_id else set()
            ),
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("", dependencies=[need_manage, Depends(verify_csrf)])
async def create_honeypot(
    request: Request,
    db: AsyncSession = Depends(get_db),
    name: str = Form(...),
    ip_address: str = Form(...),
    port: int = Form(22222),
    username: str = Form(...),
    auth_method: AuthMethod = Form(...),
    secret: str = Form(""),
    company_ids: list[uuid.UUID] = Form(default=[]),
    location: str = Form(""),
    description: str = Form(""),
    runbook: str = Form(""),
    tags: str = Form(""),
    current_user: User = Depends(get_current_user),
) -> Response:
    # A honeypot can belong to any number of companies, including none
    # (superadmin-visible only) — never trust the client's submitted list
    # over the session's own write scope: a company-scoped account may
    # only select companies it can actually write.
    if not current_user.is_superadmin:
        company_ids = [cid for cid in company_ids if current_user.can_write_company(cid)]
    try:
        payload = HoneypotCreate(
            name=name,
            ip_address=ip_address,
            port=port,
            username=username,
            auth_method=auth_method,
            secret=secret or None,
            company_ids=company_ids,
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
                "preselected_company_ids": set(company_ids),
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    # Already narrowed to writable companies for a non-superadmin above —
    # look the (validated) ids up as real rows to attach.
    companies_result = await db.execute(select(Company).where(Company.id.in_(payload.company_ids)))
    companies = list(companies_result.scalars().all())

    honeypot = Honeypot(
        name=payload.name,
        ip_address=payload.ip_address,
        port=payload.port,
        username=payload.username,
        auth_method=payload.auth_method,
        secret_encrypted=encrypt_secret(payload.secret) if payload.secret else None,
        companies=companies,
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


@router.post("/import", dependencies=[need_manage, Depends(verify_csrf)])
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


_INVENTORY_CSV_FIELDS = (
    "name",
    "ip_address",
    "hostname",
    "companies",
    "tags",
    "status",
    "os_version",
    "kernel_version",
    "cpu_architecture",
    "cpu_cores",
    "ram_gb",
    "upgradable",
    "security_upgradable",
    "reboot_required",
    "uptime_days",
    "host_key_pinned",
    "facts_updated_at",
    "updates_checked_at",
)


def _inventory_row(honeypot: Honeypot) -> dict[str, object]:
    def iso(value: datetime | None) -> str:
        return value.isoformat() if value else ""

    def number(value: int | None) -> object:
        return "" if value is None else value

    if honeypot.is_reachable is None:
        status_label = "unknown"
    else:
        status_label = "online" if honeypot.is_reachable else "offline"
    return {
        "name": _csv_safe(honeypot.name),
        "ip_address": honeypot.ip_address or "",
        "hostname": _csv_safe(honeypot.discovered_hostname or ""),
        "companies": _csv_safe(", ".join(company.name for company in honeypot.companies)),
        "tags": _csv_safe(", ".join(tag.name for tag in honeypot.tags)),
        "status": status_label,
        "os_version": _csv_safe(honeypot.os_version or ""),
        "kernel_version": _csv_safe(honeypot.kernel_version or ""),
        "cpu_architecture": honeypot.cpu_architecture or "",
        "cpu_cores": number(honeypot.cpu_cores),
        "ram_gb": round(honeypot.ram_bytes / 1024**3, 1) if honeypot.ram_bytes else "",
        "upgradable": number(honeypot.upgradable_count),
        "security_upgradable": number(honeypot.security_upgradable_count),
        "reboot_required": "" if honeypot.reboot_required is None else honeypot.reboot_required,
        "uptime_days": (
            round(honeypot.uptime_seconds / 86400, 1) if honeypot.uptime_seconds else ""
        ),
        "host_key_pinned": bool(honeypot.host_key_fingerprint),
        "facts_updated_at": iso(honeypot.facts_updated_at),
        "updates_checked_at": iso(honeypot.updates_checked_at),
    }


@router.get("/inventory.csv")
async def export_honeypot_inventory(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    q: str = "",
    tag: list[str] = Query(default=[]),
    tag_mode: str = "or",
) -> Response:
    """The honeypot list as a spreadsheet — every honeypot matching the
    current search/tag filter (not just the visible page), with the status,
    OS, hardware and update columns an inventory report needs. Scoped
    exactly like the list itself. Unlike `/config/export` (the structural
    import/export round-trip) this is a read-only report; the same data is
    available as JSON from `GET /api/v1/honeypots`."""
    tag_mode = tag_mode if tag_mode == "and" else "or"
    query = honeypots_visible_to(current_user)
    if q.strip():
        query = query.where(honeypot_search_clause(q))
    query = apply_tag_filter(query, tag, tag_mode)
    honeypots = list((await db.execute(query.order_by(Honeypot.name))).scalars().all())

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_INVENTORY_CSV_FIELDS)
    writer.writeheader()
    for honeypot in honeypots:
        writer.writerow(_inventory_row(honeypot))

    await log_event(
        db,
        request=request,
        action="honeypot.inventory_export",
        summary=f"Exported the honeypot inventory ({len(honeypots)} honeypot(s)) as CSV",
        details={"honeypot_count": len(honeypots), "q": q or None, "tags": tag or None},
    )
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="honeypot-shelf-inventory-{timestamp}.csv"'
            )
        },
    )


@router.get("/config/export")
async def export_honeypot_config_endpoint(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    format: str = "json",
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


@router.post("/config/import", dependencies=[need_manage, Depends(verify_csrf)])
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


@router.post("/bulk/check-updates", dependencies=[need_updates, Depends(verify_csrf)])
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


@router.post("/bulk/updates", dependencies=[need_updates, Depends(verify_csrf)])
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


@router.post("/bulk/power-confirm/{action}", dependencies=[need_power, Depends(verify_csrf)])
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


@router.post("/bulk/power/{action}", dependencies=[need_power, Depends(verify_csrf)])
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


@router.post("/bulk/delete", dependencies=[need_manage, Depends(verify_csrf)])
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


async def _bulk_change_tags(
    request: Request,
    db: AsyncSession,
    user: User,
    honeypot_ids: list[uuid.UUID],
    tags: str,
    *,
    add: bool,
) -> Response:
    """Add or remove `tags` on the ticked honeypots the account may write;
    the rest of each honeypot's tags stay as they are."""
    honeypots = [
        honeypot
        for honeypot in await _get_honeypots_by_ids(honeypot_ids, db, user)
        if can_write_honeypot(user, honeypot)
    ]
    names = parse_tag_names_from_text(tags)
    if not honeypots or not names:
        return RedirectResponse(
            url="/honeypots?bulk_error=Select+at+least+one+honeypot+and+enter+a+tag.",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    change = add_tags_to_honeypots if add else remove_tags_from_honeypots
    await change(db, [honeypot.id for honeypot in honeypots], names)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="honeypots.bulk.tags.add" if add else "honeypots.bulk.tags.remove",
        summary=(
            f'{"Added" if add else "Removed"} tag(s) {", ".join(names)} '
            f'{"to" if add else "from"} {len(honeypots)} selected honeypot(s)'
        ),
        details={"tags": names, "honeypot_count": len(honeypots)},
    )
    return RedirectResponse(url="/honeypots", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/bulk/tags/add", dependencies=[need_manage, Depends(verify_csrf)])
async def bulk_add_tags(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    honeypot_ids: list[uuid.UUID] = Form(default=[]),
    tags: str = Form(""),
) -> Response:
    """Add one or more tags to every honeypot in an ad-hoc selection from
    the honeypot list, leaving each honeypot's other tags untouched — the
    bulk equivalent of typing into one honeypot's own tags field."""
    return await _bulk_change_tags(request, db, current_user, honeypot_ids, tags, add=True)


@router.post("/bulk/tags/remove", dependencies=[need_manage, Depends(verify_csrf)])
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
    return await _bulk_change_tags(request, db, current_user, honeypot_ids, tags, add=False)


@router.post("/pending/{pending_id}/dismiss", dependencies=[need_manage, Depends(verify_csrf)])
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
