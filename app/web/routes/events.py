"""`/events` — OpenCanary events across every honeypot the account may
see, with filters and an export. The per-honeypot Activity tab shows one
honeypot's last events; this is where to look for "what did this address
do everywhere" or "every SSH login attempt last night".

Company-scoped like everything else honeypot-related
(`app.services.event_search`), open to any signed-in account. The REST
API has the same list and filters at `/api/v1/events`.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.auth.scope import companies_visible_to, honeypots_visible_to
from app.core.csrf import verify_csrf
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.ignored_source import IgnoredSource
from app.db.models.user import User
from app.db.session import get_db
from app.services import ignored_sources
from app.services.event_search import (
    EventFilters,
    event_types_seen,
    get_event,
    page_of_events,
    parse_uuid,
    reported_fields,
    source_summary,
)
from app.services.opencanary_logtypes import localized_logtype_label
from app.tasks import jobs as tasks
from app.web.routes.api_v1_events import export_response
from app.web.templating import parse_local_input, t, templates

router = APIRouter(prefix="/events")


def _local_time(raw: str) -> datetime | None:
    """A `datetime-local` box (app time zone) or an ISO timestamp; None for
    empty or unreadable input."""
    if not raw.strip():
        return None
    try:
        return parse_local_input(raw)
    except ValueError:
        return None


def _filters(
    honeypot_id: str,
    event_type: str,
    src_ip: str,
    country: str,
    since: str,
    until: str,
    include_ignored: str = "",
) -> EventFilters:
    return EventFilters(
        honeypot_id=parse_uuid(honeypot_id),
        event_type=event_type,
        src_ip=src_ip,
        country=country,
        since=_local_time(since),
        until=_local_time(until),
        include_ignored=bool(include_ignored),
    )


@router.get("")
async def events_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    honeypot_id: str = "",
    event_type: str = "",
    src_ip: str = "",
    country: str = "",
    since: str = "",
    until: str = "",
    include_ignored: str = "",
    page: int = 1,
) -> Response:
    page = max(page, 1)
    filters = _filters(honeypot_id, event_type, src_ip, country, since, until, include_ignored)
    events, has_older = await page_of_events(db, user, filters, page)
    honeypots = (
        await db.execute(honeypots_visible_to(user).order_by(Honeypot.name))
    ).scalars()

    def label_of(logtype: object) -> str:
        return localized_logtype_label(lambda key: t(request, key), logtype)

    # What the page was asked for, as typed — for the form, the pager and
    # the export links.
    query = {
        key: value
        for key, value in (
            ("honeypot_id", str(filters.honeypot_id or "")),
            ("event_type", event_type.strip()),
            ("src_ip", src_ip.strip()),
            ("country", country.strip().upper()),
            ("since", since.strip() if filters.since else ""),
            ("until", until.strip() if filters.until else ""),
            ("include_ignored", "1" if filters.include_ignored else ""),
        )
        if value
    }
    return templates.TemplateResponse(
        request,
        "events/list.html",
        {
            "events": events,
            "label_of": label_of,
            "honeypots": list(honeypots),
            "event_types": [(value, label_of(value)) for value in await event_types_seen(db, user)],
            "filters": filters,
            "query": query,
            "query_string": urlencode(query),
            "page": page,
            "has_older": has_older,
        },
    )


@router.get("/export")
async def export_events(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    honeypot_id: str = "",
    event_type: str = "",
    src_ip: str = "",
    country: str = "",
    since: str = "",
    until: str = "",
    include_ignored: str = "",
    format: str = "csv",
) -> Response:
    """The events the page shows with these filters — all of them, not one
    page — as CSV or JSON. A plain download link, like the audit log's."""
    filters = _filters(honeypot_id, event_type, src_ip, country, since, until, include_ignored)
    response = await export_response(db, user, filters, format)
    await log_event(
        db,
        request=request,
        action="event.export",
        summary=f"Exported events as {'json' if format == 'json' else 'csv'}",
        details={
            "format": "json" if format == "json" else "csv",
            "filtered": filters.any,
        },
    )
    return response


# --- The ignore list (app.services.ignored_sources) -------------------------


async def _ignore_page(
    request: Request,
    db: AsyncSession,
    user: User,
    *,
    errors: list[str] | None = None,
    network: str = "",
    note: str = "",
    status_code: int = 200,
) -> Response:
    companies = list(
        (await db.execute(companies_visible_to(user).order_by(Company.name))).scalars()
    )
    entries = await ignored_sources.entries_visible_to(db, user)
    return templates.TemplateResponse(
        request,
        "events/ignored.html",
        {
            "entries": [
                (entry, ignored_sources.can_manage(user, entry.company_id)) for entry in entries
            ],
            "companies": [c for c in companies if user.can_write_company(c.id)],
            "can_ignore_everywhere": user.sees_every_company,
            "errors": errors or [],
            "network": network,
            "note": note,
            "csrf_token": request.state.csrf_token,
        },
        status_code=status_code,
    )


@router.get("/ignored")
async def ignored_sources_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    network: str = "",
) -> Response:
    """The ignore list. `?network=` pre-fills the form — the "Ignore this
    address" link on a source's page."""
    return await _ignore_page(request, db, user, network=network[:64])


@router.post("/ignored", dependencies=[Depends(verify_csrf)])
async def add_ignored_source(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    network: str = Form(""),
    company_id: str = Form(""),
    note: str = Form(""),
) -> Response:
    scope = parse_uuid(company_id)
    if company_id.strip() and scope is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
    if not ignored_sources.can_manage(user, scope):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Read-only access.")
    try:
        normalized = ignored_sources.parse_network(network)
    except ValueError as exc:
        return await _ignore_page(
            request, db, user, errors=[str(exc)], network=network, note=note, status_code=422
        )
    entry = IgnoredSource(
        company_id=scope,
        network=normalized,
        note=note.strip()[: ignored_sources.MAX_NOTE_LENGTH] or None,
        created_by=user.username,
    )
    db.add(entry)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return await _ignore_page(
            request,
            db,
            user,
            errors=[t(request, "events.ignored.duplicate", network=normalized)],
            network=network,
            note=note,
            status_code=422,
        )
    tasks.reapply_ignored_sources.delay()
    await log_event(
        db,
        request=request,
        action="event.ignore.add",
        summary=f"Added {normalized} to the ignore list",
        details={"network": normalized, "company_id": str(scope) if scope else None},
    )
    return RedirectResponse(url="/events/ignored", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/ignored/{entry_id}/delete", dependencies=[Depends(verify_csrf)])
async def delete_ignored_source(
    request: Request,
    entry_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    entry = await db.get(IgnoredSource, entry_id)
    visible = {e.id for e in await ignored_sources.entries_visible_to(db, user)}
    if entry is None or entry.id not in visible:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
    if not ignored_sources.can_manage(user, entry.company_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Read-only access.")
    network = entry.network
    await db.delete(entry)
    await db.commit()
    tasks.reapply_ignored_sources.delay()
    await log_event(
        db,
        request=request,
        action="event.ignore.remove",
        summary=f"Removed {network} from the ignore list",
        details={"network": network},
    )
    return RedirectResponse(url="/events/ignored", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/source/{src_ip:path}")
async def event_source(
    request: Request,
    src_ip: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    """Everything one source address did on the honeypots the account may
    see: when, where, what kinds of events, which credentials it tried."""
    summary = await source_summary(db, user, src_ip[:64])
    if summary is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such source.")

    def label_of(logtype: object) -> str:
        return localized_logtype_label(lambda key: t(request, key), logtype)

    networks = ignored_sources._as_networks(await ignored_sources.entries_visible_to(db, user))
    return templates.TemplateResponse(
        request,
        "events/source.html",
        {
            "source": summary,
            "label_of": label_of,
            "on_ignore_list": ignored_sources.matches(summary.src_ip, networks),
            "can_ignore": user.can_write(),
        },
    )


@router.get("/{event_id}")
async def event_detail(
    request: Request,
    event_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    """One event in full: what was promoted to columns, what OpenCanary
    recorded about the attempt (`logdata` — the credentials tried, the
    client, the path), and the untouched payload."""
    event = await get_event(db, user, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")
    return templates.TemplateResponse(
        request,
        "events/detail.html",
        {
            "event": event,
            "label": localized_logtype_label(lambda key: t(request, key), event.event_type),
            "reported": reported_fields(event),
            "raw_json": json.dumps(event.raw, indent=2, ensure_ascii=False, sort_keys=True),
        },
    )
