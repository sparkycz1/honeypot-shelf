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

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.auth.scope import honeypots_visible_to
from app.db.models.honeypot import Honeypot
from app.db.models.user import User
from app.db.session import get_db
from app.services.event_search import (
    EventFilters,
    event_types_seen,
    get_event,
    page_of_events,
    parse_uuid,
    reported_fields,
)
from app.services.opencanary_logtypes import localized_logtype_label
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
    honeypot_id: str, event_type: str, src_ip: str, country: str, since: str, until: str
) -> EventFilters:
    return EventFilters(
        honeypot_id=parse_uuid(honeypot_id),
        event_type=event_type,
        src_ip=src_ip,
        country=country,
        since=_local_time(since),
        until=_local_time(until),
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
    page: int = 1,
) -> Response:
    page = max(page, 1)
    filters = _filters(honeypot_id, event_type, src_ip, country, since, until)
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
    format: str = "csv",
) -> Response:
    """The events the page shows with these filters — all of them, not one
    page — as CSV or JSON. A plain download link, like the audit log's."""
    filters = _filters(honeypot_id, event_type, src_ip, country, since, until)
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
