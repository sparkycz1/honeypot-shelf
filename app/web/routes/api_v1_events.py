"""REST API for OpenCanary events (`HoneypotEvent`) — list/filter and CSV/
JSON export, mirroring `app/web/routes/api_v1_audit.py`'s shape. Unlike the
audit log, this is company-scoped like everything else honeypot-related
(`app.auth.scope.visible_company_ids`), not superadmin-only.

Referenced from `auth/account.html`'s API-tokens hint since that page was
written (`GET /api/v1/events`) — this module is what finally makes that
true; it didn't exist before.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_api_token_user
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.user import User
from app.db.session import get_db
from app.services.event_search import (
    EventFilters,
    apply_filters,
    page_of_events,
    parse_time,
)
from app.services.opencanary_logtypes import logtype_label
from app.web.routes.audit import _csv_safe

router = APIRouter(prefix="/api/v1/events")

_view = Depends(get_api_token_user)

_PAGE_SIZE = 50

_EXPORT_FIELDS = (
    "id",
    "occurred_at",
    "received_at",
    "honeypot_id",
    "companies",
    "event_type",
    "event_label",
    "src_ip",
    "src_port",
    "dst_port",
    "source",
)


def _event_to_dict(event: HoneypotEvent) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "honeypot_id": str(event.honeypot_id),
        "companies": [{"id": str(c.id), "name": c.name} for c in event.honeypot.companies],
        "event_type": event.event_type,
        "event_label": logtype_label(event.event_type),
        "occurred_at": event.occurred_at.isoformat(),
        "received_at": event.received_at.isoformat(),
        "src_ip": event.src_ip,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "source": event.source,
        "raw": event.raw,
    }


def _event_to_export_row(event: HoneypotEvent) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "occurred_at": event.occurred_at.isoformat(),
        "received_at": event.received_at.isoformat(),
        "honeypot_id": str(event.honeypot_id),
        "companies": "; ".join(c.name for c in event.honeypot.companies),
        "event_type": event.event_type,
        "event_label": logtype_label(event.event_type),
        "src_ip": event.src_ip,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "source": event.source,
    }


@router.get("", dependencies=[_view])
async def list_events_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
    honeypot_id: uuid.UUID | None = None,
    event_type: str = "",
    source: str = "",
    src_ip: str = "",
    country: str = "",
    since: str = "",
    until: str = "",
    page: int = 1,
) -> dict[str, object]:
    """Events the token's account may see, newest first, 50 per page.
    `src_ip` matches a part of the source address, `country` an ISO
    3166-1 alpha-2 code; `since`/`until` are ISO 8601."""
    page = max(page, 1)
    filters = EventFilters(
        honeypot_id=honeypot_id,
        event_type=event_type,
        source=source,
        src_ip=src_ip,
        country=country,
        since=parse_time(since),
        until=parse_time(until),
    )
    events, has_older = await page_of_events(db, user, filters, page)
    return {
        "events": [_event_to_dict(e) for e in events],
        "page": page,
        "has_older": has_older,
    }


@router.get("/export", dependencies=[_view])
async def export_events_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
    honeypot_id: uuid.UUID | None = None,
    event_type: str = "",
    source: str = "",
    src_ip: str = "",
    country: str = "",
    since: str = "",
    until: str = "",
    format: str = "csv",
) -> Response:
    """Every matching event, oldest first, as CSV or JSON — no pagination
    (same tradeoff `app/web/routes/audit.py`'s export makes: fine for an
    infrequent, filtered, script-triggered export; could be slow
    unfiltered on a very active fleet)."""
    filters = EventFilters(
        honeypot_id=honeypot_id,
        event_type=event_type,
        source=source,
        src_ip=src_ip,
        country=country,
        since=parse_time(since),
        until=parse_time(until),
    )
    return await export_response(db, user, filters, format)


async def export_response(
    db: AsyncSession, user: User, filters: EventFilters, format: str
) -> Response:
    """The export itself — shared with the web Events page's export
    links, which pass the filters of the page they are on."""
    query = apply_filters(select(HoneypotEvent), user, filters)
    result = await db.execute(query.order_by(HoneypotEvent.occurred_at.asc()))
    events = list(result.scalars().all())

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    rows = [_event_to_export_row(e) for e in events]

    if format == "json":
        return Response(
            content=json.dumps(rows, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="events-{timestamp}.json"'},
        )

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_EXPORT_FIELDS)
    writer.writeheader()
    writer.writerows({k: _csv_safe(v) for k, v in row.items()} for row in rows)
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="events-{timestamp}.csv"'},
    )
