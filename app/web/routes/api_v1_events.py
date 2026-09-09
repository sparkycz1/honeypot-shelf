"""REST API for OpenCanary events (`HoneypotEvent`) — list/filter and CSV/
JSON export, mirroring `app/web/routes/api_v1_audit.py`'s shape. Unlike the
audit log, this is company-scoped like everything else honeypot-related
(`app.auth.scope.visible_company_id`), not superadmin-only.

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
from sqlalchemy.sql import Select

from app.auth.dependencies import get_api_token_user
from app.auth.scope import visible_company_id
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.user import User
from app.db.session import get_db
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
    "company_id",
    "event_type",
    "event_label",
    "src_ip",
    "src_port",
    "dst_port",
    "source",
)


def _parse_iso(value: str) -> datetime | None:
    """Tolerant ISO-8601 parse — an unparseable `since`/`until` is ignored
    rather than rejected, same "a bad filter never 400s the whole request"
    convention `range_key` and friends already use elsewhere in this app."""
    if not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _apply_filters[S: Select[tuple[HoneypotEvent]]](
    query: S,
    user: User,
    *,
    honeypot_id: uuid.UUID | None,
    event_type: str,
    source: str,
    since: str,
    until: str,
) -> S:
    company_id = visible_company_id(user)
    if company_id is not None:
        query = query.where(HoneypotEvent.company_id == company_id)
    if honeypot_id is not None:
        query = query.where(HoneypotEvent.honeypot_id == honeypot_id)
    if event_type.strip():
        query = query.where(HoneypotEvent.event_type == event_type.strip())
    if source.strip():
        query = query.where(HoneypotEvent.source == source.strip())
    since_dt = _parse_iso(since)
    if since_dt is not None:
        query = query.where(HoneypotEvent.occurred_at >= since_dt)
    until_dt = _parse_iso(until)
    if until_dt is not None:
        query = query.where(HoneypotEvent.occurred_at <= until_dt)
    return query


def _event_to_dict(event: HoneypotEvent) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "honeypot_id": str(event.honeypot_id),
        "company_id": str(event.company_id),
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
        "company_id": str(event.company_id),
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
    since: str = "",
    until: str = "",
    page: int = 1,
) -> dict[str, object]:
    page = max(page, 1)
    query = _apply_filters(
        select(HoneypotEvent),
        user,
        honeypot_id=honeypot_id,
        event_type=event_type,
        source=source,
        since=since,
        until=until,
    )

    offset = (page - 1) * _PAGE_SIZE
    result = await db.execute(
        query.order_by(HoneypotEvent.occurred_at.desc()).offset(offset).limit(_PAGE_SIZE + 1)
    )
    events = list(result.scalars().all())
    has_older = len(events) > _PAGE_SIZE
    events = events[:_PAGE_SIZE]
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
    since: str = "",
    until: str = "",
    format: str = "csv",  # noqa: A002
) -> Response:
    """Every matching event, oldest first, as CSV or JSON — no pagination
    (same tradeoff `app/web/routes/audit.py`'s export makes: fine for an
    infrequent, filtered, script-triggered export; could be slow
    unfiltered on a very active fleet)."""
    query = _apply_filters(
        select(HoneypotEvent),
        user,
        honeypot_id=honeypot_id,
        event_type=event_type,
        source=source,
        since=since,
        until=until,
    )
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
