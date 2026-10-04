"""A honeypot's Activity tab — what OpenCanary saw, over a chosen time
window — with its self-refreshing panel, "Refresh now" and the CSV/JSON
export."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import uuid
from datetime import UTC, datetime
from typing import Any

# NOT the builtin `TimeoutError` — `celery.exceptions.TimeoutError` does not
# subclass it, so catching the builtin around `AsyncResult.get(timeout=...)`
# would silently never match and the timeout branches below would be dead code.
from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import Depends, Form, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.auth.scope import (
    can_write_honeypot,
)
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.user import User
from app.db.session import get_db
from app.services import (
    canary_activity_history,
    monitoring_history,
)
from app.services.monitoring_history import TimeWindow
from app.services.opencanary_logtypes import localized_logtype_label, logtype_label
from app.tasks import jobs as tasks
from app.web.routes.audit import _csv_safe
from app.web.routes.honeypots_common import (
    _get_honeypot_or_404,
    _honeypot_tabs,
    _window_context,
    honeypots_router,
    need_manage,
)
from app.web.templating import t, templates
from app.web.time_window import window_from_query

router = honeypots_router()


async def _build_activity_context(
    request: Request, honeypot: Honeypot, window: TimeWindow, db: AsyncSession
) -> dict[str, Any]:
    """The Activity tab's own data — same "shared by first-paint/panel/
    refresh routes" shape as `_build_monitoring_context`."""
    range_key = window.range_key
    # A custom window ends at its own `until`; a preset ends now.
    now = window.until or datetime.now(UTC)
    since = window.since

    def label_of(logtype: object) -> str:
        return localized_logtype_label(lambda key: t(request, key), logtype)

    windowed_result = await db.execute(
        select(HoneypotEvent)
        .where(
            HoneypotEvent.honeypot_id == honeypot.id,
            HoneypotEvent.occurred_at >= since,
            HoneypotEvent.occurred_at <= now,
        )
        .order_by(HoneypotEvent.occurred_at)
        .limit(canary_activity_history.MAX_RAW_EVENTS)
    )
    windowed_events = list(windowed_result.scalars().all())
    activity = canary_activity_history.build_activity_history(
        windowed_events,
        range_key,
        now=now,
        start=since if window.is_custom else None,
        label_of=label_of,
        other_label=t(request, "dashboard.activity_other"),
    )

    recent_result = await db.execute(
        select(HoneypotEvent)
        .where(HoneypotEvent.honeypot_id == honeypot.id)
        .order_by(HoneypotEvent.occurred_at.desc())
        .limit(canary_activity_history.RECENT_EVENTS_LIMIT)
    )
    recent_events = canary_activity_history.summarize_recent_events(
        list(recent_result.scalars().all()), label_of=label_of
    )

    return {
        "honeypot": honeypot,
        "activity": activity,
        "recent_events": recent_events,
        **_window_context(window),
        "app_settings": await get_or_create_app_settings(db),
        # "Refresh now" is a write action (`POST .../status/refresh`).
        "can_refresh": can_write_honeypot(request.state.user, honeypot),
    }


@router.get("/{honeypot_id}/status")
async def honeypot_status_tab(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    range_key: str = monitoring_history.DEFAULT_TIME_RANGE,
    start: str = "",
    end: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    """Activity tab — what OpenCanary has actually seen on this honeypot,
    read from its own log over SSH every `opencanary_log_poll_interval_
    seconds` (see `app.ssh.canary_activity`,
    `app.tasks.jobs.poll_honeypot_canary_log`) and stored as `HoneypotEvent`
    rows. Same aggregate-chart-plus-recent-list shape as the Dashboard, but scoped to
    this one honeypot and with a time-range picker like the Monitoring
    tab's."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    window = window_from_query(range_key, start, end)
    context = await _build_activity_context(request, honeypot, window, db)

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
    start: str = "",
    end: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    """The `#activity-content` div's own auto-poll/live-update fetch
    target (see honeypots/status.html) — a plain re-read of whatever's
    currently in the DB, no SSH round trip."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    window = window_from_query(range_key, start, end)
    context = await _build_activity_context(request, honeypot, window, db)
    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request, "partials/honeypot_activity_content.html", {**context, "csrf_token": csrf_token}
    )


@router.post("/{honeypot_id}/status/refresh", dependencies=[need_manage, Depends(verify_csrf)])
async def refresh_activity_endpoint(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    range_key: str = Form(monitoring_history.DEFAULT_TIME_RANGE),
    start: str = Form(""),
    end: str = Form(""),
    current_user: User = Depends(get_current_user),
) -> Response:
    """"Refresh now" on the Activity tab — forces an immediate OpenCanary
    log poll, waits for it synchronously, then re-renders the same
    partial the auto-poll panel does."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.poll_honeypot_canary_log.delay(str(honeypot.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 5
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.activity.refresh",
        summary=f'Refreshed activity for "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    window = window_from_query(range_key, start, end)
    context = await _build_activity_context(request, honeypot, window, db)
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
    start: str = "",
    end: str = "",
    format: str = "csv",
) -> Response:
    """Every `HoneypotEvent` for this honeypot, as CSV or JSON — same
    filter as the Activity tab's chart when `range_key` is one of
    `monitoring_history.TIME_RANGES`, or this honeypot's whole history
    when left blank. Same download-link pattern as the audit log's export
    (`app/web/routes/audit.py`) — a plain `<a href>`, not a POST."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)

    query = select(HoneypotEvent).where(HoneypotEvent.honeypot_id == honeypot_id)
    valid_range_keys = {key for key, _label, _delta in monitoring_history.TIME_RANGES}
    window = window_from_query(range_key, start, end)
    if window.is_custom or range_key in valid_range_keys:
        query = query.where(HoneypotEvent.occurred_at >= window.since)
        if window.until is not None:
            query = query.where(HoneypotEvent.occurred_at <= window.until)
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
