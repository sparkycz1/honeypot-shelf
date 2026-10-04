"""A honeypot's Monitoring tab — the charts over a chosen time window, its
self-refreshing panel and "Refresh now"."""

from __future__ import annotations

import asyncio
import uuid

# NOT the builtin `TimeoutError` — `celery.exceptions.TimeoutError` does not
# subclass it, so catching the builtin around `AsyncResult.get(timeout=...)`
# would silently never match and the timeout branches below would be dead code.
from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import Depends, Form, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.user import User
from app.db.session import get_db
from app.services import (
    monitoring_history,
)
from app.tasks import jobs as tasks
from app.web.routes.honeypots_common import (
    _build_monitoring_context,
    _get_honeypot_or_404,
    _honeypot_tabs,
    honeypots_router,
    need_manage,
)
from app.web.templating import templates
from app.web.time_window import window_from_query

router = honeypots_router()


@router.get("/{honeypot_id}/monitoring")
async def honeypot_monitoring(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    range_key: str = monitoring_history.DEFAULT_TIME_RANGE,
    start: str = "",
    end: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    """CPU/RAM/disk-usage trend graphs (see `app.services.monitoring_history`
    for the downsampling) plus the systemd services table.
    `range_key` is one of `monitoring_history.TIME_RANGES`'s keys — an
    unrecognized value quietly falls back to the default rather than
    erroring, same tolerance `status_filter` on the Updates tab already has
    for a bad query param."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    window = window_from_query(range_key, start, end)
    context = await _build_monitoring_context(honeypot, window, db, current_user)

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
    start: str = "",
    end: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    """The `#monitoring-content` div's own auto-poll/live-update fetch
    target (see honeypots/monitoring.html) — a plain re-read of whatever's
    currently in the DB, no SSH round trip. Distinct from `POST .../
    monitoring/refresh` below, which forces a fresh sample first."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    window = window_from_query(range_key, start, end)
    context = await _build_monitoring_context(honeypot, window, db, current_user)
    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request, "partials/honeypot_monitoring_content.html", {**context, "csrf_token": csrf_token}
    )


@router.post(
    "/{honeypot_id}/monitoring/refresh", dependencies=[need_manage, Depends(verify_csrf)]
)
async def refresh_monitoring_endpoint(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    range_key: str = Form(monitoring_history.DEFAULT_TIME_RANGE),
    start: str = Form(""),
    end: str = Form(""),
    current_user: User = Depends(get_current_user),
) -> Response:
    """"Refresh now" on the Monitoring tab — forces an immediate
    CPU/RAM/OpenCanary sample, an immediate reachability check and a fresh
    systemd services snapshot (everything the tab shows, see
    `_build_monitoring_context`), waits for them concurrently (same
    "enqueue, then block on the Celery result" shape
    `refresh_facts_endpoint` already uses, just gathered rather than
    sequential since no job depends on another), then
    re-renders the same partial the auto-poll panel does."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    monitoring_result = tasks.sample_honeypot_monitoring.delay(str(honeypot.id))
    reachability_result = tasks.check_honeypot_reachability.delay(str(honeypot.id))
    services_result = tasks.refresh_honeypot_services.delay(str(honeypot.id))
    error: str | None = None
    try:
        results = await asyncio.gather(
            asyncio.to_thread(
                monitoring_result.get, timeout=app_settings.ssh_connect_timeout + 5
            ),
            asyncio.to_thread(
                reachability_result.get, timeout=app_settings.ssh_connect_timeout + 5
            ),
            asyncio.to_thread(services_result.get, timeout=app_settings.ssh_connect_timeout + 5),
        )
        for result in results:
            if isinstance(result, dict) and not result.get("ok"):
                error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.monitoring.refresh",
        summary=f'Refreshed monitoring for "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    window = window_from_query(range_key, start, end)
    context = await _build_monitoring_context(honeypot, window, db, current_user)
    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request, "partials/honeypot_monitoring_content.html", {**context, "csrf_token": csrf_token}
    )
