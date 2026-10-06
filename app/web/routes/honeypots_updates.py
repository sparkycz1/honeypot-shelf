"""A honeypot's Updates tab: check for updates, preview, run and roll back
an update, and the run history with its live status."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any
from urllib.parse import quote

# NOT the builtin `TimeoutError` — `celery.exceptions.TimeoutError` does not
# subclass it, so catching the builtin around `AsyncResult.get(timeout=...)`
# would silently never match and the timeout branches below would be dead code.
from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.honeypot_update_run import HoneypotUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.user import User
from app.db.session import get_db
from app.ssh.updates import PendingPackage, is_safe_package_name

# Imported as a module, not name-by-name: this file already has a route
# function called `preview_honeypot_update`, which would shadow the task of
# the same name.
from app.tasks import jobs as tasks
from app.web.routes.honeypots_common import (
    _get_honeypot_or_404,
    _get_writable_honeypot_or_404,
    _honeypot_tabs,
    honeypots_router,
    need_updates,
)
from app.web.templating import t, templates

router = honeypots_router()


_UPDATE_HISTORY_PAGE_SIZE = 50


async def _get_update_run_or_404(run_id: uuid.UUID, db: AsyncSession) -> HoneypotUpdateRun:
    run = await db.get(HoneypotUpdateRun, run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Update run not found.")
    return run


@router.post("/{honeypot_id}/check-updates", dependencies=[need_updates, Depends(verify_csrf)])
async def check_updates_endpoint(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.check_honeypot_updates.delay(str(honeypot.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.update_timeout_seconds + 5
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


@router.get("/{honeypot_id}/updates/preview", dependencies=[need_updates])
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
    confirming it. A GET, not a POST: it's read-only against Honeypot Shelf's
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

    app_settings = await get_or_create_app_settings(db)
    async_result = tasks.preview_honeypot_update.delay(str(honeypot.id), strategy.value)
    error: str | None = None
    to_install_or_upgrade: list[PendingPackage] = []
    to_remove: list[PendingPackage] = []
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.update_timeout_seconds + 5
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


@router.post("/{honeypot_id}/updates", dependencies=[need_updates, Depends(verify_csrf)])
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
    "/{honeypot_id}/updates/{run_id}/rollback", dependencies=[need_updates, Depends(verify_csrf)]
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


# The outcome of `POST .../updates/hold`, carried over its redirect as a
# code — the package name next to it is validated before it is echoed.
_HOLD_OUTCOMES = {"held": "held", "released": "released", "failed": "failed"}


async def _run_task(delayed: Any, wait_seconds: float) -> tuple[dict[str, Any], str | None]:
    """Wait for a task that answers `{"ok": ...}`. Returns (result, error)."""
    try:
        result = await asyncio.to_thread(delayed.get, timeout=wait_seconds)
    except CeleryTimeoutError:
        return {}, "The command did not finish in time."
    except Exception as exc:  # the broker or the worker itself failed
        return {}, str(exc)
    if not isinstance(result, dict) or not result.get("ok"):
        return {}, str((result or {}).get("error") or "Unknown error.")
    return result, None


@router.post("/{honeypot_id}/updates/hold", dependencies=[need_updates, Depends(verify_csrf)])
async def set_package_hold_endpoint(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    package: str = Form(""),
    hold: str = Form("1"),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Hold a package at its installed version (`apt-mark hold`) so no
    update run touches it, or release it again (`hold=0`). Same access as
    running updates. Audited as `honeypot.package.hold`/`.unhold`."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)
    package = package.strip()
    holding = hold not in ("0", "false", "")
    if not is_safe_package_name(package):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=t(request, "updates.hold.invalid_package"),
        )
    stored_names = [str(p.get("name") or "") for p in honeypot.apt_upgradable_packages or []]
    stored_names += list(honeypot.apt_held_packages or [])
    known_name = next((name for name in stored_names if name == package), "")
    _result, error = await _run_task(
        tasks.set_honeypot_package_hold.delay(str(honeypot.id), package, holding),
        app_settings.ssh_connect_timeout + 90,
    )
    await log_event(
        db,
        request=request,
        action="honeypot.package.hold" if holding else "honeypot.package.unhold",
        summary=f'{"Held" if holding else "Released"} package "{package}" on "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"package": package, **({"error": error} if error else {})},
    )
    outcome = "failed" if error is not None else ("held" if holding else "released")
    # The name shown after the redirect is taken from what is stored about
    # this honeypot (its pending and held packages), never from the form.
    url = f"/honeypots/{honeypot.id}/updates?hold={outcome}"
    if known_name:
        url += f"&package={quote(known_name, safe='')}"
    return RedirectResponse(url=url, status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{honeypot_id}/updates/changelog", dependencies=[need_updates])
async def package_changelog_page(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    package: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    """What changed in one pending apt update since the installed version —
    `apt-get changelog`, fetched live over SSH, trimmed to the new entries
    (`app.ssh.updates.fetch_changelog`). Read-only, never stored."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)
    package = package.strip()
    changelog: str | None = None
    installed: str | None = None
    error: str | None = None
    if not is_safe_package_name(package):
        error = t(request, "updates.hold.invalid_package")
    elif not honeypot.host_key_fingerprint:
        error = t(request, "honeypots.updates.history.confirm_fingerprint_hint")
    else:
        result, error = await _run_task(
            tasks.view_package_changelog.delay(str(honeypot.id), package),
            app_settings.ssh_connect_timeout + 60,
        )
        if error is None:
            changelog = str(result.get("changelog") or "")
            installed = result.get("installed_version")
    pending = next(
        (p for p in honeypot.apt_upgradable_packages or [] if p.get("name") == package), None
    )
    return templates.TemplateResponse(
        request,
        "honeypots/changelog.html",
        {
            "honeypot": honeypot,
            "tabs": _honeypot_tabs(request, honeypot, current_user),
            "active_tab": "updates",
            "package": package if is_safe_package_name(package) else "",
            "pending": pending,
            "installed_version": installed,
            "changelog": changelog,
            "error": error,
        },
    )


@router.get("/{honeypot_id}/updates", dependencies=[need_updates])
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
            "hold_outcome": _HOLD_OUTCOMES.get(request.query_params.get("hold", "")),
            "hold_package": (
                hold_package
                if is_safe_package_name(hold_package := request.query_params.get("package", ""))
                else ""
            ),
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
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, current_user)
    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/_update_availability_inner.html",
        {"honeypot": honeypot, "error": None, "csrf_token": csrf_token},
    )


@router.get("/{honeypot_id}/updates/{run_id}", dependencies=[need_updates])
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


@router.get("/{honeypot_id}/updates/{run_id}/status", dependencies=[need_updates])
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
