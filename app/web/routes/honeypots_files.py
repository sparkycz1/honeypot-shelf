"""The "Watched files" page of a honeypot (`app.services.watched_files`).
Ported from debcontrol's `machines_files`.

Everyone who can see the honeypot sees which files are watched and when
they last changed. The diff itself — file content — and editing the list
are for accounts that may write the honeypot.
"""

from __future__ import annotations

import asyncio
import uuid

from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.auth.scope import can_write_honeypot
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.honeypot import Honeypot
from app.db.models.user import User
from app.db.session import get_db
from app.services import watched_files
from app.tasks import jobs as tasks
from app.web.routes.honeypots_common import (
    _get_honeypot_or_404,
    _get_writable_honeypot_or_404,
    _honeypot_tabs,
    honeypots_router,
    need_manage,
)
from app.web.templating import templates

router = honeypots_router()


async def _render(
    request: Request,
    db: AsyncSession,
    honeypot: Honeypot,
    user: User,
    *,
    diff: uuid.UUID | None = None,
    paths_text: str | None = None,
    error: str | None = None,
    notice: str | None = None,
    checked: int | None = None,
) -> Response:
    rows = await watched_files.list_files(db, honeypot.id)
    can_manage = can_write_honeypot(user, honeypot)
    shown = next((row for row in rows if row.id == diff), None) if can_manage and diff else None
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/files.html",
        {
            "honeypot": honeypot,
            "tabs": _honeypot_tabs(request, honeypot, user),
            "active_tab": "overview",
            "files": rows,
            "can_manage": can_manage,
            "uses_defaults": not honeypot.watched_files_customized,
            "diff_file": shown,
            "diff_lines": watched_files.diff_of(shown) if shown is not None else [],
            "paths_text": (
                paths_text if paths_text is not None else "\n".join(row.path for row in rows)
            ),
            "max_files": watched_files.MAX_FILES,
            "max_kib": watched_files.MAX_BYTES // 1024,
            "notice": notice,
            "checked": checked,
            "error": error,
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/{honeypot_id}/files")
async def watched_files_page(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    diff: uuid.UUID | None = None,
    saved: int = 0,
    checked: int | None = None,
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    return await _render(
        request,
        db,
        honeypot,
        current_user,
        diff=diff,
        notice="saved" if saved else None,
        checked=checked,
    )


@router.post("/{honeypot_id}/files", dependencies=[need_manage, Depends(verify_csrf)])
async def save_watched_files(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    paths: str = Form(""),
) -> Response:
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, current_user)
    try:
        wanted = watched_files.parse_paths(paths)
    except watched_files.WatchedFilesError as exc:
        return await _render(
            request, db, honeypot, current_user, paths_text=paths, error=str(exc)
        )
    added, removed = await watched_files.set_paths(db, honeypot, wanted)
    if added or removed:
        await log_event(
            db,
            request=request,
            action="honeypot.watched_files.update",
            summary=f'Changed the watched files of "{honeypot.name}"',
            target_type="honeypot",
            target_id=honeypot.id,
            target_label=honeypot.name,
            details={"file": wanted, "added": added, "removed": removed},
        )
    if wanted and honeypot.host_key_fingerprint:
        tasks.check_watched_files.delay(str(honeypot.id))
    return RedirectResponse(
        url=f"/honeypots/{honeypot.id}/files?saved=1", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/{honeypot_id}/files/check", dependencies=[need_manage, Depends(verify_csrf)])
async def check_watched_files_now(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Read the files now and wait for the answer."""
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, current_user)
    if not honeypot.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint first.",
        )
    app_settings = await get_or_create_app_settings(db)
    error: str | None = None
    changed = 0
    try:
        result = await asyncio.to_thread(
            tasks.check_watched_files.delay(str(honeypot.id)).get,
            timeout=app_settings.ssh_connect_timeout + 90,
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
        elif isinstance(result, dict):
            changed = int(result.get("changed") or 0)
    except CeleryTimeoutError:
        error = "Reading the files did not finish in time."
    if error is not None:
        return await _render(request, db, honeypot, current_user, error=error)
    return RedirectResponse(
        url=f"/honeypots/{honeypot.id}/files?checked={changed}",
        status_code=status.HTTP_303_SEE_OTHER,
    )
