"""A honeypot's Logs tab (journal, log files, OpenCanary's own log) and the
Terminal page."""

from __future__ import annotations

import asyncio
import uuid

# NOT the builtin `TimeoutError` — `celery.exceptions.TimeoutError` does not
# subclass it, so catching the builtin around `AsyncResult.get(timeout=...)`
# would silently never match and the timeout branches below would be dead code.
from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.core.app_settings import get_or_create_app_settings
from app.core.config import get_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie
from app.db.models.audit_log import AuditOutcome
from app.db.models.user import User
from app.db.session import get_db
from app.ssh import logs as ssh_logs
from app.tasks import jobs as tasks
from app.web.log_lines import journal_log_lines, parse_log_lines
from app.web.routes.honeypots_common import (
    _get_honeypot_or_404,
    _honeypot_tabs,
    honeypots_router,
    need_terminal,
)
from app.web.templating import templates

router = honeypots_router()


@router.get("/{honeypot_id}/terminal", dependencies=[need_terminal])
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


def _resolve_log_source(
    source: str, path: str, browse: str, honeypot_log_path: str
) -> tuple[str, str]:
    """Which of the Logs tab's three source cards is active — `journal`
    (default), `file` (an allowed log file, or its directory browser) or
    `honeypot` (OpenCanary's own log on this device) — and the file path
    that goes with it. A bare `?path=` (older links, the browse picker)
    is read as whichever of the two file sources that path is."""
    if browse.strip():
        return "file", path
    if source == "honeypot":
        return "honeypot", honeypot_log_path
    if source == "file":
        return "file", path
    if path.strip():
        return ("honeypot" if path.strip() == honeypot_log_path else "file"), path
    return "journal", path


@router.get("/{honeypot_id}/logs", dependencies=[need_terminal])
async def honeypot_logs(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    source: str = "",
    path: str = "",
    browse: str = "",
    lines: int = ssh_logs.DEFAULT_LINE_LIMIT,
    search: str = "",
    since: str = "",
    until: str = "",
    priority: str = "",
    unit: str = "",
    boot: str = "",
    hide_own: str = "",
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
    app_settings = await get_or_create_app_settings(db)

    output: str | None = None
    journal_entries: list[dict[str, object]] | None = None
    hidden_count = 0
    priority = ssh_logs.normalize_priority(priority)
    unit = ssh_logs.normalize_unit(unit)
    boot = ssh_logs.normalize_boot(boot)
    hide_own_sessions = hide_own.strip() not in ("", "0")
    source, path = _resolve_log_source(source, path, browse, honeypot.opencanary_log_path)
    browse_entries: list[tuple[str, bool]] | None = None
    error: str | None = None
    if not honeypot.host_key_fingerprint:
        error = "Confirm the server's key fingerprint on the Overview tab first."
    elif source == "file" and not path.strip() and not browse.strip():
        # The file source with nothing picked yet: just the form.
        pass
    elif browse.strip():
        try:
            async_result = tasks.list_honeypot_log_directory.delay(
                str(honeypot.id), path=browse.strip()
            )
            result = await asyncio.to_thread(
                async_result.get, timeout=app_settings.ssh_connect_timeout + 15
            )
            if isinstance(result, dict):
                if result.get("ok"):
                    browse_entries = result.get("entries") or []
                else:
                    error = str(result.get("error") or "Unknown error.")
        except CeleryTimeoutError:
            error = "The command did not finish in time."
        except Exception as exc:
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
                    priority=priority,
                    unit=unit,
                    boot=boot,
                    hide_own=hide_own_sessions,
                )
            result = await asyncio.to_thread(
                async_result.get, timeout=app_settings.ssh_connect_timeout + 15
            )
            if isinstance(result, dict):
                if result.get("ok"):
                    output = str(result.get("output") or "")
                    raw_entries = result.get("entries")
                    if isinstance(raw_entries, list):
                        journal_entries = [e for e in raw_entries if isinstance(e, dict)]
                    hidden_count = int(result.get("hidden") or 0)
                else:
                    error = str(result.get("error") or "Unknown error.")
        except CeleryTimeoutError:
            error = "The command did not finish in time."
        except Exception as exc:
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

    if journal_entries is not None:
        log_lines = journal_log_lines(journal_entries, search)
    else:
        log_lines = parse_log_lines(output, search)
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
            "log_lines": log_lines,
            "hidden_count": hidden_count,
            "priority": priority,
            "priorities": ssh_logs.JOURNAL_PRIORITIES,
            "unit": unit,
            "boot": boot,
            "max_boot_offset": ssh_logs.MAX_BOOT_OFFSET,
            "hide_own": hide_own_sessions,
            "source": source,
            "browse": browse,
            "browse_entries": browse_entries,
            "browse_root": settings.log_file_allowed_path_list[0]
            if settings.log_file_allowed_path_list
            else "/var/log",
            "honeypot_log_path": honeypot.opencanary_log_path,
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
