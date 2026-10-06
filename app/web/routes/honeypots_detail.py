"""One honeypot: the Overview and its self-refreshing panels, editing,
onboarding and readiness, host key pinning, connection test, facts and
packages refresh, power actions, delete, and acknowledging a problem."""

from __future__ import annotations

import asyncio
import contextlib
import re
import uuid
from datetime import UTC, datetime, timedelta

# NOT the builtin `TimeoutError` — `celery.exceptions.TimeoutError` does not
# subclass it, so catching the builtin around `AsyncResult.get(timeout=...)`
# would silently never match and the timeout branches below would be dead code.
from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.auth.scope import (
    can_write_honeypot,
)
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.core.security import encrypt_secret
from app.db.models.audit_log import AuditOutcome
from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.honeypot_note import MAX_NOTE_LENGTH
from app.db.models.honeypot_package import HoneypotPackage
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.honeypot import HoneypotUpdate
from app.services import (
    acknowledgements,
    honeypot_timeline,
    maintenance_windows,
)
from app.services.honeypot_notes import EmptyNoteError, add_note, delete_note
from app.services.honeypot_tags import (
    parse_tag_names_from_text,
    set_honeypot_tags,
)
from app.ssh.client import discover_host_key_fingerprint
from app.ssh.exceptions import SSHConnectionError
from app.ssh.packages import PackageSource
from app.ssh.power import PowerAction
from app.tasks import jobs as tasks
from app.web.routes.honeypots_common import (
    _get_all_tags,
    _get_companies,
    _get_honeypot_or_404,
    _get_writable_honeypot_or_404,
    _honeypot_tabs,
    honeypots_router,
    need_manage,
    need_power,
)
from app.web.templating import templates

router = honeypots_router()


# Fingerprint shaped like "SHA256:<base64...>", as returned by AsyncSSH/OpenSSH.
_FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9]+:[A-Za-z0-9+/=_-]+$")


async def _get_package_counts(honeypot_id: uuid.UUID, db: AsyncSession) -> dict[str, int]:
    result = await db.execute(
        select(HoneypotPackage.source, func.count())
        .where(HoneypotPackage.honeypot_id == honeypot_id)
        .group_by(HoneypotPackage.source)
    )
    counts = {source.value: 0 for source in PackageSource}
    total = 0
    for source, count in result.all():
        counts[source.value] = count
        total += count
    counts["total"] = total
    return counts


async def _get_held_count(honeypot_id: uuid.UUID, db: AsyncSession) -> int:
    return (
        await db.scalar(
            select(func.count())
            .select_from(HoneypotPackage)
            .where(HoneypotPackage.honeypot_id == honeypot_id, HoneypotPackage.held.is_(True))
        )
    ) or 0


async def _get_packages(
    honeypot_id: uuid.UUID,
    db: AsyncSession,
    *,
    pkg_q: str,
    pkg_source: str,
    held_only: bool = False,
) -> list[HoneypotPackage]:
    query = select(HoneypotPackage).where(HoneypotPackage.honeypot_id == honeypot_id)
    if pkg_q.strip():
        query = query.where(HoneypotPackage.name.ilike(f"%{pkg_q.strip()}%"))
    if pkg_source in {source.value for source in PackageSource}:
        query = query.where(HoneypotPackage.source == PackageSource(pkg_source))
    if held_only:
        query = query.where(HoneypotPackage.held.is_(True))
    result = await db.execute(query.order_by(HoneypotPackage.source, HoneypotPackage.name))
    return list(result.scalars().all())


@router.get("/{honeypot_id}")
async def honeypot_detail(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    can_write = can_write_honeypot(current_user, honeypot)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    # The summary line at the top: what it caught last, and how much in
    # the last day (ignored sources left out, as everywhere else).
    counted = (HoneypotEvent.honeypot_id == honeypot.id, HoneypotEvent.ignored.is_(False))
    last_event = (
        await db.execute(
            select(HoneypotEvent)
            .where(*counted)
            .order_by(HoneypotEvent.occurred_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    events_24h = (
        await db.execute(
            select(func.count())
            .select_from(HoneypotEvent)
            .where(*counted, HoneypotEvent.occurred_at >= datetime.now(UTC) - timedelta(days=1))
        )
    ).scalar_one()
    response = templates.TemplateResponse(
        request,
        "honeypots/detail.html",
        {
            "honeypot": honeypot,
            "last_event": last_event,
            "events_24h": events_24h,
            "maintenance_window": await maintenance_windows.active_window_for(db, honeypot),
            "can_acknowledge": can_write,
            # Installed packages are for the accounts that maintain the
            # honeypot; a read-only account gets neither the panel nor the
            # counts.
            "can_see_packages": can_write,
            "csrf_token": csrf_token,
            "tabs": _honeypot_tabs(request, honeypot, current_user),
            "active_tab": "overview",
            # The package *rows* themselves are deliberately not fetched
            # here — a honeypot can easily have several hundred installed
            # packages, and rendering them inline made this page slow and
            # cluttered. Only the cheap aggregate counts are needed for the
            # summary line; the full listing loads lazily into a modal (see
            # the "Show installed packages" button and
            # GET /honeypots/{id}/packages below).
            "package_counts": await _get_package_counts(honeypot_id, db) if can_write else {},
            "held_count": await _get_held_count(honeypot_id, db) if can_write else 0,
            # One-time notice after a power action redirect — not persisted
            # anywhere, just echoed back from the query string (see
            # `power_action`'s own redirect).
            "power_sent": request.query_params.get("power_sent"),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


# --- Self-polling fragments -------------------------------------------------
#
# The Overview/Updates tabs poll these every 20-30s (see the `hx-trigger`
# attributes in detail.html/update_history.html and the templates below) so
# a periodic background sweep (reachability, facts, packages, update checks
# — all Celery Beat jobs the user never explicitly triggers) shows up on an
# already-open page without a manual reload. Each one is a plain DB read, no
# SSH round trip — cheap enough to poll on a timer, unlike the POST
# "refresh now" endpoints above/below, which do make one.
@router.get("/{honeypot_id}/status-panel")
async def honeypot_status_panel(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    return templates.TemplateResponse(
        request, "partials/honeypot_status.html", {"honeypot": honeypot}
    )


@router.get("/{honeypot_id}/facts-panel")
async def honeypot_facts_panel(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/honeypot_facts.html",
        {"honeypot": honeypot, "error": None, "csrf_token": csrf_token},
    )


@router.get("/{honeypot_id}/packages-summary-panel")
async def honeypot_packages_summary_panel(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, current_user)
    return templates.TemplateResponse(
        request,
        "partials/_packages_summary_inner.html",
        {
            "honeypot": honeypot,
            "package_counts": await _get_package_counts(honeypot_id, db),
            "held_count": await _get_held_count(honeypot_id, db),
        },
    )


@router.get("/{honeypot_id}/packages")
async def honeypot_packages_panel(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    pkg_q: str = "",
    pkg_source: str = "",
    held_only: bool = False,
    current_user: User = Depends(get_current_user),
) -> Response:
    """The modal body for "Show installed packages" on the honeypot detail
    page — loaded on demand via htmx rather than embedded in that page's
    initial render. Also serves the filter form's own requests, which target
    just `#packages-panel` (not the whole modal) to stay open while filtering.
    """
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "partials/honeypot_packages.html",
        {
            "honeypot": honeypot,
            "csrf_token": csrf_token,
            "packages": await _get_packages(
                honeypot_id, db, pkg_q=pkg_q, pkg_source=pkg_source, held_only=held_only
            ),
            "package_counts": await _get_package_counts(honeypot_id, db),
            "held_count": await _get_held_count(honeypot_id, db),
            "pkg_q": pkg_q,
            "pkg_source": pkg_source,
            "held_only": held_only,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/{honeypot_id}/services")
async def honeypot_services_redirect(
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The services pop-up is gone (0.56.0 moved the table onto the Monitoring
    tab); an old link lands there instead of on a 404."""
    # Redirect to the stored honeypot's own id, not to the value from the
    # URL — and only for a honeypot this account may see.
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    return RedirectResponse(
        url=f"/honeypots/{honeypot.id}/monitoring", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/{honeypot_id}/edit", dependencies=[need_manage])
async def edit_honeypot_form(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/edit.html",
        {
            "honeypot": honeypot,
            "tabs": _honeypot_tabs(request, honeypot, current_user),
            "active_tab": "settings",
            "auth_methods": list(AuthMethod),
            "companies": await _get_companies(db, current_user),
            "selected_company_ids": {c.id for c in honeypot.companies},
            "all_tags": await _get_all_tags(db),
            "errors": [],
            "csrf_token": csrf_token,
            "app_settings": await get_or_create_app_settings(db),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{honeypot_id}/run-onboarding", dependencies=[need_manage, Depends(verify_csrf)])
async def run_onboarding_endpoint(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """See `app.ssh.onboarding` and `app.tasks.jobs._run_honeypot_onboarding`
    for what this actually runs. Blocks on the result (like "Test
    connection"/"Refresh facts" above) rather than polling: this is a
    single bounded SSH exec, not something a fleet-wide sweep repeats, and
    the honeypot's credential never leaves this process — the task resolves
    it itself from the DB, it is never passed as a task argument."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.run_honeypot_onboarding.delay(str(honeypot.id))
    error: str | None = None
    output: str | None = None
    try:
        # Comfortably above the task's own time_limit
        # (app.tasks.jobs._ONBOARDING_EXTRA_SECONDS + 15) so a real failure
        # inside the task — a bad password, a network hiccup — is what
        # this wait reports, not this endpoint giving up first.
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 120
        )
        if isinstance(result, dict):
            if result.get("ok"):
                output = str(result.get("output") or "")
            else:
                error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The setup script did not finish in time. Reload this page shortly."
    except Exception as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.onboarding.run",
        summary=f'Ran initial setup on "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    if error is None:
        # Confirm the setup actually took (ncurses-term, the sudoers
        # scope) rather than assuming success — fire-and-forget, the
        # banner on the Overview tab picks up the result on next load.
        tasks.check_honeypot_readiness.delay(str(honeypot.id))

    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/edit.html",
        {
            "honeypot": honeypot,
            "tabs": _honeypot_tabs(request, honeypot, current_user),
            "active_tab": "settings",
            "auth_methods": list(AuthMethod),
            "companies": await _get_companies(db, current_user),
            "selected_company_ids": {c.id for c in honeypot.companies},
            "all_tags": await _get_all_tags(db),
            "errors": [],
            "onboarding_error": error,
            "onboarding_output": output,
            "csrf_token": csrf_token,
            "app_settings": await get_or_create_app_settings(db),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{honeypot_id}/recheck-readiness", dependencies=[need_manage, Depends(verify_csrf)])
async def recheck_readiness_endpoint(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The readiness banner's "Re-check" button — blocks on one SSH round
    trip, same "Test connection"-style pattern as the other on-demand
    checks on this page."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.check_honeypot_readiness.delay(str(honeypot.id))
    with contextlib.suppress(Exception):
        await asyncio.to_thread(async_result.get, timeout=app_settings.ssh_connect_timeout + 15)

    redirect_url = f"/honeypots/{honeypot.id}"
    if request.headers.get("HX-Request") == "true":
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": redirect_url})
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post(
    "/{honeypot_id}/run-onboarding-with-credential",
    dependencies=[need_manage, Depends(verify_csrf)],
)
async def run_onboarding_with_credential_endpoint(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    username: str = Form(...),
    password: str = Form(...),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The readiness banner's "Fix it" flow for a honeypot that's *already*
    onboarded (SSH_KEY auth, as the app's own "honeypotshelf" identity) but
    missing something outside that identity's own sudo scope (e.g.
    `dmidecode`, added as a requirement after this honeypot was first
    onboarded) — `run_honeypot_onboarding` needs a root-equivalent login to
    (re-)grant that, and the app no longer has one stored for an
    already-onboarded honeypot.

    Reuses the exact same task a fresh, never-onboarded honeypot's "Run
    initial setup" button does (`run_honeypot_onboarding`), by temporarily
    putting this honeypot into the same shape a password-auth honeypot is
    already in — `auth_method=PASSWORD` + the submitted one-time
    credential — so the task's own existing logic (connect, run the
    script, and on success switch back to `honeypotshelf`/SSH_KEY/no stored
    secret) handles the rest unchanged. **On failure, this endpoint itself
    restores the honeypot's previous username/auth method** rather than
    leaving a real root password sitting in `secret_encrypted` on a
    honeypot this app otherwise treats as SSH_KEY-only — the task's own
    success-path revert never gets a chance to run when the script fails.
    """
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    previous_username = honeypot.username
    previous_auth_method = honeypot.auth_method
    honeypot.username = username.strip()
    honeypot.auth_method = AuthMethod.PASSWORD
    honeypot.secret_encrypted = encrypt_secret(password)
    await db.commit()

    async_result = tasks.run_honeypot_onboarding.delay(str(honeypot.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 120
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The setup script did not finish in time. Reload this page shortly."
    except Exception as exc:
        error = str(exc)

    if error is not None:
        # The task never reached its own success-path revert — restore
        # this honeypot to what it was before this one-time attempt rather
        # than leaving it on password auth with a real credential stored.
        honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
        honeypot.username = previous_username
        honeypot.auth_method = previous_auth_method
        honeypot.secret_encrypted = None
        await db.commit()
    else:
        tasks.check_honeypot_readiness.delay(str(honeypot.id))

    await log_event(
        db,
        request=request,
        action="honeypot.onboarding.run_with_credential",
        summary=f'Ran initial setup (one-time credential) on "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    redirect_url = f"/honeypots/{honeypot.id}"
    if request.headers.get("HX-Request") == "true":
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": redirect_url})
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post(
    "/{honeypot_id}/fix-readiness-directly", dependencies=[need_manage, Depends(verify_csrf)]
)
async def fix_readiness_directly_endpoint(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The readiness banner's "Install now" button for a honeypot connected
    as root — installs `ncurses-term` with the credential already on file,
    no one-time root login needed (there is nothing to grant sudo for: see
    `app.ssh.readiness`'s module docstring). Only ever shown for
    `username == "root"` (`app/web/templates/honeypots/detail.html`), but
    not re-checked here — a honeypot reconfigured to a different username
    between page load and this click just gets its own real error back
    from the SSH connection, same as any other stale-page race."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.fix_root_readiness.delay(str(honeypot.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 60
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "Timed out. Reload this page shortly."
    except Exception as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.readiness.fix_directly",
        summary=f'Installed missing readiness packages directly on "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    redirect_url = f"/honeypots/{honeypot.id}"
    if request.headers.get("HX-Request") == "true":
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": redirect_url})
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{honeypot_id}/edit", dependencies=[need_manage, Depends(verify_csrf)])
async def update_honeypot(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    name: str = Form(...),
    ip_address: str = Form(...),
    port: int = Form(22),
    username: str = Form(...),
    auth_method: AuthMethod = Form(...),
    secret: str = Form(""),
    company_ids: list[uuid.UUID] = Form(default=[]),
    location: str = Form(""),
    description: str = Form(""),
    runbook: str = Form(""),
    is_active: str = Form(""),
    reachability_check_interval_seconds: str = Form(""),
    facts_refresh_interval_seconds: str = Form(""),
    monitoring_interval_seconds: str = Form(""),
    monitoring_history_retention_days: str = Form(""),
    opencanary_log_poll_interval_seconds: str = Form(""),
    tags: str = Form(""),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)

    # A company-scoped account only ever sees/submits the companies it can
    # write (see `_get_companies`) — merge that submission with whatever
    # this honeypot is *also* attached to outside that account's scope
    # (invisible to this form, so left untouched) rather than silently
    # detaching it. A superadmin's submission fully replaces the set, same
    # as before.
    if current_user.is_superadmin:
        resolved_company_ids = set(company_ids)
    else:
        writable_ids = {c.id for c in await _get_companies(db, current_user)}
        outside_scope_ids = {c.id for c in honeypot.companies} - writable_ids
        resolved_company_ids = (set(company_ids) & writable_ids) | outside_scope_ids

    try:
        payload = HoneypotUpdate(
            name=name,
            ip_address=ip_address,
            port=port,
            username=username,
            auth_method=auth_method,
            secret=secret or None,
            company_ids=list(resolved_company_ids),
            location=location or None,
            description=description or None,
            runbook=runbook or None,
            # HTML only sends a checkbox field when it's checked.
            is_active=bool(is_active),
            reachability_check_interval_seconds=(
                int(reachability_check_interval_seconds)
                if reachability_check_interval_seconds.strip()
                else None
            ),
            facts_refresh_interval_seconds=(
                int(facts_refresh_interval_seconds)
                if facts_refresh_interval_seconds.strip()
                else None
            ),
            monitoring_interval_seconds=(
                int(monitoring_interval_seconds) if monitoring_interval_seconds.strip() else None
            ),
            monitoring_history_retention_days=(
                int(monitoring_history_retention_days)
                if monitoring_history_retention_days.strip()
                else None
            ),
            opencanary_log_poll_interval_seconds=(
                int(opencanary_log_poll_interval_seconds)
                if opencanary_log_poll_interval_seconds.strip()
                else None
            ),
        )
    except ValueError as exc:
        await log_event(
            db,
            request=request,
            action="honeypot.update",
            summary=f'Rejected update to "{honeypot.name}": {exc}',
            outcome=AuditOutcome.FAILURE,
            target_type="honeypot",
            target_id=honeypot.id,
            target_label=honeypot.name,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "honeypots/edit.html",
            {
                "honeypot": honeypot,
                "tabs": _honeypot_tabs(request, honeypot, current_user),
                "active_tab": "settings",
                "auth_methods": list(AuthMethod),
                "companies": await _get_companies(db, current_user),
                "selected_company_ids": resolved_company_ids,
                "all_tags": await _get_all_tags(db),
                "errors": [str(exc)],
                "csrf_token": csrf_token,
                "app_settings": await get_or_create_app_settings(db),
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    # Changing where/how we connect invalidates the trust and facts we
    # previously established for whatever was at the old address — force
    # host-key re-discovery/re-confirmation rather than silently keeping
    # trust that no longer applies to the same physical/logical honeypot.
    connection_target_changed = (
        payload.ip_address != honeypot.ip_address or payload.port != honeypot.port
    )

    honeypot.name = payload.name
    honeypot.ip_address = payload.ip_address
    honeypot.port = payload.port
    honeypot.username = payload.username
    honeypot.auth_method = payload.auth_method
    if payload.company_ids:
        companies_result = await db.execute(
            select(Company).where(Company.id.in_(payload.company_ids))
        )
        honeypot.companies = list(companies_result.scalars().all())
    else:
        honeypot.companies = []
    honeypot.location = payload.location
    honeypot.description = payload.description
    honeypot.runbook = payload.runbook
    honeypot.is_active = payload.is_active
    honeypot.reachability_check_interval_seconds = payload.reachability_check_interval_seconds
    honeypot.facts_refresh_interval_seconds = payload.facts_refresh_interval_seconds
    honeypot.monitoring_interval_seconds = payload.monitoring_interval_seconds
    honeypot.monitoring_history_retention_days = payload.monitoring_history_retention_days
    honeypot.opencanary_log_poll_interval_seconds = payload.opencanary_log_poll_interval_seconds

    if payload.auth_method == AuthMethod.PASSWORD:
        if payload.secret:
            honeypot.secret_encrypted = encrypt_secret(payload.secret)
        # else: keep whatever password is already stored, unchanged.
    else:
        # SSH_KEY doesn't need a per-honeypot secret — don't leave a stale
        # password sitting around encrypted but unused.
        honeypot.secret_encrypted = None

    if connection_target_changed:
        honeypot.host_key_fingerprint = None
        honeypot.host_key_changed_fingerprint = None
        honeypot.host_key_changed_at = None
        honeypot.discovered_hostname = None
        honeypot.os_version = None
        honeypot.os_id = None
        honeypot.kernel_version = None
        honeypot.cpu_cores = None
        honeypot.cpu_model = None
        honeypot.ram_bytes = None
        honeypot.ram_speed_mhz = None
        honeypot.disks = None
        honeypot.facts_updated_at = None

    await set_honeypot_tags(db, honeypot, parse_tag_names_from_text(tags))
    await db.commit()

    await log_event(
        db,
        request=request,
        action="honeypot.update",
        summary=f'Updated honeypot "{honeypot.name}"',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"connection_target_changed": connection_target_changed},
    )

    return RedirectResponse(url=f"/honeypots/{honeypot.id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{honeypot_id}/discover-host-key", dependencies=[need_manage, Depends(verify_csrf)])
async def discover_host_key(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)

    context: dict[str, object] = {"honeypot": honeypot, "csrf_token": csrf_token}
    if not honeypot.ip_address:
        context["error"] = "This honeypot has no IP address configured."
    else:
        try:
            context["fingerprint"] = await discover_host_key_fingerprint(
                honeypot.ip_address, honeypot.port, app_settings.ssh_connect_timeout
            )
        except SSHConnectionError as exc:
            context["error"] = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.host_key.discover",
        summary=f'Discovered host key fingerprint for "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if "error" not in context else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": context["error"]} if "error" in context else None,
    )

    response = templates.TemplateResponse(request, "partials/host_key_discovery.html", context)
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{honeypot_id}/trust-host-key", dependencies=[need_manage, Depends(verify_csrf)])
async def trust_host_key(
    request: Request,
    honeypot_id: uuid.UUID,
    fingerprint: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    fingerprint = fingerprint.strip()
    if not _FINGERPRINT_RE.match(fingerprint):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid fingerprint format."
        )
    previous_fingerprint = honeypot.host_key_fingerprint
    honeypot.host_key_fingerprint = fingerprint
    honeypot.host_key_changed_fingerprint = None
    honeypot.host_key_changed_at = None
    await db.commit()

    await log_event(
        db,
        request=request,
        action="honeypot.host_key.trust",
        summary=f'Trusted host key fingerprint for "{honeypot.name}"',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={
            "fingerprint": fingerprint,
            **(
                {"previous_fingerprint": previous_fingerprint}
                if previous_fingerprint and previous_fingerprint != fingerprint
                else {}
            ),
        },
    )

    # Now that the honeypot can be safely connected to, kick off an initial
    # facts gathering pass in the background — don't block the redirect on it.
    tasks.refresh_honeypot_facts.delay(str(honeypot.id))
    # Same idea for the readiness check — surfaces a banner on the Overview
    # tab if this honeypot (freshly onboarded through this app, or hand-
    # configured) is actually missing something this app's other features
    # depend on (see app.ssh.readiness).
    tasks.check_honeypot_readiness.delay(str(honeypot.id))

    redirect_url = f"/honeypots/{honeypot.id}"
    # The fingerprint-confirmation form only ever renders inside an htmx fragment —
    # a plain 3xx redirect would be silently followed by htmx and the returned HTML
    # would end up swapped into just that panel. HX-Redirect tells htmx to navigate
    # the whole page instead.
    if request.headers.get("HX-Request") == "true":
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": redirect_url})
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{honeypot_id}/test-connection", dependencies=[need_manage, Depends(verify_csrf)])
async def test_connection_endpoint(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.test_honeypot_connection.delay(str(honeypot.id))
    result: dict[str, object] | None = None
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 5
        )
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        # Celery's `AsyncResult.get()` re-raises whatever exception happened
        # inside the task (propagate=True is the default) — we want to show
        # that to the user as a test failure, not crash the request.
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.test_connection",
        summary=f'Tested connection to "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    return templates.TemplateResponse(
        request,
        "partials/test_connection_result.html",
        {"honeypot": honeypot, "result": result, "error": error},
    )


@router.post("/{honeypot_id}/refresh-facts", dependencies=[need_manage, Depends(verify_csrf)])
async def refresh_facts_endpoint(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.refresh_honeypot_facts.delay(str(honeypot.id))
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

    if error is None:
        # Facts were updated in the DB by the job — reload to pick them up.
        honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)

    await log_event(
        db,
        request=request,
        action="honeypot.facts.refresh",
        summary=f'Refreshed facts for "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    # The partial has its own "Refresh facts" button, which needs a CSRF
    # token too — reuse the one already set on this client rather than
    # minting (and trying to re-set) a fresh cookie from inside an htmx swap.
    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/honeypot_facts.html",
        {"honeypot": honeypot, "error": error, "csrf_token": csrf_token},
    )


@router.post("/{honeypot_id}/refresh-packages", dependencies=[need_manage, Depends(verify_csrf)])
async def refresh_packages_endpoint(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    pkg_q: str = Form(""),
    pkg_source: str = Form(""),
    held_only: bool = Form(False),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.refresh_honeypot_packages.delay(str(honeypot.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 15
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    if error is None:
        # Packages were updated in the DB by the job — reload to pick them up.
        honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)

    await log_event(
        db,
        request=request,
        action="honeypot.packages.refresh",
        summary=f'Refreshed installed packages for "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/honeypot_packages.html",
        {
            "honeypot": honeypot,
            "error": error,
            "csrf_token": csrf_token,
            "packages": await _get_packages(
                honeypot_id, db, pkg_q=pkg_q, pkg_source=pkg_source, held_only=held_only
            ),
            "package_counts": await _get_package_counts(honeypot_id, db),
            "held_count": await _get_held_count(honeypot_id, db),
            "pkg_q": pkg_q,
            "pkg_source": pkg_source,
            "held_only": held_only,
        },
    )


@router.get("/{honeypot_id}/power")
async def power_tab(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The old "Power" tab's URL — reboot/shut down moved to Overview (see
    `honeypot_detail`), so this just redirects there instead of 404ing on
    whatever still links or is bookmarked here."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    query = f"?{request.url.query}" if request.url.query else ""
    return RedirectResponse(
        url=f"/honeypots/{honeypot.id}{query}", status_code=status.HTTP_301_MOVED_PERMANENTLY
    )


@router.get("/{honeypot_id}/power/{action}")
async def power_confirm_form(
    request: Request,
    honeypot_id: uuid.UUID,
    action: PowerAction,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """First confirmation step: a dedicated page stating exactly what's
    about to happen. The second step — typing the honeypot's name — is
    enforced server-side in `power_action`, not just disabled-until-typed
    in the browser."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/power_confirm.html",
        {"honeypot": honeypot, "action": action, "error": None, "csrf_token": csrf_token},
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{honeypot_id}/power", dependencies=[need_power, Depends(verify_csrf)])
async def power_action(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    action: PowerAction = Form(...),
    confirm_name: str = Form(...),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)

    if confirm_name.strip() != honeypot.name:
        await log_event(
            db,
            request=request,
            action=f"honeypot.power.{action.value}",
            summary=f'Blocked {action.value} on "{honeypot.name}": confirmation mismatch',
            outcome=AuditOutcome.DENIED,
            target_type="honeypot",
            target_id=honeypot.id,
            target_label=honeypot.name,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "honeypots/power_confirm.html",
            {
                "honeypot": honeypot,
                "action": action,
                "error": f'That doesn\'t match — type "{honeypot.name}" exactly to confirm.',
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    if not honeypot.host_key_fingerprint:
        await log_event(
            db,
            request=request,
            action=f"honeypot.power.{action.value}",
            summary=f'Blocked {action.value} on "{honeypot.name}": no pinned host key',
            outcome=AuditOutcome.DENIED,
            target_type="honeypot",
            target_id=honeypot.id,
            target_label=honeypot.name,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before sending power commands.",
        )

    # Fire-and-forget, same reasoning as system updates: the connection can
    # legitimately drop once the honeypot actually reboots/shuts down, so
    # there's nothing meaningful to wait for here.
    tasks.send_honeypot_power_command.delay(str(honeypot.id), action.value)

    await log_event(
        db,
        request=request,
        action=f"honeypot.power.{action.value}",
        summary=f'Sent {action.value} to "{honeypot.name}"',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
    )

    return RedirectResponse(
        url=f"/honeypots/{honeypot.id}?power_sent={action.value}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/{honeypot_id}/delete", dependencies=[need_manage, Depends(verify_csrf)])
async def delete_honeypot(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    honeypot_name = honeypot.name
    await db.delete(honeypot)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="honeypot.delete",
        summary=f'Deleted honeypot "{honeypot_name}"',
        target_type="honeypot",
        target_id=honeypot_id,
        target_label=honeypot_name,
    )
    return RedirectResponse(url="/honeypots", status_code=status.HTTP_303_SEE_OTHER)


# --- Acknowledging a problem (app.services.acknowledgements) ---------------


@router.post("/{honeypot_id}/acknowledge", dependencies=[need_manage, Depends(verify_csrf)])
async def acknowledge_honeypot(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    duration: str = Form("until_recovered"),
    note: str = Form(""),
    current_user: User = Depends(get_current_user),
) -> Response:
    """"I know about this one": withhold alert and "unavailable"
    notifications about this honeypot until it recovers, the chosen time
    passes or someone clears it."""
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, current_user)
    try:
        hours = acknowledgements.hours_for(duration)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from None
    acknowledgements.acknowledge(honeypot, by=current_user.username, note=note, hours=hours)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="honeypot.acknowledge",
        summary=f'Acknowledged a problem on "{honeypot.name}"',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"hours": hours, "note": honeypot.acknowledged_note},
    )
    return RedirectResponse(url=f"/honeypots/{honeypot.id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{honeypot_id}/acknowledge/clear", dependencies=[need_manage, Depends(verify_csrf)])
async def clear_honeypot_acknowledgement(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, current_user)
    acknowledgements.clear(honeypot)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="honeypot.acknowledge.clear",
        summary=f'Cleared the acknowledgement on "{honeypot.name}"',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
    )
    return RedirectResponse(url=f"/honeypots/{honeypot.id}", status_code=status.HTTP_303_SEE_OTHER)


# --- History tab and notes (app.services.honeypot_timeline) ----------------


@router.get("/{honeypot_id}/history")
async def honeypot_history(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    days: int = honeypot_timeline.DEFAULT_RANGE_DAYS,
    kind: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    """The History tab — notes, update runs, reachability transitions and
    (for a superadmin) audited actions on one time line; see
    `app.services.honeypot_timeline`."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    kind = kind if kind in honeypot_timeline.TIMELINE_KINDS else ""
    timeline = await honeypot_timeline.load_timeline(
        db,
        honeypot,
        days=days,
        include_audit=current_user.is_superadmin,
        include_updates=can_write_honeypot(current_user, honeypot),
        kinds={kind} if kind else None,
    )
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/history.html",
        {
            "honeypot": honeypot,
            "tabs": _honeypot_tabs(request, honeypot, current_user),
            "active_tab": "history",
            "csrf_token": csrf_token,
            "timeline": timeline,
            "ranges": honeypot_timeline.TIMELINE_RANGES,
            "kinds": honeypot_timeline.TIMELINE_KINDS,
            "kind": kind,
            "can_add_note": can_write_honeypot(current_user, honeypot),
            "note_error": request.query_params.get("note_error"),
            "max_note_length": MAX_NOTE_LENGTH,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{honeypot_id}/notes", dependencies=[need_manage, Depends(verify_csrf)])
async def add_honeypot_note(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    body: str = Form(""),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, current_user)
    try:
        await add_note(db, request, honeypot, current_user, body)
    except EmptyNoteError:
        return RedirectResponse(
            url=f"/honeypots/{honeypot.id}/history?note_error=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/honeypots/{honeypot.id}/history", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post(
    "/{honeypot_id}/notes/{note_id}/delete", dependencies=[need_manage, Depends(verify_csrf)]
)
async def delete_honeypot_note(
    request: Request,
    honeypot_id: uuid.UUID,
    note_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, current_user)
    if not await delete_note(db, request, honeypot, note_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found.")
    return RedirectResponse(
        url=f"/honeypots/{honeypot.id}/history", status_code=status.HTTP_303_SEE_OTHER
    )
