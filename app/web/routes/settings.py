"""Settings — the app's SSH identity, background-check intervals (both
read-only, sourced from the environment), retention policies, the audit
log hash-chain verification, and the LDAP/OIDC/syslog-forwarding
configuration (see `app/db/models/app_settings.py` for why these are
Settings-page config rather than environment variables). Superadmin-only.
"""

from __future__ import annotations

import asyncio

from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import APIRouter, Depends, Form, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event, verify_chain
from app.auth.dependencies import require_superadmin
from app.core.app_settings import get_or_create_app_settings
from app.core.config import get_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.core.security import decrypt_secret, encrypt_secret
from app.db.models.app_settings import (
    DEFAULT_LDAP_USER_SEARCH_FILTER,
    DEFAULT_OIDC_SCOPES,
    DEFAULT_OIDC_USERNAME_CLAIM,
    DEFAULT_SYSLOG_PORT,
    SyslogProtocol,
)
from app.db.models.audit_log import AuditOutcome
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.session import get_db
from app.services import netbird
from app.ssh.identity import (
    activate_pending_identity,
    discard_pending_identity,
    generate_pending_identity,
    get_or_create_identity,
)
from app.tasks.jobs import push_pending_ssh_key
from app.web.templating import t, templates

router = APIRouter(prefix="/settings", dependencies=[Depends(require_superadmin)])

# Settings has three sections on one long page — a `tab` query string param
# (see wiki/Architecture.md's "Server-rendered + htmx" section for why:
# there's only ever one GET route here, not one per tab, since every POST
# handler below redirects back to /settings regardless of which tab it
# belongs to).
_TAB_KEYS = ("general", "security", "integrations", "netbird")
_VALID_TABS = set(_TAB_KEYS)
_DEFAULT_TAB = "general"


def _tabs(request: Request) -> list[tuple[str, str, str]]:
    return [
        (key, t(request, f"settings.tabs.{key}"), f"/settings?tab={key}") for key in _TAB_KEYS
    ]


def _normalize_tab(tab: str) -> str:
    """An unrecognized/missing `tab` value (a stale bookmark, a typo'd URL)
    falls back to the first tab rather than 404ing or rendering no tab's
    content at all."""
    return tab if tab in _VALID_TABS else _DEFAULT_TAB


async def _render_settings(
    request: Request,
    db: AsyncSession,
    errors: list[str],
    *,
    tab: str = _DEFAULT_TAB,
    **extra: object,
) -> Response:
    identity = await get_or_create_identity(db)
    app_settings = await get_or_create_app_settings(db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    context: dict[str, object] = {
        "identity": identity,
        "settings": get_settings(),
        "app_settings": app_settings,
        "csrf_token": csrf_token,
        "errors": errors,
        "syslog_protocols": list(SyslogProtocol),
        "tabs": _tabs(request),
        "active_tab": tab,
        **extra,
    }
    # Only fetched for the tab that actually shows it — this is a
    # subprocess round trip (app.services.netbird), not worth paying on
    # every other tab's page load/redirect.
    if tab == "netbird" and "netbird_status" not in context:
        context["netbird_status"] = await netbird.status()
        context["netbird_log"] = netbird.tail_log()
    response = templates.TemplateResponse(request, "settings/index.html", context)
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("")
async def show_settings(
    request: Request, db: AsyncSession = Depends(get_db), tab: str = _DEFAULT_TAB
) -> Response:
    return await _render_settings(request, db, [], tab=_normalize_tab(tab))


def _parse_retention_days(raw: str) -> tuple[int | None, str | None]:
    """Shared by every `update_*_retention` handler below — all four fields
    mean the same thing (empty = keep forever, otherwise a non-negative
    whole number of days). Returns `(days, error_message)`; exactly one is
    `None`."""
    stripped = raw.strip()
    if stripped == "":
        return None, None
    try:
        value = int(stripped)
        if value < 0:
            raise ValueError("must not be negative")
    except ValueError:
        return None, f'"{stripped}" isn\'t a whole number of days (0 or more).'
    return value, None


@router.post("/audit-retention", dependencies=[Depends(verify_csrf)])
async def update_audit_retention(
    request: Request,
    db: AsyncSession = Depends(get_db),
    retention_days: str = Form(""),
) -> Response:
    app_settings = await get_or_create_app_settings(db)
    new_value, error = _parse_retention_days(retention_days)
    if error:
        return await _render_settings(request, db, [error], tab="security")

    app_settings.audit_log_retention_days = new_value
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.audit_retention.update",
        summary=(
            f"Set audit log retention to {new_value} day(s)"
            if new_value is not None
            else "Set audit log retention to keep forever"
        ),
    )

    return RedirectResponse(url="/settings?tab=security", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/dashboard-trends-retention", dependencies=[Depends(verify_csrf)])
async def update_dashboard_trends_retention(
    request: Request,
    db: AsyncSession = Depends(get_db),
    retention_days: str = Form(""),
) -> Response:
    """Same shape as `update_audit_retention` above, for the daily
    per-company snapshots behind the Dashboard's trend chart — see
    `app.db.models.company_snapshot.CompanySnapshot` and
    `app.tasks.jobs.purge_old_company_snapshots`."""
    app_settings = await get_or_create_app_settings(db)
    new_value, error = _parse_retention_days(retention_days)
    if error:
        return await _render_settings(request, db, [error], tab="security")

    app_settings.dashboard_trends_retention_days = new_value
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.dashboard_trends_retention.update",
        summary=(
            f"Set dashboard trends retention to {new_value} day(s)"
            if new_value is not None
            else "Set dashboard trends retention to keep forever"
        ),
    )

    return RedirectResponse(url="/settings?tab=security", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/update-run-retention", dependencies=[Depends(verify_csrf)])
async def update_honeypot_update_run_retention(
    request: Request,
    db: AsyncSession = Depends(get_db),
    retention_days: str = Form(""),
) -> Response:
    """Same shape as the other retention handlers, for the stored
    `HoneypotUpdateRun` rows (apt/flatpak/snap output per run) — see
    `app.tasks.jobs.purge_old_honeypot_update_runs`."""
    app_settings = await get_or_create_app_settings(db)
    new_value, error = _parse_retention_days(retention_days)
    if error:
        return await _render_settings(request, db, [error], tab="security")

    app_settings.honeypot_update_run_retention_days = new_value
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.honeypot_update_run_retention.update",
        summary=(
            f"Set update run history retention to {new_value} day(s)"
            if new_value is not None
            else "Set update run history retention to keep forever"
        ),
    )

    return RedirectResponse(url="/settings?tab=security", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/monitoring-retention", dependencies=[Depends(verify_csrf)])
async def update_monitoring_retention(
    request: Request,
    db: AsyncSession = Depends(get_db),
    retention_days: str = Form(""),
) -> Response:
    """Same shape as the other retention handlers, for
    `HoneypotMonitoringSample`/`HoneypotReachabilitySample` rows — see
    `app.tasks.jobs.purge_old_monitoring_samples`. This is the
    *instance-wide* default; a honeypot can override it (see `Honeypot.
    monitoring_history_retention_days` on that honeypot's own Settings tab)."""
    app_settings = await get_or_create_app_settings(db)
    new_value, error = _parse_retention_days(retention_days)
    if error:
        return await _render_settings(request, db, [error], tab="security")

    app_settings.monitoring_history_retention_days = new_value
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.monitoring_retention.update",
        summary=(
            f"Set monitoring history retention to {new_value} day(s)"
            if new_value is not None
            else "Set monitoring history retention to keep forever"
        ),
    )

    return RedirectResponse(url="/settings?tab=security", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/audit-verify", dependencies=[Depends(verify_csrf)])
async def verify_audit_chain(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    """Recompute the audit log's hash chain on demand — see
    `app.audit.verify_chain`. Result isn't stored anywhere; it's only ever
    the answer to "is the trail intact right now."""
    result = await verify_chain(db)
    await log_event(
        db,
        request=request,
        action="audit_log.verify",
        summary=f"Verified audit log hash chain: {result.message}",
        outcome=AuditOutcome.SUCCESS if result.ok else AuditOutcome.FAILURE,
        details={"checked": result.checked, "broken_at_sequence": result.broken_at_sequence},
    )
    return await _render_settings(request, db, [], tab="security", verify_result=result)


@router.post("/ssh-key/generate", dependencies=[Depends(verify_csrf)])
async def generate_ssh_key(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    identity = await generate_pending_identity(db)
    await log_event(
        db,
        request=request,
        action="settings.ssh_key.generate",
        summary=f"Generated a replacement SSH key ({identity.pending_fingerprint})",
    )
    return RedirectResponse(url="/settings?tab=general", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/ssh-key/activate", dependencies=[Depends(verify_csrf)])
async def activate_ssh_key(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    try:
        identity = await activate_pending_identity(db)
    except ValueError:
        return await _render_settings(
            request, db, ["No pending SSH key to activate."], tab="general"
        )
    await log_event(
        db,
        request=request,
        action="settings.ssh_key.activate",
        summary=f"Activated new SSH key ({identity.fingerprint})",
    )
    return RedirectResponse(url="/settings?tab=general", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/ssh-key/discard", dependencies=[Depends(verify_csrf)])
async def discard_ssh_key(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    await discard_pending_identity(db)
    await log_event(
        db,
        request=request,
        action="settings.ssh_key.discard",
        summary="Discarded the pending (not-yet-activated) SSH key",
    )
    return RedirectResponse(url="/settings?tab=general", status_code=status.HTTP_303_SEE_OTHER)


# How long the web request waits for one honeypot's push to finish. Every
# honeypot is dispatched first and awaited concurrently (asyncio.gather) —
# a large fleet fans out in parallel instead of one slow/unreachable
# honeypot stacking its timeout onto every honeypot after it.
_PUSH_WAIT_SECONDS = 60


@router.post("/ssh-key/push", dependencies=[Depends(verify_csrf)])
async def push_ssh_key(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    """Assisted alternative to copying the pending public key onto every
    honeypot by hand: run the append-to-authorized_keys command over SSH,
    using each honeypot's *currently active* credential, on every
    `AuthMethod.SSH_KEY` honeypot with a pinned host key — across every
    company, since the shared SSH identity is fleet-wide, not
    per-company. A `PASSWORD`-auth honeypot never uses the app's shared
    identity, so it's not a candidate and isn't counted as skipped or
    failed — it's simply not in scope.

    This never touches the active key or activates anything — it only adds
    the new public key line alongside the current one, exactly like the
    manual instructions above it on this page. "Activate new key" is still
    a separate, deliberate click.
    """
    identity = await get_or_create_identity(db)
    if identity.pending_public_key is None:
        return await _render_settings(request, db, ["No pending SSH key to push."], tab="general")

    result = await db.execute(
        select(Honeypot).where(
            Honeypot.auth_method == AuthMethod.SSH_KEY,
            Honeypot.host_key_fingerprint.is_not(None),
        )
    )
    honeypots = list(result.scalars().all())
    if not honeypots:
        return await _render_settings(
            request,
            db,
            ["No honeypots use the app's shared SSH key with a pinned host key yet."],
            tab="general",
        )

    dispatched = [(h, push_pending_ssh_key.delay(str(h.id))) for h in honeypots]

    async def _await_one(honeypot: Honeypot, async_result: object) -> tuple[str, str | None]:
        try:
            outcome = await asyncio.to_thread(async_result.get, timeout=_PUSH_WAIT_SECONDS)  # type: ignore[attr-defined]
        except CeleryTimeoutError:
            return honeypot.name, "Timed out."
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            return honeypot.name, str(exc)
        if isinstance(outcome, dict) and outcome.get("ok"):
            return honeypot.name, None
        reason = str(outcome.get("error")) if isinstance(outcome, dict) else "Unknown error."
        return honeypot.name, reason

    outcomes = await asyncio.gather(
        *(_await_one(honeypot, async_result) for honeypot, async_result in dispatched)
    )
    failed = [(name, reason) for name, reason in outcomes if reason is not None]
    succeeded_count = len(outcomes) - len(failed)

    await log_event(
        db,
        request=request,
        action="settings.ssh_key.push",
        summary=f"Pushed pending SSH key to {succeeded_count}/{len(outcomes)} honeypot(s)",
        outcome=AuditOutcome.FAILURE if failed else AuditOutcome.SUCCESS,
        details={
            "fingerprint": identity.pending_fingerprint,
            "succeeded": [name for name, reason in outcomes if reason is None],
            "failed": dict(failed),
        },
    )

    errors = [f"{name}: {reason}" for name, reason in failed]
    return await _render_settings(
        request,
        db,
        errors,
        tab="general",
        push_result={"succeeded": succeeded_count, "total": len(outcomes)},
    )


@router.post("/ldap", dependencies=[Depends(verify_csrf)])
async def update_ldap_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    ldap_enabled: str = Form(""),
    ldap_server_uri: str = Form(""),
    ldap_use_starttls: str = Form(""),
    ldap_tls_verify: str = Form(""),
    ldap_bind_dn: str = Form(""),
    # Blank = keep the existing bind password unchanged — same convention as
    # Honeypot.secret_encrypted (app/schemas/honeypot.py).
    ldap_bind_password: str = Form(""),
    ldap_user_search_base: str = Form(""),
    ldap_user_search_filter: str = Form(""),
    ldap_connect_timeout_seconds: str = Form("5"),
) -> Response:
    app_settings = await get_or_create_app_settings(db)
    errors: list[str] = []

    server_uri = ldap_server_uri.strip()
    if server_uri and not (server_uri.startswith("ldap://") or server_uri.startswith("ldaps://")):
        errors.append('Server URI must start with "ldap://" or "ldaps://".')

    try:
        timeout = int(ldap_connect_timeout_seconds.strip() or "5")
        if timeout <= 0:
            raise ValueError
    except ValueError:
        errors.append("Connect timeout must be a positive whole number of seconds.")
        timeout = app_settings.ldap_connect_timeout_seconds

    search_filter = ldap_user_search_filter.strip() or DEFAULT_LDAP_USER_SEARCH_FILTER
    if "{username}" not in search_filter:
        errors.append('Search filter must contain "{username}".')

    if bool(ldap_enabled) and not (
        server_uri and ldap_bind_dn.strip() and ldap_user_search_base.strip()
    ):
        errors.append("Enabling LDAP needs at least a server URI, bind DN, and search base.")

    if errors:
        return await _render_settings(request, db, errors, tab="integrations")

    app_settings.ldap_enabled = bool(ldap_enabled)
    app_settings.ldap_server_uri = server_uri or None
    app_settings.ldap_use_starttls = bool(ldap_use_starttls)
    app_settings.ldap_tls_verify = bool(ldap_tls_verify)
    app_settings.ldap_bind_dn = ldap_bind_dn.strip() or None
    if ldap_bind_password:
        app_settings.ldap_bind_password_encrypted = encrypt_secret(ldap_bind_password)
    app_settings.ldap_user_search_base = ldap_user_search_base.strip() or None
    app_settings.ldap_user_search_filter = search_filter
    app_settings.ldap_connect_timeout_seconds = timeout
    await db.commit()

    summary = f"Updated LDAP settings ({'enabled' if app_settings.ldap_enabled else 'disabled'})"
    if not app_settings.ldap_tls_verify:
        summary += " — certificate verification is OFF"
    await log_event(db, request=request, action="settings.ldap.update", summary=summary)
    return RedirectResponse(url="/settings?tab=integrations", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/oidc", dependencies=[Depends(verify_csrf)])
async def update_oidc_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    oidc_enabled: str = Form(""),
    oidc_provider_name: str = Form(""),
    oidc_issuer_url: str = Form(""),
    oidc_client_id: str = Form(""),
    # Blank = keep the existing client secret unchanged.
    oidc_client_secret: str = Form(""),
    oidc_username_claim: str = Form(""),
    oidc_scopes: str = Form(""),
) -> Response:
    app_settings = await get_or_create_app_settings(db)
    errors: list[str] = []

    issuer_url = oidc_issuer_url.strip()
    if issuer_url and not (issuer_url.startswith("http://") or issuer_url.startswith("https://")):
        errors.append('Issuer URL must start with "http://" or "https://".')

    claim = oidc_username_claim.strip() or DEFAULT_OIDC_USERNAME_CLAIM
    scopes = oidc_scopes.strip() or DEFAULT_OIDC_SCOPES
    if "openid" not in scopes.split():
        errors.append('Scopes must include "openid".')

    if bool(oidc_enabled) and not (issuer_url and oidc_client_id.strip()):
        errors.append("Enabling OIDC needs at least an issuer URL and client ID.")

    if errors:
        return await _render_settings(request, db, errors, tab="integrations")

    app_settings.oidc_enabled = bool(oidc_enabled)
    app_settings.oidc_provider_name = oidc_provider_name.strip() or None
    app_settings.oidc_issuer_url = issuer_url or None
    app_settings.oidc_client_id = oidc_client_id.strip() or None
    if oidc_client_secret:
        app_settings.oidc_client_secret_encrypted = encrypt_secret(oidc_client_secret)
    app_settings.oidc_username_claim = claim
    app_settings.oidc_scopes = scopes
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.oidc.update",
        summary=f"Updated OIDC settings ({'enabled' if app_settings.oidc_enabled else 'disabled'})",
    )
    return RedirectResponse(url="/settings?tab=integrations", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/syslog", dependencies=[Depends(verify_csrf)])
async def update_syslog_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    syslog_enabled: str = Form(""),
    syslog_host: str = Form(""),
    syslog_port: str = Form(str(DEFAULT_SYSLOG_PORT)),
    syslog_protocol: str = Form(SyslogProtocol.UDP.value),
) -> Response:
    app_settings = await get_or_create_app_settings(db)
    errors: list[str] = []

    host = syslog_host.strip()
    try:
        protocol = SyslogProtocol(syslog_protocol)
    except ValueError:
        errors.append("Unknown syslog protocol.")
        protocol = app_settings.syslog_protocol

    try:
        port = int(syslog_port.strip() or str(DEFAULT_SYSLOG_PORT))
        if not (0 < port <= 65535):
            raise ValueError
    except ValueError:
        errors.append("Port must be a whole number between 1 and 65535.")
        port = app_settings.syslog_port

    if bool(syslog_enabled) and not host:
        errors.append("Enabling syslog forwarding needs a server host/IP.")

    if errors:
        return await _render_settings(request, db, errors, tab="integrations")

    app_settings.syslog_enabled = bool(syslog_enabled)
    app_settings.syslog_host = host or None
    app_settings.syslog_port = port
    app_settings.syslog_protocol = protocol
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.syslog.update",
        summary=(
            f"Updated syslog forwarding settings "
            f"({'enabled, ' + protocol.value if app_settings.syslog_enabled else 'disabled'})"
        ),
    )
    return RedirectResponse(url="/settings?tab=integrations", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/netbird", dependencies=[Depends(verify_csrf)])
async def update_netbird_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    netbird_management_url: str = Form(""),
    # Blank = keep the existing setup key unchanged — same convention as
    # every other stored secret in this app (LDAP bind password, a
    # honeypot's own password).
    netbird_setup_key: str = Form(""),
) -> Response:
    """Saves the setup key/management URL (if given) and connects — one
    action, not "save" then a separate "connect" click, since a setup key
    is single-use on NetBird's side anyway (see the wiki): there's rarely
    a reason to save one without immediately using it."""
    app_settings = await get_or_create_app_settings(db)
    errors: list[str] = []

    management_url = netbird_management_url.strip()
    if management_url and not (
        management_url.startswith("http://") or management_url.startswith("https://")
    ):
        errors.append('Management URL must start with "http://" or "https://".')

    setup_key = netbird_setup_key.strip()
    if not setup_key and app_settings.netbird_setup_key_encrypted is None:
        errors.append("A setup key is required to connect.")

    if errors:
        return await _render_settings(request, db, errors, tab="netbird")

    app_settings.netbird_management_url = management_url or None
    if setup_key:
        app_settings.netbird_setup_key_encrypted = encrypt_secret(setup_key)
    else:
        # Guaranteed non-None here — the `errors.append(...)` above would
        # otherwise have already returned when both are unset.
        assert app_settings.netbird_setup_key_encrypted is not None
        setup_key = decrypt_secret(app_settings.netbird_setup_key_encrypted)

    try:
        await netbird.connect(setup_key=setup_key, management_url=management_url or None)
    except (netbird.NetbirdUnavailableError, netbird.NetbirdCommandError) as exc:
        await log_event(
            db,
            request=request,
            action="settings.netbird.connect",
            summary=f"Failed to connect to NetBird: {exc}",
            outcome=AuditOutcome.FAILURE,
        )
        await db.commit()
        return await _render_settings(request, db, [str(exc)], tab="netbird")

    app_settings.netbird_enabled = True
    await db.commit()
    await log_event(
        db, request=request, action="settings.netbird.connect", summary="Connected to NetBird"
    )
    return RedirectResponse(url="/settings?tab=netbird", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/netbird/disconnect", dependencies=[Depends(verify_csrf)])
async def disconnect_netbird(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    app_settings = await get_or_create_app_settings(db)
    try:
        await netbird.disconnect()
    except (netbird.NetbirdUnavailableError, netbird.NetbirdCommandError) as exc:
        await log_event(
            db,
            request=request,
            action="settings.netbird.disconnect",
            summary=f"Failed to disconnect from NetBird: {exc}",
            outcome=AuditOutcome.FAILURE,
        )
        await db.commit()
        return await _render_settings(request, db, [str(exc)], tab="netbird")

    app_settings.netbird_enabled = False
    await db.commit()
    await log_event(
        db,
        request=request,
        action="settings.netbird.disconnect",
        summary="Disconnected from NetBird",
    )
    return RedirectResponse(url="/settings?tab=netbird", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/netbird/restart", dependencies=[Depends(verify_csrf)])
async def restart_netbird(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    app_settings = await get_or_create_app_settings(db)
    if app_settings.netbird_setup_key_encrypted is None:
        return await _render_settings(
            request, db, ["Connect NetBird at least once before restarting it."], tab="netbird"
        )
    setup_key = decrypt_secret(app_settings.netbird_setup_key_encrypted)

    try:
        await netbird.restart(
            setup_key=setup_key, management_url=app_settings.netbird_management_url
        )
    except (netbird.NetbirdUnavailableError, netbird.NetbirdCommandError) as exc:
        await log_event(
            db,
            request=request,
            action="settings.netbird.restart",
            summary=f"Failed to restart NetBird: {exc}",
            outcome=AuditOutcome.FAILURE,
        )
        await db.commit()
        return await _render_settings(request, db, [str(exc)], tab="netbird")

    await log_event(
        db, request=request, action="settings.netbird.restart", summary="Restarted NetBird"
    )
    return RedirectResponse(url="/settings?tab=netbird", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/netbird/status-panel")
async def netbird_status_panel(request: Request) -> Response:
    return templates.TemplateResponse(
        request, "partials/netbird_status.html", {"netbird_status": await netbird.status()}
    )


@router.get("/netbird/log")
async def netbird_log_panel(request: Request) -> Response:
    return templates.TemplateResponse(
        request, "partials/netbird_log.html", {"netbird_log": netbird.tail_log()}
    )
