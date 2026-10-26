"""REST API for Settings — superadmin-only (matching the web page). It
reads and writes Checks & retention (`/checks`, `/retention`), GeoIP
(`/geoip`, `/geoip/refresh`) and the MAC manufacturer list
(`/mac-vendors`, `/mac-vendors/refresh`) with the same bounds and audit
codes as the page, and reads the rest. What's read-only or left out, and
why (mirrors debcontrol's own reasoning):

- **Version/commit info** and the **SSH public key/fingerprint** — safe to
  read over a bearer-token API; the public key is *meant* to be copied
  elsewhere (into `authorized_keys`).
- **Updating Honeypot Shelf itself** (Settings -> Update):
  `GET /api/v1/settings/update` reports what the host watcher last saw;
  `POST .../update/check` and `POST .../update/upgrade` ask it for a
  check or an upgrade, the same two buttons and audit action codes as the
  page (`app.services.app_update`). An upgrade only ever installs what the
  checkout's own branch has upstream — nothing in the request picks a
  version or a source.
- The **sign-in policy** (session lifetime, lockout, allowed networks) —
  read-only: a wrong network
  allowlist locks every browser *and* every API token out at once, and
  the web form refuses a list that excludes the address saving it — a
  safeguard a script running from somewhere else wouldn't get.

What's deliberately **not** exposed here, even to a superadmin token:

- **Rotating the SSH key** (`/settings/ssh-key/...`) — a multi-step,
  human-in-the-loop process (generate, manually copy the public half onto
  every honeypot's `authorized_keys`, then activate) specifically designed
  so the app is never locked out of a honeypot mid-rotation. Left as a
  deliberately web-UI-only, human-paced action.
- **LDAP/OIDC configuration** — carries encrypted secrets and changes how
  *every* login on the instance is authenticated; a bug or a stolen token
  reconfiguring the login provider is a much bigger blast radius than
  anything else this API can do.
- **Syslog forwarding configuration** — a live security-monitoring
  integration point; left for the web UI, pending an explicit ask.
"""

from __future__ import annotations

import asyncio

from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import require_api_superadmin
from app.core.app_settings import effective_event_retention_days, get_or_create_app_settings
from app.core.security import encrypt_secret
from app.core.version import APP_VERSION, commit_url, get_git_commit
from app.db.models.app_settings import AppSettings
from app.db.models.audit_log import AuditOutcome
from app.db.models.geoip_database import SINGLETON_ID as GEOIP_SINGLETON_ID
from app.db.models.geoip_database import GeoipDatabase
from app.db.session import get_db
from app.services import app_update, mac_vendors
from app.ssh.identity import get_or_create_identity
from app.tasks.jobs import refresh_geoip_database
from app.web.routes.settings import MAX_EVENT_RETENTION_DAYS

router = APIRouter(prefix="/api/v1/settings")

_view = Depends(require_api_superadmin)


@router.get("", dependencies=[_view])
async def get_settings_api(db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    identity = await get_or_create_identity(db)
    app_settings = await get_or_create_app_settings(db)
    git_commit = get_git_commit()
    return {
        "app_version": APP_VERSION,
        "git_commit": git_commit,
        "git_commit_url": commit_url(git_commit) if git_commit else None,
        "ssh_public_key": identity.public_key,
        "ssh_fingerprint": identity.fingerprint,
        "ssh_pending_fingerprint": identity.pending_fingerprint,
        "facts_refresh_interval_seconds": app_settings.facts_refresh_interval_seconds,
        "update_timeout_seconds": app_settings.update_timeout_seconds,
        "ssh_connect_timeout": app_settings.ssh_connect_timeout,
        "audit_log_retention_days": app_settings.audit_log_retention_days,
        # The value in force: Settings when set there, else EVENT_RETENTION_DAYS.
        "event_retention_days": effective_event_retention_days(app_settings),
        "session_idle_timeout_minutes": app_settings.session_idle_timeout_minutes,
        "session_absolute_max_hours": app_settings.session_absolute_max_hours,
        "login_max_failed_attempts": app_settings.login_max_failed_attempts,
        "login_lockout_minutes": app_settings.login_lockout_minutes,
        "login_allowed_networks": (app_settings.login_allowed_networks or "").split() or [],
        # Read-only here: whether terminal sessions are recorded is decided
        # by a person on Settings -> Security, not by a script.
        "terminal_recording_enabled": app_settings.terminal_recording_enabled,
        "terminal_recording_retention_days": app_settings.terminal_recording_retention_days,
    }


@router.get("/update", dependencies=[_view])
async def get_app_update_api() -> dict[str, object]:
    """What the host watcher behind Settings -> Update last reported:
    whether it is installed, the last check, the last upgrade."""
    return app_update.read_status().as_dict()


async def _request_app_update_api(
    request: Request, db: AsyncSession, kind: str
) -> dict[str, object]:
    try:
        app_update.request(kind)
    except app_update.WatcherNotInstalledError:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="The update watcher is not installed on the host "
            "(scripts/install_update_watcher.sh).",
        ) from None
    except app_update.UpgradeInProgressError:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="An update is already requested or running."
        ) from None
    if kind == app_update.UPGRADE:
        await log_event(
            db,
            request=request,
            action="settings.app_update.upgrade",
            summary=f"Requested an update of Honeypot Shelf (running {APP_VERSION}) via the API",
            details={"from_version": APP_VERSION},
        )
    else:
        await log_event(
            db,
            request=request,
            action="settings.app_update.check",
            summary="Requested a check for a Honeypot Shelf update via the API",
        )
    return {"requested": kind}


@router.post("/update/check", dependencies=[_view], status_code=status.HTTP_202_ACCEPTED)
async def check_app_update_api(
    request: Request, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    return await _request_app_update_api(request, db, app_update.CHECK)


@router.post("/update/upgrade", dependencies=[_view], status_code=status.HTTP_202_ACCEPTED)
async def upgrade_app_api(
    request: Request, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    """Install the newest commit of the checkout's branch — the same as
    `scripts/upgrade.sh`. Honeypot Shelf restarts during it; poll
    `GET /api/v1/settings/update` for the outcome."""
    return await _request_app_update_api(request, db, app_update.UPGRADE)


# --- Checks and retention ------------------------------------------------------
#
# Same fields, bounds and audit codes as Settings -> Checks & retention.
# Partial updates: only the fields sent change.

_CHECK_BOUNDS: dict[str, tuple[int, int]] = {
    "ssh_connect_timeout": (1, 300),
    "update_timeout_seconds": (60, 14400),
    "facts_refresh_interval_seconds": (60, 604800),
    "reachability_check_interval_seconds": (5, 86400),
    "reachability_check_concurrency": (1, 1000),
    "monitoring_interval_seconds": (10, 86400),
    "opencanary_log_poll_interval_seconds": (10, 86400),
}


class ChecksSettings(BaseModel):
    """Seconds, except the concurrency (parallel checks). The four
    intervals take effect after the worker and beat services restart."""

    ssh_connect_timeout: int | None = Field(default=None, ge=1, le=300)
    update_timeout_seconds: int | None = Field(default=None, ge=60, le=14400)
    facts_refresh_interval_seconds: int | None = Field(default=None, ge=60, le=604800)
    reachability_check_interval_seconds: int | None = Field(default=None, ge=5, le=86400)
    reachability_check_concurrency: int | None = Field(default=None, ge=1, le=1000)
    monitoring_interval_seconds: int | None = Field(default=None, ge=10, le=86400)
    opencanary_log_poll_interval_seconds: int | None = Field(default=None, ge=10, le=86400)


def _checks_of(app_settings: AppSettings) -> dict[str, int]:
    return {key: getattr(app_settings, key) for key in _CHECK_BOUNDS}


@router.get("/checks", dependencies=[_view])
async def get_checks_api(db: AsyncSession = Depends(get_db)) -> dict[str, int]:
    return _checks_of(await get_or_create_app_settings(db))


@router.patch("/checks", dependencies=[_view])
async def update_checks_api(
    request: Request, payload: ChecksSettings, db: AsyncSession = Depends(get_db)
) -> dict[str, int]:
    app_settings = await get_or_create_app_settings(db)
    for key in payload.model_fields_set:
        value = getattr(payload, key)
        if value is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f'"{key}" needs a value.'
            )
        setattr(app_settings, key, value)
    await db.commit()
    checks = _checks_of(app_settings)
    await log_event(
        db,
        request=request,
        action="settings.checks.update",
        summary="Updated background-check settings",
        details=dict(checks),
    )
    return checks


# field -> (AppSettings attribute, audit action code, label for the summary)
_RETENTIONS: dict[str, tuple[str, str, str]] = {
    "event_retention_days": (
        "event_retention_days", "settings.event_retention.update", "event retention"
    ),
    "audit_log_retention_days": (
        "audit_log_retention_days", "settings.audit_retention.update", "audit log retention"
    ),
    "dashboard_trends_retention_days": (
        "dashboard_trends_retention_days",
        "settings.dashboard_trends_retention.update",
        "dashboard trends retention",
    ),
    "update_run_retention_days": (
        "honeypot_update_run_retention_days",
        "settings.honeypot_update_run_retention.update",
        "update run history retention",
    ),
    "monitoring_retention_days": (
        "monitoring_history_retention_days",
        "settings.monitoring_retention.update",
        "monitoring history retention",
    ),
    "notification_log_retention_days": (
        "notification_log_retention_days",
        "settings.notification_log_retention.update",
        "notification history retention",
    ),
}


class RetentionSettings(BaseModel):
    """Days to keep each kind of history; null keeps it forever — except
    events, where null goes back to `EVENT_RETENTION_DAYS` from `.env`."""

    event_retention_days: int | None = Field(default=None, ge=1, le=MAX_EVENT_RETENTION_DAYS)
    audit_log_retention_days: int | None = Field(default=None, ge=0)
    dashboard_trends_retention_days: int | None = Field(default=None, ge=0)
    update_run_retention_days: int | None = Field(default=None, ge=0)
    monitoring_retention_days: int | None = Field(default=None, ge=0)
    notification_log_retention_days: int | None = Field(default=None, ge=0)


def _retention_of(app_settings: AppSettings) -> dict[str, int | None]:
    out: dict[str, int | None] = {
        field: getattr(app_settings, attr) for field, (attr, _a, _l) in _RETENTIONS.items()
    }
    out["event_retention_days_effective"] = effective_event_retention_days(app_settings)
    return out


@router.get("/retention", dependencies=[_view])
async def get_retention_api(db: AsyncSession = Depends(get_db)) -> dict[str, int | None]:
    return _retention_of(await get_or_create_app_settings(db))


@router.patch("/retention", dependencies=[_view])
async def update_retention_api(
    request: Request, payload: RetentionSettings, db: AsyncSession = Depends(get_db)
) -> dict[str, int | None]:
    app_settings = await get_or_create_app_settings(db)
    changed = sorted(payload.model_fields_set)
    for field in changed:
        setattr(app_settings, _RETENTIONS[field][0], getattr(payload, field))
    await db.commit()
    for field in changed:
        _attr, action, label = _RETENTIONS[field]
        value = getattr(payload, field)
        await log_event(
            db,
            request=request,
            action=action,
            summary=(
                f"Set {label} to {value} day(s)"
                if value is not None
                else f"Set {label} to keep forever"
                if field != "event_retention_days"
                else "Set event retention back to the EVENT_RETENTION_DAYS default"
            ),
        )
    return _retention_of(app_settings)


# --- GeoIP -----------------------------------------------------------------------


class GeoipSettings(BaseModel):
    """The download URLs embed a license key: write-only, stored
    encrypted, and left unchanged when omitted."""

    enabled: bool
    primary_url: str | None = Field(default=None, max_length=2000)
    backup_url: str | None = Field(default=None, max_length=2000)
    refresh_interval_hours: int = Field(default=168, ge=1, le=24 * 365)


async def _geoip_of(db: AsyncSession, app_settings: AppSettings) -> dict[str, object]:
    database = await db.get(GeoipDatabase, GEOIP_SINGLETON_ID)
    return {
        "enabled": app_settings.geoip_enabled,
        "has_primary_url": app_settings.geoip_primary_url_encrypted is not None,
        "has_backup_url": app_settings.geoip_backup_url_encrypted is not None,
        "refresh_interval_hours": app_settings.geoip_refresh_interval_hours,
        "database_ready": database is not None and database.mmdb_data is not None,
        "database_source": database.source if database else None,
        "database_updated_at": (
            database.updated_at.isoformat() if database and database.updated_at else None
        ),
        "last_error": database.last_error if database else None,
    }


@router.get("/geoip", dependencies=[_view])
async def get_geoip_api(db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    return await _geoip_of(db, await get_or_create_app_settings(db))


@router.put("/geoip", dependencies=[_view])
async def update_geoip_api(
    request: Request, payload: GeoipSettings, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    app_settings = await get_or_create_app_settings(db)
    primary = (payload.primary_url or "").strip()
    backup = (payload.backup_url or "").strip()
    if payload.enabled and not (primary or app_settings.geoip_primary_url_encrypted):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Enabling GeoIP needs at least a primary database URL.",
        )
    app_settings.geoip_enabled = payload.enabled
    if primary:
        app_settings.geoip_primary_url_encrypted = encrypt_secret(primary)
    if backup:
        app_settings.geoip_backup_url_encrypted = encrypt_secret(backup)
    app_settings.geoip_refresh_interval_hours = payload.refresh_interval_hours
    await db.commit()
    await log_event(
        db,
        request=request,
        action="settings.geoip.update",
        summary=f"Updated GeoIP settings ({'enabled' if payload.enabled else 'disabled'})",
    )
    return await _geoip_of(db, app_settings)


@router.post("/geoip/refresh", dependencies=[_view])
async def refresh_geoip_api(
    request: Request, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    """"Download now": waits up to 90 seconds for the download."""
    app_settings = await get_or_create_app_settings(db)
    if not (app_settings.geoip_primary_url_encrypted or app_settings.geoip_backup_url_encrypted):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Set a primary (or backup) database URL first.",
        )
    error: str | None = None
    try:
        outcome = await asyncio.to_thread(refresh_geoip_database.delay().get, timeout=90)
        if not (isinstance(outcome, dict) and outcome.get("ok")):
            error = str(outcome.get("error")) if isinstance(outcome, dict) else "Unknown error."
    except CeleryTimeoutError:
        error = "Download timed out — it may still complete in the background."
    except Exception as exc:
        error = str(exc)
    await log_event(
        db,
        request=request,
        action="settings.geoip.refresh",
        summary=(
            "Downloaded GeoIP database"
            if error is None
            else f"Failed to download GeoIP database: {error}"
        ),
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return await _geoip_of(db, app_settings)


# --- MAC manufacturer list -----------------------------------------------------


class MacVendorSettings(BaseModel):
    """`list_url` null turns the periodic download off; the stored list
    stays."""

    list_url: str | None = Field(default=None, max_length=1000)
    refresh_interval_hours: int = Field(
        default=mac_vendors.DEFAULT_REFRESH_INTERVAL_HOURS, ge=1, le=24 * 365
    )


async def _mac_vendors_of(db: AsyncSession, app_settings: AppSettings) -> dict[str, object]:
    updated = app_settings.mac_vendor_list_updated_at
    return {
        "list_url": app_settings.mac_vendor_list_url,
        "refresh_interval_hours": app_settings.mac_vendor_refresh_interval_hours,
        "prefixes": await mac_vendors.vendor_count(db),
        "updated_at": updated.isoformat() if updated else None,
        "last_error": app_settings.mac_vendor_list_error,
    }


@router.get("/mac-vendors", dependencies=[_view])
async def get_mac_vendors_api(db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    return await _mac_vendors_of(db, await get_or_create_app_settings(db))


@router.put("/mac-vendors", dependencies=[_view])
async def update_mac_vendors_api(
    request: Request, payload: MacVendorSettings, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    app_settings = await get_or_create_app_settings(db)
    url = (payload.list_url or "").strip()
    if url:
        try:
            mac_vendors.validate_list_url(url)
        except mac_vendors.MacVendorListError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
            ) from exc
    app_settings.mac_vendor_list_url = url or None
    app_settings.mac_vendor_refresh_interval_hours = payload.refresh_interval_hours
    await db.commit()
    await log_event(
        db,
        request=request,
        action="settings.mac_vendors.update",
        summary="Updated the MAC manufacturer list source",
        details={"url": url or None, "refresh_interval_hours": payload.refresh_interval_hours},
    )
    return await _mac_vendors_of(db, app_settings)


@router.post("/mac-vendors/refresh", dependencies=[_view])
async def refresh_mac_vendors_api(
    request: Request, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    """"Download now" — fetches the list from `list_url` right away."""
    app_settings = await get_or_create_app_settings(db)
    error: str | None = None
    count = 0
    try:
        count = await mac_vendors.refresh_vendor_list(db, app_settings)
    except mac_vendors.MacVendorListError as exc:
        error = str(exc)
    await log_event(
        db,
        request=request,
        action="settings.mac_vendors.refresh",
        summary="Downloaded the MAC manufacturer list",
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        details={"error": error} if error else {"prefixes": count},
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return await _mac_vendors_of(db, app_settings)
