"""REST API for a honeypot's Monitoring and Config tabs — the same data
and actions as the web pages, through the same helpers, scoped the same
way: reading the Monitoring tab needs only read access to the honeypot;
everything on the Config tab (and "Refresh now") needs write access to
*this* honeypot (`_get_writable_honeypot_or_404`), like on the web.

The OpenCanary settings use the dotted `opencanary.conf` keys the module
editor manages (`ftp.enabled`, `ftp.port`, `ssh.version`, ...); `GET
.../config` lists every one of them with its current value. A save is a
partial update: only the keys sent change, every other key in the file is
kept exactly as it was, then OpenCanary restarts."""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import asdict
from typing import Any

from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_api_token_user, require_api_write
from app.core.app_settings import get_or_create_app_settings
from app.db.models.audit_log import AuditOutcome
from app.db.models.honeypot import Honeypot
from app.db.models.user import User
from app.db.session import get_db
from app.services import mac_vendors, monitoring_history
from app.services.honeypot_tags import sync_module_tags
from app.ssh.mac_address import InvalidMacAddressError, normalize_mac
from app.ssh.opencanary_config import OPENCANARY_MODULES, ConfigField
from app.tasks import jobs as tasks
from app.web.routes.api_v1 import _get_honeypot_or_404, _get_writable_honeypot_or_404
from app.web.routes.honeypots_common import _build_monitoring_context
from app.web.routes.honeypots_config import (
    JOB_FAILED_MESSAGE,
    _load_opencanary_config,
    _load_readonly_state,
    _mac_task,
)
from app.web.time_window import window_from_query

router = APIRouter(prefix="/api/v1/honeypots")
logger = logging.getLogger(__name__)

_view = Depends(get_api_token_user)
_write = Depends(require_api_write)

_NO_FINGERPRINT = "Confirm the host key fingerprint first."


# --- Monitoring --------------------------------------------------------------


async def _monitoring_payload(
    honeypot: Honeypot, range_key: str, start: str, end: str, db: AsyncSession, user: User
) -> dict[str, Any]:
    window = window_from_query(range_key, start, end)
    context = await _build_monitoring_context(honeypot, window, db, user)
    encoded: dict[str, Any] = jsonable_encoder(
        {
            "range_key": window.range_key,
            "since": window.since,
            "until": window.until,
            "last_checked_at": context["last_checked_at"],
            "history": asdict(context["history"]),
            "availability": asdict(context["availability"]),
            "service_counts": context["service_counts"],
            "services": [
                {
                    "unit": s.unit,
                    "load_state": s.load_state,
                    "active_state": s.active_state,
                    "sub_state": s.sub_state,
                    "description": s.description,
                }
                for s in context["services"]
            ],
        }
    )
    return encoded


@router.get("/{honeypot_id}/monitoring", dependencies=[_view])
async def honeypot_monitoring_api(
    honeypot_id: uuid.UUID,
    range_key: str = monitoring_history.DEFAULT_TIME_RANGE,
    start: str = "",
    end: str = "",
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """The Monitoring tab: CPU, RAM, load, network, disk and filesystem
    series (downsampled, oldest first, one timestamp list shared by every
    series), SSH availability and latency, and the systemd services.
    `range_key` is one of `1h`, `24h`, `7d`, `30d`, `90d` (an unknown
    value falls back to 24 hours), or give `start`/`end` (ISO dates or
    times) for a custom window."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    return await _monitoring_payload(honeypot, range_key, start, end, db, user)


@router.post("/{honeypot_id}/monitoring/refresh", dependencies=[_write])
async def refresh_honeypot_monitoring_api(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """"Refresh now": takes a fresh monitoring sample, a reachability check
    and a services snapshot over SSH, waits for them, and answers with the
    last 24 hours like `GET .../monitoring` plus `error` (null on success)."""
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, user)
    app_settings = await get_or_create_app_settings(db)
    timeout = app_settings.ssh_connect_timeout + 5
    pending = [
        tasks.sample_honeypot_monitoring.delay(str(honeypot.id)),
        tasks.check_honeypot_reachability.delay(str(honeypot.id)),
        tasks.refresh_honeypot_services.delay(str(honeypot.id)),
    ]
    error: str | None = None
    try:
        results = await asyncio.gather(
            *(asyncio.to_thread(r.get, timeout=timeout) for r in pending)
        )
        for result in results:
            if isinstance(result, dict) and not result.get("ok"):
                error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception:
        logger.warning("Background job failed", exc_info=True)
        error = JOB_FAILED_MESSAGE
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
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, user)
    # The worker wrote new values in its own session: reload them, or the
    # answer would still show the previous check time.
    await db.refresh(honeypot)
    payload = await _monitoring_payload(
        honeypot, monitoring_history.DEFAULT_TIME_RANGE, "", "", db, user
    )
    return {**payload, "error": error}


# --- Config: OpenCanary modules and read-only root ---------------------------


_FIELDS: dict[str, tuple[str, ConfigField | None]] = {}
for _module in OPENCANARY_MODULES:
    if _module.enabled_key is not None:
        _FIELDS[_module.enabled_key] = (_module.key, None)
    for _field in _module.fields:
        _FIELDS[_field.key] = (_module.key, _field)


def _settings_of(config: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for key, (module_key, field_def) in _FIELDS.items():
        value = config.get(key)
        if field_def is None:
            kind, value = "bool", bool(value)
        else:
            kind = field_def.type
            if value is None:
                value = [] if kind == "list" else field_def.default
        out.append({"key": key, "module": module_key, "type": kind, "value": value})
    return out


def _validated(settings: dict[str, Any]) -> dict[str, Any]:
    """Each key must be one the module editor manages, with a value of its
    type — 422 naming every problem otherwise."""
    errors: list[str] = []
    clean: dict[str, Any] = {}
    for key, value in settings.items():
        if key not in _FIELDS:
            errors.append(f'"{key}" is not an OpenCanary setting this editor manages.')
            continue
        field_def = _FIELDS[key][1]
        kind = "bool" if field_def is None else field_def.type
        ok = (
            (kind == "bool" and isinstance(value, bool))
            or (kind == "int" and isinstance(value, int) and not isinstance(value, bool)
                and 0 <= value <= 65535)
            or (kind == "str" and isinstance(value, str) and len(value) <= 1000)
            or (kind == "list" and isinstance(value, list)
                and all(isinstance(v, str) and len(v) <= 255 for v in value)
                and len(value) <= 500)
        )
        if not ok:
            errors.append(f'"{key}" must be a {kind}.')
            continue
        clean[key] = [v.strip() for v in value if v.strip()] if kind == "list" else value
    if errors:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=errors)
    return clean


@router.get("/{honeypot_id}/config", dependencies=[_write])
async def honeypot_config_api(
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """The Config tab, read fresh over SSH: the read-only root state
    (`enabled`/`disabled`, null when unsupported or unreadable) and every
    OpenCanary setting the module editor manages, with its type."""
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, user)
    if not honeypot.host_key_fingerprint:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_NO_FINGERPRINT)
    app_settings = await get_or_create_app_settings(db)
    readonly_state: str | None = None
    readonly_error: str | None = None
    if honeypot.supports_readonly_root:
        readonly_state, readonly_error = await _load_readonly_state(honeypot, app_settings)
    config, config_error = await _load_opencanary_config(honeypot, app_settings)
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=config_error or "Could not read the OpenCanary config.",
        )
    return {
        "supports_readonly_root": honeypot.supports_readonly_root,
        "readonly_state": readonly_state,
        "readonly_error": readonly_error,
        "opencanary": _settings_of(config),
    }


class OpenCanarySettings(BaseModel):
    settings: dict[str, Any] = Field(
        min_length=1,
        description='Dotted keys to change, e.g. {"ftp.enabled": true, "ftp.port": 2121}.',
    )


@router.patch("/{honeypot_id}/config/opencanary", dependencies=[_write])
async def save_honeypot_opencanary_api(
    request: Request,
    honeypot_id: uuid.UUID,
    payload: OpenCanarySettings,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Changes only the settings sent, keeps everything else in
    `opencanary.conf`, writes it back and restarts OpenCanary. The
    honeypot's module tags follow the enabled modules, like on the web."""
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, user)
    if not honeypot.host_key_fingerprint:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_NO_FINGERPRINT)
    changes = _validated(payload.settings)
    app_settings = await get_or_create_app_settings(db)
    current, error = await _load_opencanary_config(honeypot, app_settings)
    updated: dict[str, Any] | None = None
    if current is not None:
        updated = {**current, **changes}
        try:
            result = await asyncio.to_thread(
                tasks.write_honeypot_opencanary_config.delay(str(honeypot.id), updated).get,
                timeout=app_settings.ssh_connect_timeout + 60,
            )
            if not (isinstance(result, dict) and result.get("ok")):
                error = str((result or {}).get("error") or "Unknown error.")
        except CeleryTimeoutError:
            error = "Applying the config did not finish in time."
        except Exception:
            logger.warning("Background job failed", exc_info=True)
            error = JOB_FAILED_MESSAGE
        if error is None:
            await sync_module_tags(db, honeypot, updated)
    await log_event(
        db,
        request=request,
        action="honeypot.opencanary_config.save",
        summary=f'Saved OpenCanary config on "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"keys": sorted(changes), **({"error": error} if error else {})},
    )
    if error is not None or updated is None:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail=error or "Unknown error."
        )
    return {"opencanary": _settings_of(updated)}


class ReadonlyRoot(BaseModel):
    enable: bool


@router.put("/{honeypot_id}/config/readonly", dependencies=[_write])
async def set_honeypot_readonly_api(
    request: Request,
    honeypot_id: uuid.UUID,
    payload: ReadonlyRoot,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Turns the read-only root filesystem on or off — from the next boot
    on, so reboot the honeypot afterwards."""
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, user)
    if not honeypot.host_key_fingerprint:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_NO_FINGERPRINT)
    if not honeypot.supports_readonly_root:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This honeypot doesn't support the read-only-root toggle (no raspi-config).",
        )
    app_settings = await get_or_create_app_settings(db)
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            tasks.set_honeypot_readonly.delay(str(honeypot.id), enable=payload.enable).get,
            timeout=app_settings.ssh_connect_timeout + 30,
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The command did not finish in time."
    except Exception:
        logger.warning("Background job failed", exc_info=True)
        error = JOB_FAILED_MESSAGE
    await log_event(
        db,
        request=request,
        action="honeypot.readonly.enable" if payload.enable else "honeypot.readonly.disable",
        summary=(
            f'{"Enabled" if payload.enable else "Disabled"} read-only root on "{honeypot.name}"'
        ),
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {"ok": True, "enable": payload.enable, "effective": "next boot"}


# --- Config: MAC address -----------------------------------------------------


async def _mac_payload(db: AsyncSession, state: dict[str, Any]) -> dict[str, Any]:
    current = state.get("current")
    configured = state.get("configured")
    return {
        "current": current,
        "current_vendor": await mac_vendors.vendor_of(db, current) if current else None,
        "configured": configured,
        "configured_vendor": (
            await mac_vendors.vendor_of(db, configured) if configured else None
        ),
    }


@router.get("/{honeypot_id}/config/mac", dependencies=[_write])
async def honeypot_mac_api(
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """The address the honeypot uses now, and the one set for its next boot
    (null when it keeps its hardware address), with their manufacturers."""
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, user)
    state, error = await _mac_task(honeypot, await get_or_create_app_settings(db))
    if state is None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return await _mac_payload(db, state)


class MacAddress(BaseModel):
    mac_address: str = Field(min_length=1, max_length=40)


async def _audited_mac_change(
    request: Request,
    db: AsyncSession,
    honeypot: Honeypot,
    *,
    action: str,
    summary: str,
    details: dict[str, Any],
    **task_kwargs: Any,
) -> dict[str, Any]:
    state, error = await _mac_task(honeypot, await get_or_create_app_settings(db), **task_kwargs)
    await log_event(
        db,
        request=request,
        action=action,
        summary=summary,
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={**details, **({"error": error} if error else {})} or None,
    )
    if state is None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return await _mac_payload(db, state)


@router.put("/{honeypot_id}/config/mac", dependencies=[_write])
async def set_honeypot_mac_api(
    request: Request,
    honeypot_id: uuid.UUID,
    payload: MacAddress,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Sets the address the honeypot uses from its next boot on — e.g. one
    of a printer maker, so the decoy looks like a printer on the network."""
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, user)
    try:
        mac = normalize_mac(payload.mac_address)
    except InvalidMacAddressError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    vendor = await mac_vendors.vendor_of(db, mac)
    return await _audited_mac_change(
        request,
        db,
        honeypot,
        action="honeypot.mac_address.set",
        summary=f'Set the MAC address of "{honeypot.name}" to {mac}',
        details={"mac_address": mac, **({"vendor": vendor} if vendor else {})},
        mac=mac,
        vendor=vendor,
    )


@router.delete("/{honeypot_id}/config/mac", dependencies=[_write])
async def reset_honeypot_mac_api(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Back to the hardware address after the next boot."""
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, user)
    return await _audited_mac_change(
        request,
        db,
        honeypot,
        action="honeypot.mac_address.reset",
        summary=f'Returned "{honeypot.name}" to its hardware MAC address',
        details={},
        reset=True,
    )
