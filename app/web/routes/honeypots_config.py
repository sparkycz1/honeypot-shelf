"""A honeypot's Config tab: the OpenCanary modules and the read-only root
switch."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any
from urllib.parse import urlencode

# NOT the builtin `TimeoutError` — `celery.exceptions.TimeoutError` does not
# subclass it, so catching the builtin around `AsyncResult.get(timeout=...)`
# would silently never match and the timeout branches below would be dead code.
from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import Depends, Form, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.app_settings import AppSettings
from app.db.models.audit_log import AuditOutcome
from app.db.models.honeypot import Honeypot
from app.db.models.user import User
from app.db.session import get_db
from app.services import mac_vendors
from app.services.honeypot_tags import (
    sync_module_tags,
)
from app.ssh.mac_address import InvalidMacAddressError, normalize_mac
from app.ssh.opencanary_config import (
    OPENCANARY_MODULES,
    apply_form_to_config,
    field_value,
    module_enabled,
)
from app.tasks import jobs as tasks
from app.web.routes.honeypots_common import (
    _get_honeypot_or_404,
    _get_writable_honeypot_or_404,
    _honeypot_tabs,
    honeypots_router,
    need_terminal,
)
from app.web.templating import templates

router = honeypots_router()


async def _load_readonly_state(
    honeypot: Honeypot, app_settings: AppSettings
) -> tuple[str | None, str | None]:
    """`(state, error)` — see `app.ssh.readonly`."""
    try:
        async_result = tasks.check_honeypot_readonly_status.delay(str(honeypot.id))
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 15
        )
        if isinstance(result, dict):
            if result.get("ok"):
                return str(result.get("state")), None
            return None, str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        return None, "The status check did not finish in time."
    except Exception as exc:
        return None, str(exc)
    return None, "Unknown error."


async def _load_opencanary_config(
    honeypot: Honeypot, app_settings: AppSettings
) -> tuple[dict[str, Any] | None, str | None]:
    """`(config, error)` — a fresh SSH read of `opencanary.conf`, see
    `app.ssh.opencanary_config`'s module docstring for why this is never
    cached."""
    try:
        async_result = tasks.read_honeypot_opencanary_config.delay(str(honeypot.id))
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 15
        )
        if isinstance(result, dict):
            if result.get("ok"):
                config = result.get("config")
                return (config if isinstance(config, dict) else {}), None
            return None, str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        return None, "Reading the config did not finish in time."
    except Exception as exc:
        return None, str(exc)
    return None, "Unknown error."


@router.get("/{honeypot_id}/config", dependencies=[need_terminal])
async def honeypot_config_tab(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    readonly_saved: str = "",
    readonly_error: str = "",
) -> Response:
    """Honeypot config — the read-only root filesystem toggle (see
    `app.ssh.readonly`) and the OpenCanary module editor (see
    `app.ssh.opencanary_config`). Two independent live SSH round trips on
    every load, same as the Logs tab; nothing here is persisted.

    `readonly_saved` (`"enable"`/`"disable"`, or empty) and `readonly_error`
    ride in on the redirect from `set_honeypot_readonly_endpoint` below —
    that POST's own success/failure used to just redirect to a plain
    `/config` with nothing riding along, so neither a successful toggle
    (which only ever changes what the *next* boot looks like — see
    `app.ssh.readonly`'s module docstring, `readonly_state` below reflects
    the currently-booted state and never visibly changes right after) nor
    a real failure (e.g. a missing sudoers grant) was ever distinguishable
    from a silent no-op. Confirmed live as a real "it does nothing" bug
    report."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    readonly_state: str | None = None
    opencanary_config: dict[str, Any] | None = None
    error: str | None = readonly_error or None
    if not honeypot.host_key_fingerprint:
        error = error or "Confirm the server's key fingerprint on the Overview tab first."
    else:
        readonly_state, readonly_load_error = await _load_readonly_state(honeypot, app_settings)
        opencanary_config, config_error = await _load_opencanary_config(honeypot, app_settings)
        error = error or readonly_load_error or config_error

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/config.html",
        {
            "honeypot": honeypot,
            "tabs": _honeypot_tabs(request, honeypot, current_user),
            "active_tab": "config",
            "csrf_token": csrf_token,
            "readonly_state": readonly_state,
            "readonly_saved": readonly_saved if readonly_saved in ("enable", "disable") else "",
            "opencanary_config": opencanary_config,
            "opencanary_modules": OPENCANARY_MODULES,
            "field_value": field_value,
            "module_enabled": module_enabled,
            "error": error,
            "saved": False,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post(
    "/{honeypot_id}/config/modules", dependencies=[need_terminal, Depends(verify_csrf)]
)
async def save_honeypot_opencanary_config_endpoint(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Saves the OpenCanary module editor form — reads the current config
    fresh, merges the submitted values in (see
    `app.ssh.opencanary_config.apply_form_to_config` for exactly what
    "merges" means — every key this editor doesn't manage passes through
    untouched), writes it back, and restarts whatever needs restarting.
    Never a partial save: reading and writing both happen in this one
    request, no separate "stage changes then apply" step."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    error: str | None = None
    saved = False
    readonly_state: str | None = None
    opencanary_config: dict[str, Any] | None = None
    if not honeypot.host_key_fingerprint:
        error = "Confirm the server's key fingerprint on the Overview tab first."
    else:
        current_config, read_error = await _load_opencanary_config(honeypot, app_settings)
        if read_error or current_config is None:
            error = read_error or "Could not read the current config."
        else:
            form = await request.form()
            form_values = {k: str(v) for k, v in form.multi_items() if isinstance(v, str)}
            updated_config = apply_form_to_config(current_config, form_values)
            try:
                async_result = tasks.write_honeypot_opencanary_config.delay(
                    str(honeypot.id), updated_config
                )
                result = await asyncio.to_thread(
                    async_result.get, timeout=app_settings.ssh_connect_timeout + 60
                )
                if isinstance(result, dict):
                    if result.get("ok"):
                        saved = True
                        opencanary_config = updated_config
                        # Tag the honeypot with exactly its now-enabled
                        # modules ("ftp", "http", "ssh", ...), untagging
                        # whichever got turned off — never touching a
                        # manually-added tag. See that function's own
                        # docstring for how it tells the two apart.
                        await sync_module_tags(db, honeypot, updated_config)
                    else:
                        error = str(result.get("error") or "Unknown error.")
            except CeleryTimeoutError:
                error = "Applying the config did not finish in time."
            except Exception as exc:
                error = str(exc)

        readonly_state, readonly_error = await _load_readonly_state(honeypot, app_settings)
        error = error or readonly_error
        if opencanary_config is None:
            opencanary_config, _ = await _load_opencanary_config(honeypot, app_settings)

    await log_event(
        db,
        request=request,
        action="honeypot.opencanary_config.save",
        summary=f'Saved OpenCanary config on "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "honeypots/config.html",
        {
            "honeypot": honeypot,
            "tabs": _honeypot_tabs(request, honeypot, current_user),
            "active_tab": "config",
            "csrf_token": csrf_token,
            "readonly_state": readonly_state,
            "opencanary_config": opencanary_config,
            "opencanary_modules": OPENCANARY_MODULES,
            "field_value": field_value,
            "module_enabled": module_enabled,
            "error": error,
            "saved": saved,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post(
    "/{honeypot_id}/config/readonly", dependencies=[need_terminal, Depends(verify_csrf)]
)
async def set_honeypot_readonly_endpoint(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    enable: str = Form(...),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Toggles the read-only root filesystem — see `app.ssh.readonly`.
    `enable` is the literal string "true"/"false" from the two buttons on
    the Config tab, not a checkbox (there's nothing to check — each button
    is its own explicit, unambiguous action)."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)
    enable_bool = enable == "true"

    error: str | None = None
    if not honeypot.host_key_fingerprint:
        error = "Confirm the server's key fingerprint on the Overview tab first."
    elif not honeypot.supports_readonly_root:
        # Defense in depth — the Config tab already hides this section
        # entirely for a honeypot without raspi-config (see config.html),
        # this only matters for a direct POST bypassing that.
        error = "This honeypot doesn't support the read-only-root toggle (no raspi-config)."
    else:
        try:
            async_result = tasks.set_honeypot_readonly.delay(str(honeypot.id), enable=enable_bool)
            result = await asyncio.to_thread(
                async_result.get, timeout=app_settings.ssh_connect_timeout + 30
            )
            if isinstance(result, dict) and not result.get("ok"):
                error = str(result.get("error") or "Unknown error.")
        except CeleryTimeoutError:
            error = "The command did not finish in time."
        except Exception as exc:
            error = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.readonly.enable" if enable_bool else "honeypot.readonly.disable",
        summary=(
            f'{"Enabled" if enable_bool else "Disabled"} read-only root on "{honeypot.name}"'
        ),
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )

    # Both the success and the error case used to just redirect to a plain
    # `/config` with nothing riding along — the GET handler's own `error`
    # only ever reflects *that request's own* status-read failures, never
    # what this POST's toggle attempt itself did. A real toggle failure
    # (e.g. the sudoers grant missing "raspi-config") and a genuine success
    # both rendered as the exact same page, indistinguishable from a
    # silent no-op — confirmed live as a real "it does nothing" bug report.
    query = (
        {"readonly_error": error}
        if error
        else {"readonly_saved": "enable" if enable_bool else "disable"}
    )
    redirect_url = f"/honeypots/{honeypot.id}/config?{urlencode(query)}"
    if request.headers.get("HX-Request") == "true":
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": redirect_url})
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


# --- MAC address ---------------------------------------------------------
#
# Its own self-loading panel on the Config tab (see
# partials/honeypot_mac_panel.html): every request here is one SSH round
# trip through `tasks.honeypot_mac_address`, and all three answer with the
# panel as it is afterwards. `_get_writable_honeypot_or_404`, not just
# `need_terminal`: an account that writes one company and only reads
# another must not change a honeypot of the second.


async def _mac_task(
    honeypot: Honeypot, app_settings: AppSettings, **action: Any
) -> tuple[dict[str, Any] | None, str | None]:
    """`(state, error)` from `tasks.honeypot_mac_address`."""
    try:
        async_result = tasks.honeypot_mac_address.delay(str(honeypot.id), **action)
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 45
        )
    except CeleryTimeoutError:
        return None, "The honeypot did not answer in time."
    except Exception as exc:
        return None, str(exc)
    if isinstance(result, dict) and result.get("ok"):
        return result, None
    return None, str((result or {}).get("error") or "Unknown error.")


async def _render_mac_panel(
    request: Request,
    db: AsyncSession,
    honeypot: Honeypot,
    *,
    state: dict[str, Any] | None,
    error: str | None,
    saved: str = "",
    mac_address: str = "",
    mac_vendor: str = "",
) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    current = (state or {}).get("current")
    configured = (state or {}).get("configured")
    response = templates.TemplateResponse(
        request,
        "partials/honeypot_mac_panel.html",
        {
            "honeypot": honeypot,
            "csrf_token": csrf_token,
            "state": state,
            "error": error,
            "saved": saved,
            # What the field starts with: what was just typed (on an
            # error), else what the honeypot is already set to.
            "mac_address": mac_address or configured or "",
            "mac_vendor": mac_vendor,
            "vendors_available": await mac_vendors.vendor_count(db) > 0,
            "current_vendor": await mac_vendors.vendor_of(db, current) if current else None,
            "configured_vendor": (
                await mac_vendors.vendor_of(db, configured) if configured else None
            ),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/{honeypot_id}/config/mac", dependencies=[need_terminal])
async def honeypot_mac_panel(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)
    state, error = await _mac_task(honeypot, app_settings)
    return await _render_mac_panel(request, db, honeypot, state=state, error=error)


@router.post("/{honeypot_id}/config/mac", dependencies=[need_terminal, Depends(verify_csrf)])
async def set_honeypot_mac_address(
    request: Request,
    honeypot_id: uuid.UUID,
    mac_address: str = Form(""),
    mac_vendor: str = Form(""),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Writes the address the honeypot will use from its next boot on.
    Nothing changes on the wire until then — see `app.ssh.mac_address`."""
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)
    vendor = mac_vendor.strip()[:255] or None

    error: str | None = None
    state: dict[str, Any] | None = None
    normalized: str | None = None
    try:
        normalized = normalize_mac(mac_address)
    except InvalidMacAddressError as exc:
        error = str(exc)
    if normalized is not None:
        if vendor and await mac_vendors.vendor_of(db, normalized) != vendor:
            # The address was edited after a manufacturer was picked.
            vendor = None
        state, error = await _mac_task(honeypot, app_settings, mac=normalized, vendor=vendor)

    await log_event(
        db,
        request=request,
        action="honeypot.mac_address.set",
        summary=f'Set the MAC address of "{honeypot.name}" to {normalized or mac_address[:40]}',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={
            "mac_address": normalized or mac_address[:40],
            **({"vendor": vendor} if vendor else {}),
            **({"error": error} if error else {}),
        },
    )
    if state is None:
        # Still show what the honeypot has, next to the reason it failed.
        state, _ = await _mac_task(honeypot, app_settings)
    return await _render_mac_panel(
        request,
        db,
        honeypot,
        state=state,
        error=error,
        saved="" if error else "set",
        mac_address=mac_address.strip()[:40] if error else "",
        mac_vendor=mac_vendor.strip()[:255] if error else "",
    )


@router.post(
    "/{honeypot_id}/config/mac/reset", dependencies=[need_terminal, Depends(verify_csrf)]
)
async def reset_honeypot_mac_address(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Removes the unit: the hardware address is back after the next boot."""
    honeypot = await _get_writable_honeypot_or_404(honeypot_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)
    state, error = await _mac_task(honeypot, app_settings, reset=True)
    await log_event(
        db,
        request=request,
        action="honeypot.mac_address.reset",
        summary=f'Returned "{honeypot.name}" to its hardware MAC address',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )
    if state is None:
        state, _ = await _mac_task(honeypot, app_settings)
    return await _render_mac_panel(
        request, db, honeypot, state=state, error=error, saved="" if error else "reset"
    )
