""""Initialize" — provisions a brand new Raspberry Pi OS 13 device (not yet
managed by HoneyHive at all) into a working OpenCanary honeypot over SSH.
See `app.ssh.initialize` for exactly what the provisioning script does and
`app.tasks.jobs.run_honeypot_initialize` for the background task this
dispatches.

Deliberately **not** honeypot-scoped and **doesn't create a `Honeypot`
row** — it's a standalone tool that runs before a device exists in
HoneyHive's database at all. Once it succeeds, an operator adds the
device the normal way (`/honeypots/new`), which discovers and pins its
host key the usual, non-TOFU way.

**Host-key trust here is deliberately trust-on-first-use** — an explicit,
narrow exception to this app's otherwise strict no-blind-trust pinning
policy (see `app.ssh.client`'s module docstring): there is no prior
fingerprint to compare against for a device that was never in this app to
begin with, so the fingerprint the device presents on this first
connection is simply accepted. It's shown back to the operator afterwards
so they can note it down; nothing about it is stored anywhere.

Gated by `require_write` (not superadmin-only) — same tier as managing
honeypots within one's own company, since this is preparation for exactly
that, not company/user/company management.
"""

from __future__ import annotations

import asyncio
import re

from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import APIRouter, Depends, Form, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import require_write
from app.core.config import get_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.honeypot import AuthMethod
from app.db.session import get_db
from app.ssh.initialize import INITIALIZE_RUN_TIMEOUT_EXTRA_SECONDS
from app.tasks import jobs as tasks
from app.web.templating import templates

router = APIRouter(prefix="/initialize", dependencies=[Depends(require_write)])

# RFC 1123 hostname label — conservative on purpose: this value is written
# unescaped into a shell script (hostnamectl, /etc/hosts, sed's s///
# delimiter) by app.ssh.initialize.build_initialize_command, so rejecting
# anything but a safe hostname here is what keeps that string interpolation
# safe rather than needing shell-escaping tricks there.
_DEVICE_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


async def _render(
    request: Request, db: AsyncSession, *, errors: list[str] | None = None, **extra: object
) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    context: dict[str, object] = {
        "errors": errors or [],
        "csrf_token": csrf_token,
        **extra,
    }
    response = templates.TemplateResponse(request, "initialize/index.html", context)
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("")
async def initialize_form(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    return await _render(request, db)


@router.post("", dependencies=[Depends(verify_csrf)])
async def initialize_run(
    request: Request,
    db: AsyncSession = Depends(get_db),
    ip_address: str = Form(...),
    device_name: str = Form(...),
    username: str = Form(...),
    port: int = Form(22),
    auth_method: str = Form(AuthMethod.SSH_KEY.value),
    password: str = Form(""),
    netbird_setup_key: str = Form(""),
) -> Response:
    ip_address = ip_address.strip()
    device_name = device_name.strip()
    username = username.strip()

    errors: list[str] = []
    if not ip_address:
        errors.append("IP address is required.")
    if not _DEVICE_NAME_RE.match(device_name):
        errors.append(
            "Device name must be a valid hostname (letters, digits, hyphens; "
            "can't start or end with a hyphen)."
        )
    if not username:
        errors.append("User is required.")
    if not (1 <= port <= 65535):
        errors.append("SSH port must be between 1 and 65535.")
    if auth_method not in (AuthMethod.SSH_KEY.value, AuthMethod.PASSWORD.value):
        errors.append("Unknown authentication method.")
    if auth_method == AuthMethod.PASSWORD.value and not password:
        errors.append("A password is required for password authentication.")

    form_values = {
        "ip_address": ip_address,
        "device_name": device_name,
        "username": username,
        "port": port,
        "auth_method": auth_method,
    }
    if errors:
        return await _render(request, db, errors=errors, **form_values)

    settings = get_settings()
    async_result = tasks.run_honeypot_initialize.delay(
        ip_address,
        port,
        username,
        device_name,
        auth_method,
        password or None,
        netbird_setup_key.strip() or None,
    )

    error: str | None = None
    output: str | None = None
    fingerprint: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get,
            timeout=settings.ssh_connect_timeout + INITIALIZE_RUN_TIMEOUT_EXTRA_SECONDS + 10,
        )
        if isinstance(result, dict):
            fingerprint = result.get("fingerprint")
            if result.get("ok"):
                output = result.get("output")
            else:
                error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = (
            "The setup script did not finish in time. It may still be running on the "
            "device — check back, or re-run once it's had time to finish."
        )
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.initialize.run",
        summary=f'Ran Initialize on "{device_name}" ({ip_address})',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="device",
        target_label=f"{device_name} ({ip_address})",
        details={"error": error, "fingerprint": fingerprint} if (error or fingerprint) else None,
    )

    return await _render(
        request,
        db,
        errors=[],
        **form_values,
        output=output,
        run_error=error,
        fingerprint=fingerprint,
    )
