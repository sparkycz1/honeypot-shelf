""""Initialize" — provisions a brand new Raspberry Pi OS 13 device (not yet
managed by HoneyHive at all) into a working OpenCanary honeypot over SSH.
See `app.ssh.initialize` for exactly what the provisioning script does and
`app.web.routes.initialize_ws` for where it's actually run — this module
only ever handles the form (`GET`/`POST /initialize`) and the run page
shell (`GET /initialize/run/{run_id}`); the SSH connection and live output
streaming happen entirely in that WebSocket module, the same split
`app.web.routes.honeypots`/`app.web.routes.terminal_ws` already use for
the interactive terminal.

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

**Why a `run_id` + redirect instead of running it inline in this POST**:
a run can take up to `app.ssh.initialize.INITIALIZE_RUN_MAX_SECONDS`
(an hour) and the operator needs to *see* it happen live — that needs a
long-lived WebSocket, which a plain POST handler can't hand back. The
POST here only validates the form and stashes the (never persisted to
disk) connection details — including the one-time password/NetBird key,
if given — in `PENDING_RUNS`, an in-process dict keyed by a random
`run_id`; the redirect target's page immediately opens a WebSocket to
`/initialize/run/{run_id}/ws`, which pops (single-use) and actually runs
it. **This assumes a single web process** (true today — see the plain
`CMD ["uvicorn", ...]` with no `--workers` in the `Dockerfile`; a
multi-worker deployment would need this moved to Redis instead, the same
way `app.services.live_updates` already is for a similar reason).
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Form, Request, Response, status
from fastapi.responses import RedirectResponse

from app.auth.dependencies import require_write
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.honeypot import AuthMethod
from app.web.templating import templates

router = APIRouter(prefix="/initialize", dependencies=[Depends(require_write)])

# RFC 1123 hostname label — conservative on purpose: this value is written
# unescaped into a shell script (hostnamectl, /etc/hosts, sed's s///
# delimiter) by app.ssh.initialize.build_initialize_command, so rejecting
# anything but a safe hostname here is what keeps that string interpolation
# safe rather than needing shell-escaping tricks there.
_DEVICE_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

# How long an unclaimed run stays pending before `_purge_stale_runs` drops
# it — generous enough for a slow page load, short enough that a form
# submitted and then abandoned doesn't leave a password sitting in memory
# indefinitely.
_PENDING_RUN_TTL_SECONDS = 15 * 60


@dataclass
class PendingInitializeRun:
    """One `POST /initialize` submission, staged for `initialize_ws` to
    pick up — see this module's own docstring for why this exists instead
    of running inline. Never written to disk or the DB; popped (removed)
    the moment a WebSocket actually starts using it."""

    ip_address: str
    port: int
    username: str
    device_name: str
    auth_method: str
    password: str | None
    netbird_setup_key: str | None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


# Module-level, not `app.state` — see the module docstring's single-process
# caveat either way. `initialize_ws` imports this dict directly.
PENDING_RUNS: dict[str, PendingInitializeRun] = {}


def _purge_stale_runs() -> None:
    cutoff = datetime.now(UTC) - timedelta(seconds=_PENDING_RUN_TTL_SECONDS)
    stale = [run_id for run_id, run in PENDING_RUNS.items() if run.created_at < cutoff]
    for run_id in stale:
        PENDING_RUNS.pop(run_id, None)


async def _render_form(
    request: Request, *, errors: list[str] | None = None, **extra: object
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
async def initialize_form(request: Request) -> Response:
    return await _render_form(request)


@router.post("", dependencies=[Depends(verify_csrf)])
async def initialize_submit(
    request: Request,
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

    if errors:
        return await _render_form(
            request,
            errors=errors,
            ip_address=ip_address,
            device_name=device_name,
            username=username,
            port=port,
            auth_method=auth_method,
        )

    _purge_stale_runs()
    run_id = secrets.token_urlsafe(24)
    PENDING_RUNS[run_id] = PendingInitializeRun(
        ip_address=ip_address,
        port=port,
        username=username,
        device_name=device_name,
        auth_method=auth_method,
        password=password or None,
        netbird_setup_key=netbird_setup_key.strip() or None,
    )
    return RedirectResponse(
        url=f"/initialize/run/{run_id}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/run/{run_id}")
async def initialize_run_page(request: Request, run_id: str) -> Response:
    """The run's own page — connects `initialize_ws`'s WebSocket
    immediately on load (see `static/js/initialize.js`) to stream live
    output and step progress. Only peeks at `PENDING_RUNS` (doesn't pop
    it — the WebSocket does, once it actually starts using it), so a
    refresh of this page before the socket connects still works.
    """
    _purge_stale_runs()
    run = PENDING_RUNS.get(run_id)
    if run is None:
        # Never existed, expired, or a run already claimed and finished —
        # either way there's nothing left to show; back to a fresh form
        # rather than an error page for what's usually just a stale
        # bookmark/refresh-after-completion.
        return RedirectResponse(url="/initialize", status_code=status.HTTP_303_SEE_OTHER)

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "initialize/run.html",
        {
            "run_id": run_id,
            "device_name": run.device_name,
            "ip_address": run.ip_address,
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response
