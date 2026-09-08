"""The Initialize page's WebSocket — actually runs the provisioning script
(`app.ssh.initialize.build_initialize_command`) over SSH and streams its
output live, plus a "which step is it on right now" banner. The byte-relay
counterpart to `app.web.routes.initialize`'s form/run-page shell, the same
split `app.web.routes.terminal_ws` documents for the interactive terminal
— see that module's docstring for why a WebSocket needs to re-implement
its own auth instead of using `require_write` like every other route
(`app.auth.middleware` never runs for WebSocket requests at all).

**Protocol**: text frames only, each a JSON object:
- `{"kind": "step", "label": "..."}` — a new phase started (parsed out of
  the script's own output, never shown as raw output — see
  `app.ssh.initialize.STEP_MARKER_PREFIX`).
- `{"kind": "output", "text": "..."}` — one line of the script's actual
  stdout/stderr (merged), verbatim.
- `{"kind": "done", "ok": true|false, "error": "..."|null, "fingerprint": "..."|null}`
  — the run finished (or failed); the socket closes right after.

Unlike the terminal, this is one-way (server to client) after the initial
connection — there's nothing for an operator to type back into a batch
script, so there's no input relay task here.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from datetime import UTC, datetime

import asyncssh
from fastapi import APIRouter, WebSocket, status
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.audit import log_event
from app.auth.sessions import SESSION_COOKIE_NAME, get_valid_session
from app.core.config import get_settings
from app.core.security import decrypt_secret
from app.db.models.audit_log import AuditOutcome
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.initialize_run import MAX_OUTPUT_CHARS, InitializeRun
from app.db.models.user import User
from app.ssh.client import discover_host_key_fingerprint, open_process_session
from app.ssh.exceptions import SSHConnectionError
from app.ssh.identity import get_or_create_identity
from app.ssh.initialize import (
    INITIALIZE_RUN_MAX_SECONDS,
    INITIALIZE_SUCCESS_MARKER,
    STEP_MARKER_PREFIX,
    build_initialize_command,
    service_user_for,
    wrap_for_sudo,
)
from app.web.routes.initialize import PENDING_RUNS, PendingInitializeRun

router = APIRouter()

_POLICY_VIOLATION = status.WS_1008_POLICY_VIOLATION


async def _authenticate(websocket: WebSocket) -> User | None:
    """Returns the user if this connection may run an Initialize job, or
    `None` after already closing the socket with an explanatory reason.
    Same two checks as every other write-gated page (`require_write`) —
    there's no company/honeypot to additionally scope against, since
    Initialize is deliberately standalone (see
    `app.web.routes.initialize`'s module docstring)."""
    raw_token = websocket.cookies.get(SESSION_COOKIE_NAME)
    if not raw_token:
        await websocket.close(code=_POLICY_VIOLATION, reason="Not authenticated.")
        return None

    db_session_factory = websocket.app.state.db_session_factory
    async with db_session_factory() as db:
        session = await get_valid_session(db, raw_token)
    if session is None:
        await websocket.close(code=_POLICY_VIOLATION, reason="Not authenticated.")
        return None

    user = session.user
    if not user.can_write():
        await websocket.close(code=_POLICY_VIOLATION, reason="Read-only account.")
        return None
    return user


async def _relay_output(
    websocket: WebSocket, process: asyncssh.SSHClientProcess[str], collected: list[str]
) -> None:
    """Reads the script's output one line at a time, forwarding each as
    either a `step` or `output` frame — see the module docstring's
    protocol note. `collected` accumulates every non-step line, purely so
    the caller can still check `INITIALIZE_SUCCESS_MARKER` the same way
    `app.ssh.exec.run_command`'s callers do, without a second read pass."""
    while True:
        line = await process.stdout.readline()
        if not line:
            return
        line = line.rstrip("\n")
        if line.startswith(STEP_MARKER_PREFIX):
            await websocket.send_text(
                json.dumps({"kind": "step", "label": line[len(STEP_MARKER_PREFIX) :]})
            )
            continue
        collected.append(line)
        await websocket.send_text(json.dumps({"kind": "output", "text": line}))


async def _send_done(
    websocket: WebSocket, *, ok: bool, error: str | None, fingerprint: str | None
) -> None:
    with contextlib.suppress(Exception):
        await websocket.send_text(
            json.dumps({"kind": "done", "ok": ok, "error": error, "fingerprint": fingerprint})
        )


async def _log_initialize_event(
    db_session_factory: async_sessionmaker[AsyncSession],
    *,
    user: User,
    run: PendingInitializeRun,
    error: str | None,
    duration_seconds: float,
) -> None:
    """Same reasoning as `app.web.routes.terminal_ws`'s `_log_terminal_event`
    for passing `actor` explicitly — there's no `Request` here."""
    details: dict[str, object] = {"duration_seconds": round(duration_seconds, 1)}
    if error:
        details["error"] = error
    async with db_session_factory() as db:
        await log_event(
            db,
            action="honeypot.initialize.run",
            summary=f'Ran Initialize on "{run.device_name}" ({run.ip_address})',
            outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
            target_type="device",
            target_label=f"{run.device_name} ({run.ip_address})",
            actor=user.username,
            details=details,
        )


async def _persist_initialize_run(
    db_session_factory: async_sessionmaker[AsyncSession],
    *,
    user: User,
    run: PendingInitializeRun,
    started_at: datetime,
    error: str | None,
    fingerprint: str | None,
    output_lines: list[str],
) -> None:
    """The durable counterpart to the live WebSocket stream — see
    `InitializeRun`'s module docstring for why this exists (nothing else
    keeps the script's output once the run page is closed)."""
    output = "\n".join(output_lines)
    if len(output) > MAX_OUTPUT_CHARS:
        output = output[-MAX_OUTPUT_CHARS:]
    async with db_session_factory() as db:
        db.add(
            InitializeRun(
                device_name=run.device_name,
                ip_address=run.ip_address,
                port=run.port,
                username=run.username,
                started_at=started_at,
                success=error is None,
                error=error,
                fingerprint=fingerprint,
                output=output,
                triggered_by=user.username,
            )
        )
        await db.commit()


@router.websocket("/initialize/run/{run_id}/ws")
async def initialize_websocket(websocket: WebSocket, run_id: str) -> None:
    user = await _authenticate(websocket)
    if user is None:
        return

    run = PENDING_RUNS.pop(run_id, None)
    if run is None:
        await websocket.close(code=_POLICY_VIOLATION, reason="Run not found or already started.")
        return

    await websocket.accept()

    settings = get_settings()
    db_session_factory = websocket.app.state.db_session_factory

    error: str | None = None
    fingerprint: str | None = None
    conn: asyncssh.SSHClientConnection | None = None
    process: asyncssh.SSHClientProcess[str] | None = None
    started_at = datetime.now(UTC)
    collected: list[str] = []

    try:
        await websocket.send_text(json.dumps({"kind": "step", "label": "Connecting"}))
        try:
            fingerprint = await discover_host_key_fingerprint(
                run.ip_address, run.port, settings.ssh_connect_timeout
            )
        except SSHConnectionError as exc:
            error = str(exc)
            return

        device = Honeypot(
            name=run.device_name,
            ip_address=run.ip_address,
            port=run.port,
            username=run.username,
            host_key_fingerprint=fingerprint,
        )
        async with db_session_factory() as db:
            if run.auth_method == AuthMethod.PASSWORD.value:
                device.auth_method = AuthMethod.PASSWORD
                secret = run.password
            else:
                device.auth_method = AuthMethod.SSH_KEY
                identity = await get_or_create_identity(db)
                secret = decrypt_secret(identity.private_key_encrypted)

        script = build_initialize_command(
            device_name=run.device_name,
            service_user=service_user_for(run.username),
            vpn_provider=run.vpn_provider,
            netbird_setup_key=run.netbird_setup_key,
            netbird_management_url=run.netbird_management_url,
            wireguard_config=run.wireguard_config,
        )
        script = wrap_for_sudo(
            script,
            ssh_username=run.username,
            sudo_password=run.password if run.auth_method == AuthMethod.PASSWORD.value else None,
        )

        try:
            conn, process = await open_process_session(
                device, secret, script, settings.ssh_connect_timeout
            )
        except SSHConnectionError as exc:
            error = str(exc)
            return

        try:
            await asyncio.wait_for(
                _relay_output(websocket, process, collected),
                timeout=INITIALIZE_RUN_MAX_SECONDS,
            )
        except TimeoutError:
            error = "Timed out — the script may still be running on the device."
            return

        exit_status = await process.wait()
        if (exit_status.exit_status or 0) != 0 or not any(
            INITIALIZE_SUCCESS_MARKER in line for line in collected
        ):
            error = f"Setup script exited {exit_status.exit_status}."
    except Exception as exc:  # noqa: BLE001 - reported to the client, not swallowed
        error = str(exc)
    finally:
        if process is not None:
            with contextlib.suppress(Exception):
                process.terminate()
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.close()

        await _send_done(websocket, ok=error is None, error=error, fingerprint=fingerprint)
        with contextlib.suppress(Exception):
            await websocket.close(code=status.WS_1000_NORMAL_CLOSURE)

        duration_seconds = (datetime.now(UTC) - started_at).total_seconds()
        with contextlib.suppress(Exception):
            await _log_initialize_event(
                db_session_factory,
                user=user,
                run=run,
                error=error,
                duration_seconds=duration_seconds,
            )
        with contextlib.suppress(Exception):
            await _persist_initialize_run(
                db_session_factory,
                user=user,
                run=run,
                started_at=started_at,
                error=error,
                fingerprint=fingerprint,
                output_lines=collected,
            )
