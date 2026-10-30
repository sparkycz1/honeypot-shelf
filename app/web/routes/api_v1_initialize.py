"""REST API for Initialize — provision a fresh device into a honeypot,
the same run the web page starts (`app.web.routes.initialize_ws.
run_initialize`), with the same validation and the same audit entry and
history record.

The web page watches a run over a WebSocket; here `POST` starts it in the
background and answers `202` with a `run_id`, and `GET .../runs/{run_id}`
reports its progress (current step, the script's output so far, and once
finished `ok`/`error` and the device's SSH host key fingerprint). Like on
the web, only the account that started a run can follow it — the run
holds the device's password and VPN secrets until it ends, and those are
never returned or stored. A finished run stays readable here for an hour,
then only in the history (`/history`), which keeps every run.

Needs write access, like the web page, and a token that isn't limited
to some companies. Same single-web-process caveat as
the page (see `app.web.routes.initialize`)."""

from __future__ import annotations

import asyncio
import itertools
import secrets
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_api_token_user, require_api_write
from app.db.models.honeypot import AuthMethod
from app.db.models.initialize_run import InitializeRun
from app.db.models.user import User
from app.db.session import get_db
from app.ssh.initialize import NEW_SSH_PORT
from app.web.routes import initialize_ws
from app.web.routes.initialize import PendingInitializeRun, validate_initialize_input


async def _require_unlimited_write(user: User = Depends(require_api_write)) -> User:
    """Initialize belongs to no company: the new device isn't in one yet,
    and the run history covers the whole fleet. So a token limited to some
    companies can't use it, like the superadmin-only endpoints."""
    if user.token_company_scope is not None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, detail="This API token is limited to some companies."
        )
    return user


router = APIRouter(
    prefix="/api/v1/initialize", dependencies=[Depends(_require_unlimited_write)]
)

_FINISHED_RUN_TTL = timedelta(hours=1)
_MAX_LIVE_OUTPUT_LINES = 5000
_HISTORY_PAGE_SIZE = 50


@dataclass
class LiveRun:
    """What `GET .../runs/{run_id}` reports — no credentials in here."""

    created_by: uuid.UUID
    device_name: str
    ip_address: str
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    step: str | None = None
    steps: list[str] = field(default_factory=list)
    output: deque[str] = field(default_factory=lambda: deque(maxlen=_MAX_LIVE_OUTPUT_LINES))
    output_dropped: int = 0
    done: bool = False
    ok: bool | None = None
    error: str | None = None
    fingerprint: str | None = None
    finished_at: datetime | None = None

    async def emit(self, frame: dict[str, Any]) -> None:
        kind = frame.get("kind")
        if kind == "step":
            self.step = str(frame.get("label"))
            self.steps.append(self.step)
        elif kind == "output":
            if len(self.output) == self.output.maxlen:
                self.output_dropped += 1
            self.output.append(str(frame.get("text")))
        elif kind == "done":
            self.done = True
            self.ok = bool(frame.get("ok"))
            error, fingerprint = frame.get("error"), frame.get("fingerprint")
            self.error = str(error) if error is not None else None
            self.fingerprint = str(fingerprint) if fingerprint is not None else None
            self.finished_at = datetime.now(UTC)


LIVE_RUNS: dict[str, LiveRun] = {}
# Strong references, so a running task is never garbage-collected.
_TASKS: set[asyncio.Task[None]] = set()


def _purge_finished_runs() -> None:
    cutoff = datetime.now(UTC) - _FINISHED_RUN_TTL
    for run_id in [
        rid for rid, r in LIVE_RUNS.items() if r.finished_at is not None and r.finished_at < cutoff
    ]:
        LIVE_RUNS.pop(run_id, None)


class InitializeRequest(BaseModel):
    ip_address: str = Field(min_length=1, max_length=255)
    device_name: str = Field(min_length=1, max_length=63)
    username: str = Field(min_length=1, max_length=255)
    port: int = 22
    auth_method: Literal["ssh_key", "password"] = "ssh_key"
    password: str | None = Field(default=None, max_length=1024)
    vpn_provider: Literal["none", "netbird", "wireguard"] = "none"
    netbird_setup_key: str | None = Field(default=None, max_length=1024)
    netbird_management_url: str | None = Field(default=None, max_length=1024)
    wireguard_config: str | None = Field(default=None, max_length=20000)
    new_ssh_port: int = NEW_SSH_PORT
    mac_address: str | None = Field(default=None, max_length=40)


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def start_initialize_api(
    request: Request,
    payload: InitializeRequest,
    user: User = Depends(get_api_token_user),
) -> dict[str, str]:
    """Starts provisioning the device; poll `GET /api/v1/initialize/runs/
    {run_id}` until `done`. Same fields as the web form; `password` is
    required for `auth_method: "password"` and is also used for sudo."""
    ip_address = payload.ip_address.strip()
    device_name = payload.device_name.strip()
    username = payload.username.strip()
    management_url = (payload.netbird_management_url or "").strip()
    wireguard_config = (payload.wireguard_config or "").strip()
    errors, mac = validate_initialize_input(
        ip_address=ip_address,
        device_name=device_name,
        username=username,
        port=payload.port,
        new_ssh_port=payload.new_ssh_port,
        auth_method=payload.auth_method,
        password=payload.password or "",
        vpn_provider=payload.vpn_provider,
        netbird_management_url=management_url,
        wireguard_config=wireguard_config,
        mac_address=payload.mac_address or "",
    )
    if errors:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=errors)

    pending = PendingInitializeRun(
        ip_address=ip_address,
        port=payload.port,
        username=username,
        device_name=device_name,
        auth_method=AuthMethod(payload.auth_method).value,
        password=payload.password or None,
        vpn_provider=payload.vpn_provider,
        netbird_setup_key=(payload.netbird_setup_key or "").strip() or None,
        netbird_management_url=management_url or None,
        wireguard_config=wireguard_config or None,
        new_ssh_port=payload.new_ssh_port,
        mac_address=mac,
        created_by=user.id,
    )
    _purge_finished_runs()
    run_id = secrets.token_urlsafe(24)
    live = LiveRun(created_by=user.id, device_name=device_name, ip_address=ip_address)
    LIVE_RUNS[run_id] = live
    task = asyncio.create_task(
        initialize_ws.run_initialize(
            pending, user, request.app.state.db_session_factory, live.emit
        )
    )
    _TASKS.add(task)
    task.add_done_callback(_TASKS.discard)
    return {"run_id": run_id}


@router.get("/runs/{run_id}")
async def initialize_run_api(
    run_id: str,
    since: int = 0,
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """A run's progress. `since` skips output lines already read (pass the
    previous answer's `next_since`)."""
    _purge_finished_runs()
    live = LIVE_RUNS.get(run_id)
    # Another account's run is "not found", as on the web.
    if live is None or live.created_by != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found.")
    total = live.output_dropped + len(live.output)
    start = max(since - live.output_dropped, 0)
    return {
        "device_name": live.device_name,
        "ip_address": live.ip_address,
        "started_at": live.started_at.isoformat(),
        "step": live.step,
        "steps": live.steps,
        "output": list(itertools.islice(live.output, start, None)),
        "next_since": total,
        "done": live.done,
        "ok": live.ok,
        "error": live.error,
        "fingerprint": live.fingerprint,
        "finished_at": live.finished_at.isoformat() if live.finished_at else None,
    }


def _history_row(run: InitializeRun, *, with_output: bool) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": str(run.id),
        "device_name": run.device_name,
        "ip_address": run.ip_address,
        "port": run.port,
        "username": run.username,
        "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "success": run.success,
        "error": run.error,
        "fingerprint": run.fingerprint,
        "triggered_by": run.triggered_by,
    }
    if with_output:
        row["output"] = run.output
    return row


@router.get("/history")
async def initialize_history_api(db: AsyncSession = Depends(get_db)) -> list[dict[str, Any]]:
    """The last 50 runs, newest first — the web page's Initialize history."""
    result = await db.execute(
        select(InitializeRun).order_by(InitializeRun.finished_at.desc()).limit(_HISTORY_PAGE_SIZE)
    )
    return [_history_row(r, with_output=False) for r in result.scalars()]


@router.get("/history/{history_id}")
async def initialize_history_detail_api(
    history_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    """One past run, with the script's full output."""
    run = await db.get(InitializeRun, history_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found.")
    return _history_row(run, with_output=True)
