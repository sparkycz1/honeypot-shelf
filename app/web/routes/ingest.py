"""Event ingestion from a honeypot — the one endpoint an OpenCanary host
itself ever talks to. Not a session-authenticated page: `/api/ingest/...`
sits under `app.auth.middleware`'s `/api/` public prefix, bearer-token
authenticated instead (the shared `INGEST_TOKEN`), mirroring the
shared-token shape of debcontrol's `POST /api/inform`. (An earlier version
also supported a per-honeypot token, alongside the shared one — removed:
the Activity tab's own SSH log poll already covers every honeypot without
needing push-based ingestion configured on each one individually.)

**How events actually get here** (see wiki/Honeypot-Onboarding.md): OpenCanary
itself only writes to a local log file/syslog/its own handlers — it has no
built-in "POST to a URL" output. A small forwarder on the Pi (a `logger`
config in OpenCanary's own JSON output pointed at a local pipe, or a tiny
tailer script/systemd unit) is what actually calls this endpoint. This route
accepts OpenCanary's own JSON event shape close to verbatim so that
forwarder can stay a thin, close-to-`curl` shim.
"""

from __future__ import annotations

import hmac
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.models.honeypot import Honeypot
from app.db.session import get_db
from app.services.honeypot_events import EventSource, build_event
from app.services.opencanary_logtypes import is_internal_logtype

router = APIRouter(prefix="/api/ingest", tags=["ingest"])


async def _authenticate_honeypot(
    db: AsyncSession, honeypot_id: uuid.UUID, authorization: str | None
) -> Honeypot:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token.")
    raw_token = authorization.removeprefix("Bearer ").strip()

    honeypot = await db.get(Honeypot, honeypot_id)
    if honeypot is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Unknown honeypot id.")

    settings = get_settings()
    # Constant-time comparison — a naive `==` leaks how many leading bytes
    # matched through response timing, same reasoning as every other
    # secret comparison in this app (session/API tokens, CSRF).
    if not hmac.compare_digest(raw_token, settings.ingest_token.get_secret_value()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid ingest token.")
    return honeypot


@router.post("/{honeypot_id}/events", status_code=status.HTTP_201_CREATED)
async def ingest_event(
    honeypot_id: uuid.UUID,
    request: Request,
    payload: Annotated[dict[str, Any], Body(...)],
    authorization: Annotated[str | None, Header()] = None,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str | None]:
    honeypot = await _authenticate_honeypot(db, honeypot_id, authorization)

    honeypot.last_seen_at = datetime.now(UTC)
    client_ip = request.client.host if request.client else None
    if client_ip:
        honeypot.last_seen_ip = client_ip

    # OpenCanary's own internal/operational log lines ("General message",
    # a crash-loop's repeated startup banner, ...) still prove the
    # forwarder is alive (last_seen_* above already reflects that) but
    # aren't a real alert — skip storing a HoneypotEvent for one, same as
    # the SSH-poll path (app.tasks.jobs._poll_honeypot_canary_log).
    event_id: str | None = None
    if not is_internal_logtype(payload.get("logtype")):
        event = build_event(honeypot, payload, source=EventSource.PUSH)
        db.add(event)
        event_id = str(event.id)

    await db.commit()
    return {"status": "accepted", "event_id": event_id}
