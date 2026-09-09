"""Event ingestion from a honeypot — the one endpoint an OpenCanary host
itself ever talks to. Not a session-authenticated page: `/api/ingest/...`
sits under `app.auth.middleware`'s `/api/` public prefix, bearer-token
authenticated instead (either the shared `INGEST_TOKEN`, or a per-honeypot
token — see `Honeypot.ingest_token_hash`), mirroring the shared-token/
per-resource-token shape of debcontrol's `POST /api/inform`.

**How events actually get here** (see wiki/Honeypot-Onboarding.md): OpenCanary
itself only writes to a local log file/syslog/its own handlers — it has no
built-in "POST to a URL" output. A small forwarder on the Pi (a `logger`
config in OpenCanary's own JSON output pointed at a local pipe, or a tiny
tailer script/systemd unit) is what actually calls this endpoint. This route
accepts OpenCanary's own JSON event shape close to verbatim so that
forwarder can stay a thin, close-to-`curl` shim.
"""

from __future__ import annotations

import hashlib
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
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    # Constant-time comparisons — a naive `==` leaks how many leading bytes
    # matched through response timing, same reasoning as every other
    # secret comparison in this app (session/API tokens, CSRF).
    is_shared_token = hmac.compare_digest(
        raw_token, settings.ingest_token.get_secret_value()
    )
    is_per_honeypot_token = honeypot.ingest_token_hash is not None and hmac.compare_digest(
        honeypot.ingest_token_hash, token_hash
    )
    if not (is_shared_token or is_per_honeypot_token):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid ingest token.")
    return honeypot


@router.post("/{honeypot_id}/events", status_code=status.HTTP_201_CREATED)
async def ingest_event(
    honeypot_id: uuid.UUID,
    request: Request,
    payload: Annotated[dict[str, Any], Body(...)],
    authorization: Annotated[str | None, Header()] = None,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    honeypot = await _authenticate_honeypot(db, honeypot_id, authorization)

    event = build_event(honeypot, payload, source=EventSource.PUSH)
    db.add(event)

    honeypot.last_seen_at = datetime.now(UTC)
    client_ip = request.client.host if request.client else None
    if client_ip:
        honeypot.last_seen_ip = client_ip

    await db.commit()
    return {"status": "accepted", "event_id": str(event.id)}
