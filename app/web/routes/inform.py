"""Self-registration endpoint: a not-yet-known honeypot announces itself
for review — see `app/db/models/pending_honeypot.py`'s module docstring
for how this differs from `POST /api/ingest/{id}/events` (an
already-registered honeypot's OpenCanary event stream).

This is a honeypot-to-server JSON API, not a browser form — there's no
cookie involved, so CSRF protection doesn't apply here (CSRF exploits a
browser automatically attaching cookies to a cross-site request; nothing
here relies on cookies). Two kinds of bearer token are accepted:

- The shared `INFORM_TOKEN` from the environment — the original mechanism.
- A per-user API token (`app.auth.api_tokens`) belonging to a user with
  write access — lets self-registration be attributed to (and revoked
  for) a specific person/script instead of one token shared by every
  honeypot.

Nothing submitted here is trusted for connecting to the honeypot — it just
creates a `PendingHoneypot` row for a superadmin to review. Turning it into
a real, manageable `Honeypot` still goes through the normal add-honeypot
form (which also requires picking a `Company`) and the mandatory host-key
discovery/confirmation flow.
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.api_tokens import get_user_for_api_token
from app.core.config import get_settings
from app.db.models.audit_log import AuditOutcome
from app.db.models.pending_honeypot import PendingHoneypot
from app.db.session import get_db
from app.schemas.inform import InformPayload

router = APIRouter(prefix="/api")


async def _verify_inform_token(request: Request, db: AsyncSession = Depends(get_db)) -> None:
    provided = request.headers.get("Authorization", "")
    expected = f"Bearer {get_settings().inform_token.get_secret_value()}"
    if secrets.compare_digest(provided, expected):
        return

    if provided.startswith("Bearer "):
        user = await get_user_for_api_token(db, provided.removeprefix("Bearer ").strip())
        if user is not None and user.can_write():
            return

    await log_event(
        db,
        request=request,
        action="honeypot.self_register",
        summary="Blocked self-registration: invalid or missing bearer token",
        outcome=AuditOutcome.DENIED,
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing bearer token."
    )


@router.post(
    "/inform",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_verify_inform_token)],
)
async def inform(
    request: Request, payload: InformPayload, db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
    source_ip = request.client.host if request.client else None
    pending = PendingHoneypot(
        ip_address=payload.ip_address or source_ip or "unknown",
        reported_hostname=payload.hostname,
        os_version=payload.os_version,
        kernel_version=payload.kernel_version,
        cpu_cores=payload.cpu_cores,
        ram_bytes=payload.ram_bytes,
        disks=payload.disks,
        source_ip=source_ip,
    )
    db.add(pending)
    await db.commit()
    await db.refresh(pending)

    await log_event(
        db,
        request=request,
        action="honeypot.self_register",
        summary=f"Honeypot self-registered as pending ({pending.ip_address})",
        target_type="pending_honeypot",
        target_id=pending.id,
        target_label=pending.ip_address,
    )

    return {"status": "received"}
