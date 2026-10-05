"""Per-account saved filters on a honeypot's Logs tab — see
`app.db.models.saved_log_view`. Shared by the Logs tab
(`app/web/routes/honeypots_logs.py`) and the REST API
(`app/web/routes/api_v1_account.py`)."""

from __future__ import annotations

import uuid
from urllib.parse import urlencode

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.saved_log_view import SavedLogView
from app.services.saved_views import MAX_VIEW_NAME_LENGTH, DuplicateViewNameError
from app.ssh.logs import normalize_boot, normalize_priority, normalize_unit

# The Logs tab's own filters, in a fixed order. No honeypot: a log view is
# replayed on whichever honeypot's Logs tab it's picked from.
ALLOWED_LOG_VIEW_PARAMS = (
    "source", "path", "priority", "unit", "boot", "hide_own", "search", "since", "until", "lines",
)
# "honeypot" = OpenCanary's own log, wherever it is on that honeypot.
LOG_VIEW_SOURCES = ("journal", "file", "honeypot")


def _clean(key: str, value: str) -> str:
    """One filter's value the way it is stored; "" drops it."""
    if key == "source":
        return value if value in LOG_VIEW_SOURCES else ""
    if key == "priority":
        return normalize_priority(value)
    if key == "unit":
        return normalize_unit(value)
    if key == "boot":
        return normalize_boot(value)
    if key == "lines":
        return value if value.isdigit() else ""
    if key == "hide_own":
        return "1" if value in ("1", "true", "on") else ""
    return value


def build_log_query_string(params: dict[str, str]) -> str:
    """Only the recognized, non-blank Logs filters, in a stable order;
    `source` and `priority` only when they're known values, `lines` only
    when it's a number."""
    ordered: dict[str, str] = {}
    own_log = str(params.get("source", "")).strip() == "honeypot"
    for key in ALLOWED_LOG_VIEW_PARAMS:
        value = _clean(key, str(params.get(key, "") or "").strip())
        # OpenCanary's own log sits wherever that honeypot keeps it.
        if value and not (own_log and key == "path"):
            ordered[key] = value[:300]
    return urlencode(ordered)


async def list_saved_log_views(db: AsyncSession, user_id: uuid.UUID) -> list[SavedLogView]:
    result = await db.execute(
        select(SavedLogView).where(SavedLogView.user_id == user_id).order_by(SavedLogView.name)
    )
    return list(result.scalars().all())


async def create_saved_log_view(
    db: AsyncSession, user_id: uuid.UUID, name: str, query_string: str
) -> SavedLogView:
    """Raises `DuplicateViewNameError` for a name this account already uses."""
    view = SavedLogView(
        user_id=user_id, name=name.strip()[:MAX_VIEW_NAME_LENGTH], query_string=query_string
    )
    db.add(view)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise DuplicateViewNameError(name) from None
    await db.refresh(view)
    return view


async def delete_saved_log_view(
    db: AsyncSession, user_id: uuid.UUID, view_id: uuid.UUID
) -> bool:
    result = await db.execute(
        select(SavedLogView).where(SavedLogView.id == view_id, SavedLogView.user_id == user_id)
    )
    view = result.scalar_one_or_none()
    if view is None:
        return False
    await db.delete(view)
    await db.commit()
    return True
