"""Add/delete a honeypot's history notes (`app.db.models.honeypot_note`) —
shared by the History tab (`app/web/routes/honeypots_detail.py`) and the
REST API (`app/web/routes/api_v1.py`), audited identically from both."""

from __future__ import annotations

import uuid

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_note import MAX_NOTE_LENGTH, HoneypotNote
from app.db.models.user import User


class EmptyNoteError(ValueError):
    """The note has no text."""


async def add_note(
    db: AsyncSession, request: Request, honeypot: Honeypot, user: User, body: str
) -> HoneypotNote:
    text = body.strip()[:MAX_NOTE_LENGTH]
    if not text:
        raise EmptyNoteError
    note = HoneypotNote(honeypot_id=honeypot.id, author=user.username, body=text)
    db.add(note)
    await db.commit()
    await db.refresh(note)
    await log_event(
        db,
        request=request,
        action="honeypot.note.add",
        summary=f'Added a note to "{honeypot.name}"',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"note": text[:500]},
    )
    return note


async def delete_note(
    db: AsyncSession, request: Request, honeypot: Honeypot, note_id: uuid.UUID
) -> bool:
    """`True` when a note of *this* honeypot was deleted."""
    result = await db.execute(
        select(HoneypotNote).where(
            HoneypotNote.id == note_id, HoneypotNote.honeypot_id == honeypot.id
        )
    )
    note = result.scalar_one_or_none()
    if note is None:
        return False
    body = note.body
    await db.delete(note)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="honeypot.note.delete",
        summary=f'Deleted a note from "{honeypot.name}"',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"note": body[:500]},
    )
    return True
