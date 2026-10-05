"""A dated, attributed note on a honeypot — "moved to the DMZ switch",
"replaced the SD card", "don't reboot before Friday" — shown on the
honeypot's History tab alongside what Honeypot Shelf itself recorded.

Adding or deleting one needs write access to the honeypot (the same access
that edits it) and is audit-logged.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

MAX_NOTE_LENGTH = 4000


class HoneypotNote(Base):
    __tablename__ = "honeypot_notes"
    __table_args__ = (
        Index("ix_honeypot_notes_honeypot_id_created_at", "honeypot_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    honeypot_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=False
    )
    # The author's username at the time — kept as text (like the audit
    # log's `actor`) so a note outlives its author's account.
    author: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
