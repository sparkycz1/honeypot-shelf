"""A file on a honeypot that is watched for changes
(`app.services.watched_files`). Ported from debcontrol's
`MachineWatchedFile`."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Integer, LargeBinary, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class HoneypotWatchedFile(Base):
    __tablename__ = "honeypot_watched_files"
    __table_args__ = (
        UniqueConstraint("honeypot_id", "path", name="uq_honeypot_watched_files_path"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    honeypot_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    # "pending" until first read, then "ok" / "missing" / "unreadable" /
    # "too_large".
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # The file as last read, and as it was before its last change. Encrypted:
    # a configuration file may hold a secret.
    content_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    previous_content_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    lines_added: Mapped[int | None] = mapped_column(Integer, nullable=True)
    lines_removed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    checked_at: Mapped[datetime | None] = mapped_column(nullable=True)
    changed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"HoneypotWatchedFile(honeypot_id={self.honeypot_id!r}, path={self.path!r})"
