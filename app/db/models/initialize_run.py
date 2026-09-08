"""A persisted record of one "Initialize" run (`app.web.routes.initialize_ws`)
— unlike `HoneypotUpdateRun`, this isn't tied to a `Honeypot` row (the whole
point of Initialize is provisioning a device *before* it's added to
HoneyHive, see `app.web.routes.initialize`'s module docstring), so this is
its own standalone table rather than reusing that one.

Written once, at the end of the run — there's no PENDING/RUNNING status the
way `HoneypotUpdateRun` has, since the live progress is only ever streamed
over the WebSocket while it's happening; this is purely the "what happened"
record left behind for later, e.g. debugging a failed provisioning without
having kept the browser tab open."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# Defensive cap, not a real-world expectation — a normal run's output (apt
# full-upgrade included) is a few thousand lines, comfortably under this.
# Guards against an unbounded row if a script ever loops/hangs producing
# output right up to the timeout.
MAX_OUTPUT_CHARS = 500_000


class InitializeRun(Base):
    __tablename__ = "initialize_runs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    device_name: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    username: Mapped[str] = mapped_column(String(255), nullable=False)

    started_at: Mapped[datetime] = mapped_column(nullable=False)
    finished_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    output: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # The username of whoever ran it — a plain string, not a FK, same
    # reasoning as the audit log's own `actor` column: this must stay
    # readable even after the user account is later deleted.
    triggered_by: Mapped[str] = mapped_column(String(255), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"InitializeRun(id={self.id!r}, device_name={self.device_name!r}, "
            f"success={self.success!r})"
        )
