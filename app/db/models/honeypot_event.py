"""One row per OpenCanary alert ingested from a honeypot.

OpenCanary emits one JSON object per event (its `logdata` dict plus common
fields `logtype`, `local_time`, `src_host`, `src_port`, `dst_host`,
`dst_port`, `node_id`) — see
https://github.com/thinkst/opencanary/blob/master/opencanary/logger.py and
the module list in the OpenCanary wiki for what `logtype`/`logdata` look
like per service (SSH, Telnet, FTP, HTTP, SMB, ...). `POST
/api/ingest/events` (`app.web.routes.ingest`) accepts that shape close to
verbatim — `raw` keeps the untouched payload for anything the UI doesn't
special-case yet; the handful of promoted columns below exist purely so the
common list/filter/dashboard queries don't have to unpack JSON on every
row.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.honeypot import Honeypot


class HoneypotEvent(Base):
    __tablename__ = "honeypot_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    honeypot_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    honeypot: Mapped[Honeypot] = relationship(back_populates="events", lazy="joined")
    # Denormalized onto the event so a company-wide event query never has to
    # join through Honeypot — every list/filter/dashboard-count query in
    # this app is scoped by company first (see app.services.access_scope).
    company_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # OpenCanary's own event type, e.g. "SSH_LOGIN_ATTEMPT", "PORTSCAN",
    # "HTTP_GET" — see the OpenCanary wiki's module list for the full set.
    # Free text, not an enum: OpenCanary modules (and their logtypes) are
    # configured per-honeypot and can change without a HoneyHive release.
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    occurred_at: Mapped[datetime] = mapped_column(nullable=False, index=True)
    received_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # The full OpenCanary payload (logdata + common fields), untouched —
    # source of truth for anything not promoted to its own column above.
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    # How this row got here — "push" (a forwarder called POST
    # /api/ingest/{id}/events, see app/web/routes/ingest.py) or "ssh_poll"
    # (HoneyHive itself read a new line from OpenCanary's log over SSH, see
    # app.ssh.canary_activity/app.tasks.jobs.poll_all_honeypot_canary_logs).
    # Free text like `event_type`, not an enum, for the same reason — kept
    # simple since there are only ever the two values in practice. Existing
    # rows predate this column and were all "push" (see the migration).
    source: Mapped[str] = mapped_column(String(20), nullable=False, server_default="push")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"HoneypotEvent(id={self.id!r}, event_type={self.event_type!r}, "
            f"src_ip={self.src_ip!r})"
        )
