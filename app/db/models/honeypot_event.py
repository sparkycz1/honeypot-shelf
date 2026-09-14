"""One row per OpenCanary alert ingested from a honeypot.

OpenCanary emits one JSON object per event (its `logdata` dict plus common
fields `logtype`, `local_time`, `src_host`, `src_port`, `dst_host`,
`dst_port`, `node_id`) — see
https://github.com/thinkst/opencanary/blob/master/opencanary/logger.py and
the module list in the OpenCanary wiki for what `logtype`/`logdata` look
like per service (SSH, Telnet, FTP, HTTP, SMB, ...). `app.ssh.
canary_activity`/`app.services.honeypot_events.build_event` — reached by
SSH-polling a honeypot's own log, the only way a row is created — accepts
that shape close to verbatim. `raw` keeps the untouched payload for
anything the UI doesn't special-case yet; the handful of promoted columns
below exist purely so the common list/filter/dashboard queries don't have
to unpack JSON on every row.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Float, ForeignKey, Integer, String, func
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
    # No denormalized `company_id` any more — a honeypot can belong to any
    # number of companies now (see app.db.models.company's module
    # docstring), so an event's company scope is derived by joining
    # through `honeypot.companies` at query time instead (see
    # `app.auth.scope`). Was a single required FK before this.

    # OpenCanary's own event type, e.g. "SSH_LOGIN_ATTEMPT", "PORTSCAN",
    # "HTTP_GET" — see the OpenCanary wiki's module list for the full set.
    # Free text, not an enum: OpenCanary modules (and their logtypes) are
    # configured per-honeypot and can change without a Honeypot Shelf release.
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    occurred_at: Mapped[datetime] = mapped_column(nullable=False, index=True)
    received_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Resolved once, at ingestion time, from `src_ip` via
    # `app.services.geoip` — not re-derived later, so a row's location
    # stays historically accurate even after the GeoIP database itself is
    # updated. All `None` when GeoIP isn't configured, `src_ip` is missing,
    # or (deliberately) `src_ip` isn't a public address at all — see
    # `app.services.geoip`'s own module docstring. `src_country_code` is
    # ISO 3166-1 alpha-2 (e.g. "US"), the source of the flag emoji shown
    # next to it — see `app.services.geoip_display.country_flag`.
    src_country_code: Mapped[str | None] = mapped_column(String(2), nullable=True, index=True)
    src_country_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    src_city_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    src_latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    src_longitude: Mapped[float | None] = mapped_column(Float, nullable=True)

    # The full OpenCanary payload (logdata + common fields), untouched —
    # source of truth for anything not promoted to its own column above.
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    # How this row got here — always "ssh_poll" now (Honeypot Shelf itself
    # read a new line from OpenCanary's log over SSH — see
    # app.ssh.canary_activity/app.tasks.jobs.poll_all_honeypot_canary_logs).
    # A now-removed forwarder-push endpoint used to also write "push" rows;
    # some existing deployments may still have historical rows with that
    # value. Free text like `event_type`, not an enum, for the same
    # reason — kept simple even though there's only ever one value written
    # going forward.
    source: Mapped[str] = mapped_column(String(20), nullable=False, server_default="ssh_poll")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"HoneypotEvent(id={self.id!r}, event_type={self.event_type!r}, "
            f"src_ip={self.src_ip!r})"
        )
