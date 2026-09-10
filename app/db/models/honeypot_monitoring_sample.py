"""One CPU/load/RAM/network/disk-I/O/filesystem-usage sample for a managed
honeypot, taken on the Monitoring tab's own cadence (`MONITORING_INTERVAL_SECONDS`, see
`app.ssh.monitoring` and `app.tasks.jobs._sample_honeypot_monitoring`).

Unlike `HoneypotPackage`/`HoneypotService`, this genuinely is a history, not
a replaced snapshot — the whole point is trend graphs over a time range.
Purged by `app.tasks.jobs.purge_old_monitoring_samples` per
`AppSettings.monitoring_history_retention_days` (overridable per honeypot —
see `Honeypot.monitoring_history_retention_days`).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, BigInteger, Float, ForeignKey, Index, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.honeypot import Honeypot


class HoneypotMonitoringSample(Base):
    __tablename__ = "honeypot_monitoring_samples"
    __table_args__ = (
        # The one query this table exists to serve: "this honeypot's samples
        # in this time range, in order" — and the same shape the retention
        # purge deletes by.
        Index("ix_honeypot_monitoring_samples_honeypot_id_sampled_at", "honeypot_id", "sampled_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    honeypot_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    honeypot: Mapped[Honeypot] = relationship(viewonly=True)

    sampled_at: Mapped[datetime] = mapped_column(nullable=False)

    # 0-100, None if it couldn't be computed (e.g. /proc/stat unreadable).
    cpu_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    # 1/5/15-minute load averages (`/proc/loadavg`) — a count of
    # runnable+uninterruptible processes, not a percentage; can exceed a
    # honeypot's own `cpu_cores`, unlike cpu_percent.
    load1: Mapped[float | None] = mapped_column(Float, nullable=True)
    load5: Mapped[float | None] = mapped_column(Float, nullable=True)
    load15: Mapped[float | None] = mapped_column(Float, nullable=True)
    ram_used_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Stored per-sample (not just read off `Honeypot.ram_bytes`) so a sample
    # row stays meaningful on its own even if RAM changes (or hasn't been
    # gathered by a facts refresh yet at all).
    ram_total_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Each {"iface": ..., "rx_bytes": ..., "tx_bytes": ...} — cumulative
    # counters since boot (loopback excluded), one entry per interface
    # found. The Monitoring tab's graphs compute a rate (bytes/sec) from
    # the delta between consecutive samples — see
    # app.services.monitoring_history.
    network_io: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # Each {"device": ..., "read_bytes": ..., "write_bytes": ...} —
    # cumulative counters since boot, one entry per whole disk found. A
    # different question from `filesystems` below (throughput vs. how
    # full a mount is), sampled here for the same reason.
    disk_io: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # Each {"mount": ..., "size_bytes": ..., "used_bytes": ..., "avail_bytes":
    # ..., "use_percent": ...} — same shape as `Honeypot.filesystems` (the
    # facts snapshot), but historized on this table's own shorter cadence
    # so the Monitoring tab can chart usage *over time*, not just show the
    # single most recent reading.
    filesystems: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # None = couldn't tell (no `systemctl` — see app.ssh.monitoring), not
    # "zero failed services".
    failed_services_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # `systemctl is-active opencanary` on this same round trip — None =
    # couldn't tell (no `systemctl`), not "inactive". Drives the
    # Monitoring tab's "OpenCanary service" panel, styled and computed
    # the same way the Availability panel's own uptime graph is (see
    # app.services.monitoring_history.MonitoringHistory.opencanary_active)
    # — a dedicated, historized signal distinct from both
    # `Honeypot.is_reachable` (SSH reachability) and `last_seen_at`
    # (OpenCanary event flow): this one answers "was the systemd unit
    # itself reported active", independent of whether it emitted any
    # events during this sample or is even reachable by anything other
    # than this app's own SSH connection.
    opencanary_active: Mapped[bool | None] = mapped_column(nullable=True)
