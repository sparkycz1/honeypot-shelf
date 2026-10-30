"""Turns a honeypot's raw `HoneypotEvent` rows (see `app.services.
honeypot_events`, `app.ssh.canary_activity`) into the bucketed series the
Activity tab's chart renders — same idea as `app.services.monitoring_
history`, but genuinely time-aligned buckets rather than positional
downsampling: an event is a discrete occurrence, not a periodic
measurement, so "spread evenly across however many rows came back" would
distort a bursty attack (e.g. a portscan) into a flat line. Reuses
`monitoring_history.TIME_RANGES`/`time_range_delta` — same range picker,
one definition of what "Last 24 hours" means across both tabs.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import ColumnElement, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.honeypot_event import HoneypotEvent
from app.services.honeypot_status import as_aware_utc
from app.services.monitoring_history import time_range_delta
from app.services.opencanary_logtypes import logtype_label, module_key

# Fixed bucket count for the trend chart, independent of the time range —
# unlike the Monitoring tab's downsampling (which starts from however many
# *samples* exist), an event count naturally wants the same-width columns
# whichever range is selected.
BUCKET_COUNT = 60

# How many of the most recent individual events to list in the raw activity
# table below the chart — a quick "what actually just happened" view,
# independent of the aggregated/bucketed chart above it.
RECENT_EVENTS_LIMIT = 50

# How many distinct alert types get their own line in the per-type
# breakdown — anything past this is folded into "Other", so the chart
# legend never gets unreadable on a honeypot with many active modules.
_TOP_TYPES_LIMIT = 8


@dataclass
class ActivityHistory:
    bucket_timestamps: list[datetime] = field(default_factory=list)
    total_counts: list[int] = field(default_factory=list)
    # event_type -> per-bucket counts, one entry per one of the top
    # `_TOP_TYPES_LIMIT` types in this window (by total count), plus an
    # "other" entry if anything didn't make the cut.
    counts_by_type: dict[str, list[int]] = field(default_factory=dict)
    # event_type -> total count in the whole window (used for the numbers
    # table below the chart, and to pick the top types above).
    totals_by_type: dict[str, int] = field(default_factory=dict)
    sample_count: int = 0

    @property
    def total(self) -> int:
        return sum(self.total_counts)


def _bucket_layout(
    range_key: str, now: datetime, start: datetime | None
) -> tuple[datetime, timedelta, list[datetime]]:
    """Where the window starts, how wide one bucket is, and each bucket's
    midpoint. A custom window (`start` given, `now` being its end) is
    bucketed over its own length; a preset over the preset's."""
    delta = now - start if start is not None else time_range_delta(range_key)
    start = now - delta
    bucket_width = delta / BUCKET_COUNT
    bucket_timestamps = [start + bucket_width * (i + 0.5) for i in range(BUCKET_COUNT)]
    return start, bucket_width, bucket_timestamps


def _assemble(
    counts: dict[tuple[int, object], int],
    bucket_timestamps: list[datetime],
    *,
    label_of: Callable[[object], str],
    other_label: str,
) -> ActivityHistory:
    """`counts` maps (bucket index, raw event type) to how many events."""
    total_counts = [0] * BUCKET_COUNT
    totals_by_type: dict[str, int] = {}
    per_type_buckets: dict[str, list[int]] = {}
    for (index, event_type), count in counts.items():
        label = label_of(event_type)
        total_counts[index] += count
        totals_by_type[label] = totals_by_type.get(label, 0) + count
        per_type_buckets.setdefault(label, [0] * BUCKET_COUNT)[index] += count

    top_labels = [
        label
        for label, _count in sorted(totals_by_type.items(), key=lambda kv: kv[1], reverse=True)[
            :_TOP_TYPES_LIMIT
        ]
    ]
    counts_by_type = {label: per_type_buckets[label] for label in top_labels}
    if len(totals_by_type) > len(top_labels):
        other_buckets = [0] * BUCKET_COUNT
        for label, buckets in per_type_buckets.items():
            if label in counts_by_type:
                continue
            for i, count in enumerate(buckets):
                other_buckets[i] += count
        counts_by_type[other_label] = other_buckets

    return ActivityHistory(
        bucket_timestamps=bucket_timestamps,
        total_counts=total_counts,
        counts_by_type=counts_by_type,
        totals_by_type=totals_by_type,
        sample_count=sum(total_counts),
    )


def build_activity_history(
    events: list[HoneypotEvent],
    range_key: str,
    *,
    now: datetime,
    start: datetime | None = None,
    label_of: Callable[[object], str] = logtype_label,
    other_label: str = "Other",
) -> ActivityHistory:
    """Pure function over already-loaded rows (tests, small lists); pages
    use `load_activity_history`, which counts in the database instead.
    `label_of` defaults to the plain-English `logtype_label` — a
    template-rendering caller passes `app.services.opencanary_logtypes.
    localized_logtype_label` pre-bound to the current request's `t`, so
    the chart legend/table read in whichever language the viewer's session
    is in."""
    start, bucket_width, bucket_timestamps = _bucket_layout(range_key, now, start)
    counts: dict[tuple[int, object], int] = {}
    for event in events:
        # SQLite (this app's test backend) drops tzinfo on round-trip;
        # real Postgres columns never do — normalize before comparing, same
        # gotcha `app.services.honeypot_status.is_online` was written for.
        occurred_at = as_aware_utc(event.occurred_at)
        offset = (occurred_at - start) / bucket_width if bucket_width else 0
        index = min(max(int(offset), 0), BUCKET_COUNT - 1)
        key = (index, event.event_type)
        counts[key] = counts.get(key, 0) + 1
    return _assemble(counts, bucket_timestamps, label_of=label_of, other_label=other_label)


async def load_activity_history(
    db: AsyncSession,
    conditions: list[ColumnElement[bool]],
    range_key: str,
    *,
    now: datetime,
    start: datetime | None = None,
    label_of: Callable[[object], str] = logtype_label,
    other_label: str = "Other",
) -> ActivityHistory:
    """Every event matching `conditions` counted per bucket and type by the
    database (one GROUP BY over a CASE on `occurred_at`), so a busy window
    is counted in full instead of loading rows. Loading the oldest 20,000
    rows (before 0.84.2) cut a long or flooded window short: its newest
    buckets read zero. Portable SQL, so SQLite runs the same query.
    `conditions` must hold the window itself (`occurred_at` between the
    start and `now`); anything outside is clamped into the first or last
    bucket, like `build_activity_history`."""
    start, bucket_width, bucket_timestamps = _bucket_layout(range_key, now, start)
    bucket = case(
        *[
            (HoneypotEvent.occurred_at < start + bucket_width * (i + 1), i)
            for i in range(BUCKET_COUNT - 1)
        ],
        else_=BUCKET_COUNT - 1,
    )
    # Grouped in an outer query: grouping by the CASE itself would repeat
    # its bound parameters, which PostgreSQL treats as a different
    # expression from the selected one.
    inner = (
        select(bucket.label("bucket"), HoneypotEvent.event_type.label("event_type"))
        .where(*conditions)
        .subquery()
    )
    rows = await db.execute(
        select(inner.c.bucket, inner.c.event_type, func.count()).group_by(
            inner.c.bucket, inner.c.event_type
        )
    )
    counts: dict[tuple[int, object], int] = {
        (int(index), event_type): int(count) for index, event_type, count in rows.all()
    }
    return _assemble(counts, bucket_timestamps, label_of=label_of, other_label=other_label)


@dataclass
class RecentActivityEvent:
    id: uuid.UUID
    occurred_at: datetime
    label: str
    module: str | None
    src_ip: str | None
    src_port: int | None
    source: str
    # How many identical events directly after this one (same type and
    # source address, moments apart) this row stands for.
    count: int = 1


# Same rule as the Events page (`app.services.event_search.group_repeats`).
_REPEAT_WINDOW_SECONDS = 60


def summarize_recent_events(
    events: list[HoneypotEvent], *, label_of: Callable[[object], str] = logtype_label
) -> list[RecentActivityEvent]:
    rows: list[RecentActivityEvent] = []
    previous: HoneypotEvent | None = None
    for event in events:
        if (
            previous is not None
            and event.event_type == previous.event_type
            and event.src_ip == previous.src_ip
            and event.dst_port == previous.dst_port
            and abs((previous.occurred_at - event.occurred_at).total_seconds())
            <= _REPEAT_WINDOW_SECONDS
        ):
            rows[-1].count += 1
        else:
            rows.append(
                RecentActivityEvent(
                    id=event.id,
                    occurred_at=event.occurred_at,
                    label=label_of(event.event_type),
                    module=module_key(event.event_type),
                    src_ip=event.src_ip,
                    src_port=event.src_port,
                    source=event.source,
                )
            )
        previous = event
    return rows
