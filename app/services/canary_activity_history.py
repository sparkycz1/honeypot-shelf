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

from dataclasses import dataclass, field
from datetime import datetime

from app.db.models.honeypot_event import HoneypotEvent
from app.services.honeypot_status import as_aware_utc
from app.services.monitoring_history import time_range_delta
from app.services.opencanary_logtypes import logtype_label, module_key

# A hard cap on how many raw rows one request will pull into memory before
# bucketing — protects against a busy honeypot (a sustained portscan can
# log thousands of lines an hour) blowing up one page render.
MAX_RAW_EVENTS = 20_000

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
    truncated: bool = False

    @property
    def total(self) -> int:
        return sum(self.total_counts)


def build_activity_history(
    events: list[HoneypotEvent], range_key: str, *, now: datetime
) -> ActivityHistory:
    delta = time_range_delta(range_key)
    start = now - delta
    bucket_width = delta / BUCKET_COUNT

    bucket_timestamps = [start + bucket_width * (i + 0.5) for i in range(BUCKET_COUNT)]
    total_counts = [0] * BUCKET_COUNT
    totals_by_type: dict[str, int] = {}
    per_type_buckets: dict[str, list[int]] = {}

    for event in events:
        # SQLite (this app's test backend) drops tzinfo on round-trip;
        # real Postgres columns never do — normalize before comparing, same
        # gotcha `app.services.honeypot_status.is_online` was written for.
        occurred_at = as_aware_utc(event.occurred_at)
        offset = (occurred_at - start) / bucket_width if bucket_width else 0
        index = min(max(int(offset), 0), BUCKET_COUNT - 1)
        total_counts[index] += 1

        label = logtype_label(event.event_type)
        totals_by_type[label] = totals_by_type.get(label, 0) + 1
        per_type_buckets.setdefault(label, [0] * BUCKET_COUNT)[index] += 1

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
        counts_by_type["Other"] = other_buckets

    return ActivityHistory(
        bucket_timestamps=bucket_timestamps,
        total_counts=total_counts,
        counts_by_type=counts_by_type,
        totals_by_type=totals_by_type,
        sample_count=len(events),
        truncated=len(events) >= MAX_RAW_EVENTS,
    )


@dataclass
class RecentActivityEvent:
    occurred_at: datetime
    label: str
    module: str | None
    src_ip: str | None
    src_port: int | None
    source: str


def summarize_recent_events(events: list[HoneypotEvent]) -> list[RecentActivityEvent]:
    return [
        RecentActivityEvent(
            occurred_at=event.occurred_at,
            label=logtype_label(event.event_type),
            module=module_key(event.event_type),
            src_ip=event.src_ip,
            src_port=event.src_port,
            source=event.source,
        )
        for event in events
    ]
