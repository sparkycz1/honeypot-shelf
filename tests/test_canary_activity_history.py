"""`app.services.canary_activity_history` — bucketing `HoneypotEvent` rows
into the Activity tab's trend chart."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.db.models.honeypot_event import HoneypotEvent
from app.services.canary_activity_history import (
    BUCKET_COUNT,
    build_activity_history,
    summarize_recent_events,
)

_HONEYPOT_ID = uuid.uuid4()
_COMPANY_ID = uuid.uuid4()


def _event(event_type: str, occurred_at: datetime, **kwargs: object) -> HoneypotEvent:
    return HoneypotEvent(
        honeypot_id=_HONEYPOT_ID,
event_type=event_type,
        occurred_at=occurred_at,
        raw={},
        source="ssh_poll",
        **kwargs,
    )


def test_build_activity_history_buckets_events_by_time():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    events = [
        _event("4002", now - timedelta(minutes=5)),
        _event("4002", now - timedelta(minutes=10)),
        _event("3000", now - timedelta(hours=20)),
    ]

    history = build_activity_history(events, "24h", now=now)

    assert len(history.bucket_timestamps) == BUCKET_COUNT
    assert len(history.total_counts) == BUCKET_COUNT
    assert history.total == 3
    assert history.sample_count == 3
    assert history.totals_by_type["SSH login attempt"] == 2
    assert history.totals_by_type["HTTP GET request"] == 1
    # The two recent SSH events land in the same (last) bucket.
    assert history.total_counts[-1] >= 2


def test_build_activity_history_empty_when_no_events():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    history = build_activity_history([], "1h", now=now)
    assert history.total == 0
    assert history.counts_by_type == {}
    assert not history.truncated


def test_build_activity_history_folds_extra_types_into_other():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    # 9 distinct types, one event each — more than `_TOP_TYPES_LIMIT` (8).
    events = [_event(str(1000 + n), now) for n in range(9)]

    history = build_activity_history(events, "1h", now=now)

    assert "Other" in history.counts_by_type
    assert len(history.counts_by_type) == 9  # 8 top + "Other" folding the rest


def test_summarize_recent_events_uses_human_labels_and_module_keys():
    events = [_event("4002", datetime(2026, 1, 1, tzinfo=UTC), src_ip="203.0.113.5")]

    summarized = summarize_recent_events(events)

    assert len(summarized) == 1
    assert summarized[0].label == "SSH login attempt"
    assert summarized[0].module == "ssh"
    assert summarized[0].src_ip == "203.0.113.5"
