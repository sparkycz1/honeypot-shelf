"""Turning one OpenCanary JSON payload into a `HoneypotEvent` row — shared
between the two ways a row gets created: a forwarder pushing to `POST
/api/ingest/{id}/events` (`app.web.routes.ingest`) and HoneyHive itself
SSH-polling OpenCanary's own log (`app.ssh.canary_activity`,
`app.tasks.jobs.poll_honeypot_canary_log`). Both hand OpenCanary's payload
shape to `build_event` close to verbatim — see
`app.db.models.honeypot_event`'s module docstring for that shape.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent


class EventSource:
    """`HoneypotEvent.source` values — a plain string, not an enum, matching
    `event_type`'s own "free text" convention."""

    PUSH = "push"
    SSH_POLL = "ssh_poll"


def parse_occurred_at(payload: dict[str, Any]) -> datetime:
    """OpenCanary's `local_time` is a naive, locally-formatted timestamp
    (the Pi's own clock, usually NTP-synced but not guaranteed) — parsed
    best-effort; falls back to "now" (still correct to within a poll
    interval or network latency) rather than rejecting an otherwise-valid
    event over a malformed/missing timestamp."""
    value = payload.get("local_time") or payload.get("utc_time")
    if isinstance(value, str):
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=UTC)
            except ValueError:
                continue
    return datetime.now(UTC)


def build_event(honeypot: Honeypot, payload: dict[str, Any], *, source: str) -> HoneypotEvent:
    """One `HoneypotEvent` from one OpenCanary payload — not yet added to a
    session or committed, that's the caller's job (it may want to batch
    several, or set `honeypot.last_seen_at` alongside)."""
    return HoneypotEvent(
        honeypot_id=honeypot.id,
        company_id=honeypot.company_id,
        event_type=str(
            payload.get("logtype") or payload.get("logdata", {}).get("type") or "UNKNOWN"
        ),
        occurred_at=parse_occurred_at(payload),
        src_ip=payload.get("src_host"),
        src_port=payload.get("src_port"),
        dst_port=payload.get("dst_port"),
        raw=payload,
        source=source,
    )
