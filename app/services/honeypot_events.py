"""Turning one OpenCanary JSON payload into a `HoneypotEvent` row — the one
way a row gets created now: Honeypot Shelf itself SSH-polling OpenCanary's own
log (`app.ssh.canary_activity`, `app.tasks.jobs.poll_honeypot_canary_log`).
Hands OpenCanary's payload shape to `build_event` close to verbatim — see
`app.db.models.honeypot_event`'s module docstring for that shape.

There used to be a second way — a forwarder on the honeypot pushing to
`POST /api/ingest/{id}/events` — removed per explicit instruction: the SSH
poll already covers every honeypot with no forwarder to set up, so the
push path was pure redundancy. `HoneypotEvent.source` still holds
`"push"` on rows ingested that way before the removal; nothing new is
ever written with it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent

# `HoneypotEvent.event_type` / `src_ip` column widths, and the port range.
_EVENT_TYPE_MAX_LENGTH = 100
_SRC_IP_MAX_LENGTH = 64
_MAX_PORT = 65535


class EventSource:
    """`HoneypotEvent.source` values — a plain string, not an enum,
    matching `event_type`'s own "free text" convention.

    `PUSH` is historical only (see the module docstring) — kept so
    existing rows from before the push endpoint was removed still parse
    and display correctly; `build_event` below never produces it."""

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


def _coerce_port(value: Any) -> int | None:
    """OpenCanary's JSON usually has `src_port`/`dst_port` as a real
    number, but confirmed live that at least one module instead emits a
    numeric *string* (`"42206"`) for it — harmless against the SQLite
    test harness (which coerces silently), but asyncpg refuses to bind a
    `str` into an `Integer` column at all and fails the whole insert,
    taking down every other event batched in the same poll with it (see
    `app.db.models.honeypot_event.HoneypotEvent.src_port`/`dst_port`).
    Best-effort like `parse_occurred_at` above: an unparseable value just
    means "don't know" (`None`), never a reason to drop the rest of an
    otherwise-good event."""
    if isinstance(value, bool):  # bool is an int subclass - not a real port
        return None
    if isinstance(value, str):
        try:
            value = int(value.strip())
        except ValueError:
            return None
    # Out of range fails the insert just the same (Integer column).
    if isinstance(value, int) and 0 <= value <= _MAX_PORT:
        return value
    return None


def _bounded_str(value: Any, max_length: int) -> str | None:
    """A string field of the payload only if it's really a string that fits
    its column — a longer or non-string `src_host` isn't an address anyway,
    and binding it would fail the whole batch's insert."""
    if isinstance(value, str) and len(value) <= max_length:
        return value
    return None


def build_event(honeypot: Honeypot, payload: dict[str, Any]) -> HoneypotEvent:
    """One `HoneypotEvent` from one OpenCanary payload, always sourced from
    the SSH log poll (see the module docstring) — not yet added to a
    session or committed, that's the caller's job (it may want to batch
    several, or set `honeypot.last_seen_at` alongside)."""
    logdata = payload.get("logdata")
    event_type = payload.get("logtype") or (
        logdata.get("type") if isinstance(logdata, dict) else None
    )
    return HoneypotEvent(
        honeypot_id=honeypot.id,
        # Cut to the column's width: a forged log line can carry anything.
        event_type=str(event_type or "UNKNOWN")[:_EVENT_TYPE_MAX_LENGTH],
        occurred_at=parse_occurred_at(payload),
        src_ip=_bounded_str(payload.get("src_host"), _SRC_IP_MAX_LENGTH),
        src_port=_coerce_port(payload.get("src_port")),
        dst_port=_coerce_port(payload.get("dst_port")),
        raw=payload,
        source=EventSource.SSH_POLL,
    )
