"""Shared "is this honeypot online" logic. This is about OpenCanary event
flow, not SSH reachability (see `app.db.models.honeypot`'s module
docstring on the two independent signals) — status here is purely derived
from how recently the honeypot last pushed an event."""

from __future__ import annotations

import enum
from datetime import UTC, datetime, timedelta

from app.core.config import get_settings
from app.db.models.honeypot import Honeypot


class HoneypotStatus(enum.StrEnum):
    """Derived, not stored — see `status_of` below. Kept as an enum anyway
    so templates/API responses share one vocabulary rather than each
    computing their own "online" wording."""

    ONLINE = "online"
    OFFLINE = "offline"
    # No event has ever been received for this honeypot — distinct from
    # OFFLINE, which means it was seen before and has since gone quiet.
    NEVER_SEEN = "never_seen"


def offline_cutoff() -> datetime:
    """A honeypot with no event since this instant is offline."""
    return datetime.now(UTC) - timedelta(seconds=get_settings().honeypot_offline_after_seconds)


def as_aware_utc(value: datetime) -> datetime:
    """Every timestamp this app writes is UTC, naive or not — a naive one
    (e.g. read back from SQLite in tests, which drops tzinfo on round-trip;
    real Postgres columns are `DateTime(timezone=True)` and never lose it)
    is treated as already being UTC rather than local time, same reasoning
    `app.audit._normalized_timestamp`/`User.is_locked_out` already apply."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def is_online(last_seen_at: datetime | None, *, cutoff: datetime | None = None) -> bool:
    if last_seen_at is None:
        return False
    return as_aware_utc(last_seen_at) >= (cutoff or offline_cutoff())


def status_of(honeypot: Honeypot, *, cutoff: datetime | None = None) -> HoneypotStatus:
    if honeypot.last_seen_at is None:
        return HoneypotStatus.NEVER_SEEN
    if is_online(honeypot.last_seen_at, cutoff=cutoff):
        return HoneypotStatus.ONLINE
    return HoneypotStatus.OFFLINE
