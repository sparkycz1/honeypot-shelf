"""Shared "is this honeypot online" logic — a honeypot has no live agent
HoneyHive polls (see `app.db.models.honeypot`'s module docstring); status
is purely derived from how recently it last pushed an event."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.config import get_settings
from app.db.models.honeypot import Honeypot, HoneypotStatus


def offline_cutoff() -> datetime:
    """A honeypot with no event since this instant is offline."""
    return datetime.now(UTC) - timedelta(seconds=get_settings().honeypot_offline_after_seconds)


def status_of(honeypot: Honeypot, *, cutoff: datetime | None = None) -> HoneypotStatus:
    if honeypot.last_seen_at is None:
        return HoneypotStatus.NEVER_SEEN
    if honeypot.last_seen_at >= (cutoff or offline_cutoff()):
        return HoneypotStatus.ONLINE
    return HoneypotStatus.OFFLINE
