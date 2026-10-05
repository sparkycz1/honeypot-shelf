"""Acknowledging a problem: "I know about this one."

A honeypot can be acknowledged by a person, with a note and an optional
end time. While the acknowledgement is active, alert and "unavailable"
notifications about that honeypot are withheld and recorded in the
delivery history as muted, naming who acknowledged it — the same shape as
a maintenance window, but started from the problem itself and ended by the
recovery. Same feature as debcontrol's.

It ends when:
- the honeypot is reachable again after being unreachable (the "recovered"
  notification itself is still sent),
- its end time passes, or
- someone clears it.

Stored as four columns on `Honeypot` rather than a table of its own: there
is at most one per honeypot, and its history is the audit log
(`honeypot.acknowledge`, `honeypot.acknowledge.clear`).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Protocol

from app.db.models.notification_log import NotificationKind

# Offered in the UI; the REST API takes any number of hours up to the max.
DURATION_CHOICES: tuple[tuple[str, int | None], ...] = (
    ("until_recovered", None),
    ("1h", 1),
    ("8h", 8),
    ("24h", 24),
    ("3d", 72),
    ("7d", 168),
)
MAX_HOURS = 24 * 31
MAX_NOTE_LENGTH = 500
# How a withheld notification's `NotificationLog.muted_by` starts.
MUTED_BY_PREFIX = "acknowledged by "

# What an acknowledgement keeps from being sent. "Recovered" ends it and
# is always delivered; a test send is never withheld.
_WITHHELD = frozenset(
    {
        NotificationKind.ALERT,
        NotificationKind.UNAVAILABLE,
        NotificationKind.DISK_FULL,
        NotificationKind.SERVICE_FAILED,
        NotificationKind.REBOOT_REQUIRED,
    }
)


class Acknowledgeable(Protocol):
    acknowledged_at: datetime | None
    acknowledged_until: datetime | None
    acknowledged_by: str | None
    acknowledged_note: str | None


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def is_active(target: Acknowledgeable, now: datetime | None = None) -> bool:
    if target.acknowledged_at is None:
        return False
    if target.acknowledged_until is None:
        return True
    return _aware(target.acknowledged_until) > (now or datetime.now(UTC))


def hours_for(choice: str) -> int | None:
    """The form's duration choice as hours (None = until it recovers).
    Raises ValueError for anything not offered."""
    for key, hours in DURATION_CHOICES:
        if key == choice:
            return hours
    raise ValueError("Choose how long the acknowledgement should last.")


def acknowledge(
    target: Acknowledgeable,
    *,
    by: str,
    note: str | None,
    hours: int | None,
    now: datetime | None = None,
) -> None:
    if hours is not None and not 1 <= hours <= MAX_HOURS:
        raise ValueError(f"An acknowledgement can last 1 to {MAX_HOURS} hours.")
    now = now or datetime.now(UTC)
    target.acknowledged_at = now
    target.acknowledged_until = now + timedelta(hours=hours) if hours is not None else None
    target.acknowledged_by = by[:255]
    target.acknowledged_note = (note or "").strip()[:MAX_NOTE_LENGTH] or None


def clear(target: Acknowledgeable) -> None:
    target.acknowledged_at = None
    target.acknowledged_until = None
    target.acknowledged_by = None
    target.acknowledged_note = None


def withholds(kind: NotificationKind) -> bool:
    """Whether an active acknowledgement keeps this kind from being sent."""
    return kind in _WITHHELD


def muted_by(target: Acknowledgeable) -> str:
    return f"{MUTED_BY_PREFIX}{target.acknowledged_by or 'someone'}"


def as_dict(target: Acknowledgeable) -> dict[str, str | None] | None:
    """The active acknowledgement as the REST API returns it, or None."""
    if not is_active(target) or target.acknowledged_at is None:
        return None
    until = target.acknowledged_until
    return {
        "at": _aware(target.acknowledged_at).isoformat(),
        "until": _aware(until).isoformat() if until is not None else None,
        "by": target.acknowledged_by,
        "note": target.acknowledged_note,
    }
