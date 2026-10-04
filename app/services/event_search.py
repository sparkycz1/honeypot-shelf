"""Filtering OpenCanary events (`HoneypotEvent`) — one place for the web
Events page (`/events`) and the REST API (`/api/v1/events`), so both
accept the same filters and both stay inside the account's companies.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from app.auth.scope import visible_company_ids
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.user import User

PAGE_SIZE = 50


@dataclass(frozen=True)
class EventFilters:
    """What a list of events is narrowed by. Empty strings and `None` mean
    "any"; an unreadable value is ignored rather than refused, like every
    other filter in this app."""

    honeypot_id: uuid.UUID | None = None
    event_type: str = ""
    source: str = ""
    # Substring of the source address: "203.0.113." finds a whole /24.
    src_ip: str = ""
    # ISO 3166-1 alpha-2, as stored in `HoneypotEvent.src_country_code`.
    country: str = ""
    since: datetime | None = None
    until: datetime | None = None

    @property
    def any(self) -> bool:
        return bool(
            self.honeypot_id
            or self.event_type
            or self.source
            or self.src_ip
            or self.country
            or self.since
            or self.until
        )


def parse_time(value: str) -> datetime | None:
    """An ISO-8601 timestamp (UTC when it has no offset), or None for an
    empty or unreadable value."""
    if not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value.strip()) if value.strip() else None
    except ValueError:
        return None


def _like(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def apply_filters[S: Select[HoneypotEvent]](query: S, user: User, filters: EventFilters) -> S:
    """`query` limited to the events `user` may see and to `filters`."""
    company_ids = visible_company_ids(user)
    if company_ids is not None:
        query = query.where(
            HoneypotEvent.honeypot.has(Honeypot.companies.any(Company.id.in_(company_ids)))
        )
    if filters.honeypot_id is not None:
        query = query.where(HoneypotEvent.honeypot_id == filters.honeypot_id)
    if filters.event_type.strip():
        query = query.where(HoneypotEvent.event_type == filters.event_type.strip())
    if filters.source.strip():
        query = query.where(HoneypotEvent.source == filters.source.strip())
    if filters.src_ip.strip():
        query = query.where(
            HoneypotEvent.src_ip.ilike(_like(filters.src_ip.strip()), escape="\\")
        )
    if filters.country.strip():
        query = query.where(HoneypotEvent.src_country_code == filters.country.strip().upper())
    if filters.since is not None:
        query = query.where(HoneypotEvent.occurred_at >= filters.since)
    if filters.until is not None:
        query = query.where(HoneypotEvent.occurred_at <= filters.until)
    return query


async def page_of_events(
    db: AsyncSession, user: User, filters: EventFilters, page: int
) -> tuple[list[HoneypotEvent], bool]:
    """One page, newest first, and whether an older page exists."""
    offset = (max(page, 1) - 1) * PAGE_SIZE
    result = await db.execute(
        apply_filters(select(HoneypotEvent), user, filters)
        .order_by(HoneypotEvent.occurred_at.desc())
        .offset(offset)
        .limit(PAGE_SIZE + 1)
    )
    events = list(result.scalars().all())
    return events[:PAGE_SIZE], len(events) > PAGE_SIZE


async def event_types_seen(db: AsyncSession, user: User) -> list[str]:
    """Every event type among the events `user` may see — the choices of
    the Events page's type filter."""
    visible = apply_filters(select(HoneypotEvent), user, EventFilters())
    result = await db.execute(
        visible.with_only_columns(HoneypotEvent.event_type, maintain_column_froms=True)
        .distinct()
        .order_by(HoneypotEvent.event_type)
    )
    return [value for value in result.scalars().all() if value]


async def get_event(db: AsyncSession, user: User, event_id: uuid.UUID) -> HoneypotEvent | None:
    """One event, or None when it does not exist or belongs to a company
    the account may not see (the caller answers 404 either way)."""
    result = await db.execute(
        apply_filters(select(HoneypotEvent), user, EventFilters()).where(
            HoneypotEvent.id == event_id
        )
    )
    return result.scalar_one_or_none()


# Longest value shown in the "what was reported" table; the full payload is
# on the page as JSON anyway.
_MAX_VALUE_LENGTH = 2000


def reported_fields(event: HoneypotEvent) -> list[tuple[str, str]]:
    """What OpenCanary recorded about the attempt — the `logdata` part of
    the payload (the user name and password tried, the client version, the
    requested path...) as `(name, value)` pairs in a stable order. Values
    come from whoever connected to the honeypot: text only, never trusted."""
    logdata = event.raw.get("logdata") if isinstance(event.raw, dict) else None
    if not isinstance(logdata, dict):
        return []
    rows: list[tuple[str, str]] = []
    for key in sorted(logdata, key=str):
        value = logdata[key]
        if value is None or value == "":
            continue
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        rows.append((str(key)[:100], text[:_MAX_VALUE_LENGTH]))
    return rows


# How many of an address's newest events are read for the "what it tried"
# tables — enough to show a pattern, bounded for an address with millions.
SOURCE_SAMPLE = 1000
_TOP = 15


@dataclass(frozen=True)
class SourceSummary:
    """Everything one source address did, across the honeypots the account
    may see."""

    src_ip: str
    total: int
    first_seen: datetime | None
    last_seen: datetime | None
    country_code: str | None
    country_name: str | None
    city_name: str | None
    # (honeypot id, honeypot name, events), busiest first.
    honeypots: list[tuple[uuid.UUID, str, int]]
    # (event type, events), most frequent first.
    event_types: list[tuple[str, int]]
    # (user name, password, times tried) among the newest SOURCE_SAMPLE
    # events, most tried first.
    credentials: list[tuple[str, str, int]]
    recent: list[HoneypotEvent]
    sampled: bool


def _text(value: object) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


async def source_summary(db: AsyncSession, user: User, src_ip: str) -> SourceSummary | None:
    """None when the account can see no event from `src_ip` (exact match)."""
    src_ip = src_ip.strip()
    visible = apply_filters(select(HoneypotEvent), user, EventFilters()).where(
        HoneypotEvent.src_ip == src_ip
    )
    total, first_seen, last_seen = (
        await db.execute(
            visible.with_only_columns(
                func.count(),
                func.min(HoneypotEvent.occurred_at),
                func.max(HoneypotEvent.occurred_at),
                maintain_column_froms=True,
            )
        )
    ).one()
    if not total:
        return None

    by_type = (
        await db.execute(
            visible.with_only_columns(
                HoneypotEvent.event_type, func.count(), maintain_column_froms=True
            )
            .group_by(HoneypotEvent.event_type)
            .order_by(func.count().desc())
        )
    ).all()
    by_honeypot = (
        await db.execute(
            visible.with_only_columns(
                HoneypotEvent.honeypot_id, func.count(), maintain_column_froms=True
            )
            .group_by(HoneypotEvent.honeypot_id)
            .order_by(func.count().desc())
        )
    ).all()
    names = dict(
        (
            await db.execute(
                select(Honeypot.id, Honeypot.name).where(
                    Honeypot.id.in_([honeypot_id for honeypot_id, _count in by_honeypot])
                )
            )
        ).all()
    )

    sample = list(
        (
            await db.execute(
                visible.order_by(HoneypotEvent.occurred_at.desc()).limit(SOURCE_SAMPLE)
            )
        )
        .scalars()
        .all()
    )
    tried: dict[tuple[str, str], int] = {}
    for event in sample:
        logdata = event.raw.get("logdata") if isinstance(event.raw, dict) else None
        if not isinstance(logdata, dict):
            continue
        username, password = logdata.get("USERNAME"), logdata.get("PASSWORD")
        if username is None and password is None:
            continue
        key = (_text(username or "")[:200], _text(password or "")[:200])
        tried[key] = tried.get(key, 0) + 1
    newest = sample[0]
    return SourceSummary(
        src_ip=src_ip,
        total=total,
        first_seen=first_seen,
        last_seen=last_seen,
        country_code=newest.src_country_code,
        country_name=newest.src_country_name,
        city_name=newest.src_city_name,
        honeypots=[
            (honeypot_id, names.get(honeypot_id, "?"), count) for honeypot_id, count in by_honeypot
        ],
        event_types=[(event_type, count) for event_type, count in by_type],
        credentials=[
            (username, password, count)
            for (username, password), count in sorted(
                tried.items(), key=lambda item: (-item[1], item[0])
            )[:_TOP]
        ],
        recent=sample[:_TOP],
        sampled=total > len(sample),
    )
