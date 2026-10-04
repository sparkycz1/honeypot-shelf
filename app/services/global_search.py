"""One search box for the whole app (the header's search field, `/search`,
`GET /api/v1/search`). Same feature and layout as debcontrol's.

Looks for the query in the names (and a few other identifying fields) of
honeypots, companies, scheduled tasks, the account's own notification
rules and users, and returns links to them, grouped by kind. Each kind is
searched only for an account that could open it anyway, and honeypots,
companies and scheduled tasks are scope-filtered exactly like their own
lists (`app.auth.scope`, `app.scheduling.targets`), so the search never
shows something the account could not otherwise see.

A plain `ILIKE '%q%'` per kind, a handful of rows each: fine at the fleet
sizes this app targets, and nothing to keep in sync with the data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import quote

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth.scope import companies_visible_to, honeypots_visible_to
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.notification_rule import NotificationRule
from app.db.models.scheduled_task import ScheduledTask
from app.db.models.user import User
from app.scheduling.targets import task_within_scope
from app.web.honeypot_search import honeypot_search_clause

MIN_QUERY_LENGTH = 2
MAX_QUERY_LENGTH = 100
PER_KIND_LIMIT = 8


@dataclass(frozen=True)
class SearchHit:
    label: str
    detail: str
    href: str


@dataclass
class SearchGroup:
    # "honeypots", "companies", ... — also the i18n key suffix (`search.kind.*`).
    kind: str
    hits: list[SearchHit] = field(default_factory=list)
    # More matched than are shown; `more_href` is the kind's own filtered
    # list when it has one.
    has_more: bool = False
    more_href: str | None = None


def normalize(query: str) -> str:
    return " ".join(query.split())[:MAX_QUERY_LENGTH]


def _like(query: str) -> str:
    escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _cut(rows: list[SearchHit]) -> tuple[list[SearchHit], bool]:
    return rows[:PER_KIND_LIMIT], len(rows) > PER_KIND_LIMIT


async def search(db: AsyncSession, user: User, query: str) -> list[SearchGroup]:
    """Matches for `query`, one group per kind the account may see, in the
    order of the main navigation. Empty for a query shorter than
    `MIN_QUERY_LENGTH`; groups with no match are left out."""
    query = normalize(query)
    if len(query) < MIN_QUERY_LENGTH:
        return []
    like = _like(query)
    limit = PER_KIND_LIMIT + 1
    groups: list[SearchGroup] = []

    def add(kind: str, hits: list[SearchHit], more_href: str | None = None) -> None:
        shown, has_more = _cut(hits)
        if shown:
            groups.append(SearchGroup(kind, shown, has_more, more_href if has_more else None))

    honeypots = (
        await db.execute(
            honeypots_visible_to(user)
            .where(honeypot_search_clause(query))
            .order_by(Honeypot.name)
            .limit(limit)
        )
    ).scalars()
    add(
        "honeypots",
        [SearchHit(h.name, h.ip_address or "", f"/honeypots/{h.id}") for h in honeypots],
        f"/honeypots?q={quote(query)}",
    )

    companies = (
        await db.execute(
            companies_visible_to(user)
            .where(Company.name.ilike(like, escape="\\"))
            .order_by(Company.name)
            .limit(limit)
        )
    ).scalars()
    add("companies", [SearchHit(c.name, c.notes or "", f"/companies/{c.id}") for c in companies])

    if user.can_write():
        # Scope is decided per task in Python, like the Scheduling page
        # itself — there are few of these.
        tasks = (
            await db.execute(
                select(ScheduledTask)
                .options(
                    selectinload(ScheduledTask.target_honeypot),
                    selectinload(ScheduledTask.owner_company),
                )
                .where(ScheduledTask.name.ilike(like, escape="\\"))
                .order_by(ScheduledTask.name)
            )
        ).scalars()
        add(
            "scheduled_tasks",
            [
                SearchHit(t.name, t.cron_expression, f"/scheduling/{t.id}/edit")
                for t in tasks
                if task_within_scope(user, t)
            ],
        )

    # Notification rules are personal: only the account's own.
    rules = (
        await db.execute(
            select(NotificationRule)
            .where(
                NotificationRule.user_id == user.id,
                NotificationRule.name.ilike(like, escape="\\"),
            )
            .order_by(NotificationRule.name)
            .limit(limit)
        )
    ).scalars()
    add(
        "notification_rules",
        [SearchHit(r.name, "", f"/account/notifications/{r.id}/edit") for r in rules],
    )

    if user.sees_every_company:
        users = (
            await db.execute(
                select(User)
                .where(
                    or_(
                        User.username.ilike(like, escape="\\"),
                        User.display_name.ilike(like, escape="\\"),
                        User.email.ilike(like, escape="\\"),
                    )
                )
                .order_by(User.username)
                .limit(limit)
            )
        ).scalars()
        add(
            "users",
            [
                SearchHit(u.username, u.display_name or u.email or "", f"/users/{u.id}/edit")
                for u in users
            ],
        )

    return groups
