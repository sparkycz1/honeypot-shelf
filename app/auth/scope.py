"""Company scoping: which company's data a user may read or write.

The single implementation of per-user visibility scoping — the Honeypot
Shelf equivalent of debcontrol's `app.services.access_scope`. Both `User`
and `Honeypot` relate to `Company` many-to-many now (`CompanyMembership`
for users, each with its own `AccessLevel`; a plain link table for
honeypots) — see `app.db.models.company`'s module docstring — so "which
companies can this user see" is a *set*, not a single id, and a honeypot
is visible if it shares **any** company with the user (a superadmin sees
everything regardless, an honeypot with zero companies is visible to a
superadmin only).

Orthogonal to `app.auth.dependencies.require_write` the same way
debcontrol's machine-group scoping was orthogonal to its permission
matrix — `require_write` decides *whether* this user may write at all
(on at least one company), this module decides *which* company/honeypot
they may read or write.

Two shapes are offered, mirroring debcontrol's `access_scope`, because
call sites come in two shapes:

- `honeypots_visible_to` / `companies_visible_to` return a `Select`,
  already scope-filtered and still fully composable (`.where(...)`,
  `.order_by(...)`, `.options(...)`, pagination) — for listing queries.
- `can_see_honeypot` / `ensure_company_access` / `filter_honeypots` answer
  the same question about rows already loaded, or about a bare id — for
  detail routes (404, never 403 — see below) and bulk endpoints, which
  must never trust a client-submitted list of honeypot ids.

**Out of scope reads as 404, never 403** — a 403 would confirm the
company/honeypot exists at all, which is itself information a user
outside that company shouldn't get for free.

What is deliberately **not** scoped: the audit log (superadmin-only, see
`app/web/routes/audit.py`). Background jobs aren't scoped either, and
can't be — a Celery task has no "current user"; scope on a `ScheduledTask`
is enforced when it's *created or edited* (`owner_company_id`), never at
execution time.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence

from fastapi import HTTPException, status
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.user import User


def has_company_access(user: User, company_id: uuid.UUID, *, write: bool = False) -> bool:
    if user.is_superadmin:
        return True
    if write:
        return user.can_write_company(company_id)
    return company_id in user.company_ids()


def ensure_company_access(user: User, company_id: uuid.UUID, *, write: bool = False) -> None:
    """Raises a 404 (never 403 — see module docstring) if `user` may not
    read (or, with `write=True`, write) `company_id`'s data."""
    if not has_company_access(user, company_id, write=write):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found.")


def visible_company_ids(user: User) -> set[uuid.UUID] | None:
    """Every company a non-superadmin user may see — `None` for a
    superadmin, meaning "every company" (callers branch on that rather
    than trying to express "no filter" as a finite set). An empty set for
    a non-superadmin with zero memberships is a real, valid result — it
    means "sees nothing," not "unscoped"."""
    return None if user.is_superadmin else user.company_ids()


def honeypots_visible_to(user: User) -> Select[tuple[Honeypot]]:
    """A `Select` for `Honeypot`, already scope-filtered — compose with
    `.where()` / `.order_by()` / `.options()` exactly as the call site
    needs. A honeypot is visible if it shares **any** company with the
    user; superadmin sees everything, including a honeypot attached to no
    company at all."""
    query = select(Honeypot)
    company_ids = visible_company_ids(user)
    if company_ids is not None:
        query = query.where(Honeypot.companies.any(Company.id.in_(company_ids)))
    return query


def companies_visible_to(user: User) -> Select[tuple[Company]]:
    """The `Company` equivalent of `honeypots_visible_to`."""
    query = select(Company)
    company_ids = visible_company_ids(user)
    if company_ids is not None:
        query = query.where(Company.id.in_(company_ids))
    return query


async def count_visible_honeypots(db: AsyncSession, user: User) -> int:
    query = honeypots_visible_to(user)
    return (
        await db.execute(query.with_only_columns(func.count(), maintain_column_froms=True))
    ).scalar_one()


def can_see_honeypot(user: User, honeypot: Honeypot) -> bool:
    if user.is_superadmin:
        return True
    return bool(user.company_ids() & {c.id for c in honeypot.companies})


def can_write_honeypot(user: User, honeypot: Honeypot) -> bool:
    """`True` if the user can write this honeypot through **any** of the
    companies it's attached to — a honeypot shared across companies is
    manageable by anyone with `READ_WRITE` on at least one of them."""
    if user.is_superadmin:
        return True
    return any(user.can_write_company(c.id) for c in honeypot.companies)


def filter_honeypots(user: User, honeypots: Iterable[Honeypot]) -> list[Honeypot]:
    """Drop the honeypots `user` may not see from an already-loaded list —
    for any endpoint acting on an ad-hoc, client-submitted selection of
    honeypot ids: out-of-scope ids are dropped silently rather than
    rejected loudly, for the same 404-not-403 reasoning as detail routes."""
    if user.is_superadmin:
        return list(honeypots)
    my_companies = user.company_ids()
    return [h for h in honeypots if my_companies & {c.id for c in h.companies}]


async def visible_honeypots_by_ids(
    db: AsyncSession, user: User, honeypot_ids: Sequence[uuid.UUID]
) -> list[Honeypot]:
    """Load exactly the honeypots among `honeypot_ids` that `user` may see."""
    if not honeypot_ids:
        return []
    query = honeypots_visible_to(user).where(Honeypot.id.in_(honeypot_ids))
    result = await db.execute(query)
    return list(result.scalars().all())
