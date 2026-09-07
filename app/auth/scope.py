"""Company scoping: which company's data a user may read or write.

Orthogonal to `app.auth.dependencies.require_write` the same way debcontrol's
machine-group scoping was orthogonal to its permission matrix — `require_write`
decides *whether* this user may write at all, this decides *which company*
they may read or write. A superadmin passes for every company; a regular
user only ever passes for their own `company_id`.

Used by every read and write path that's scoped to one company: honeypots
(list/detail/create/edit/delete), events (list/filter), the Dashboard's
per-company counts, the REST API, and the event-ingest endpoint's honeypot
lookup.

**Out of scope reads as 404, never 403** — same reasoning debcontrol's
`app.services.access_scope` documents: a 403 would confirm the company/
honeypot exists at all, which is itself information a user outside that
company shouldn't get for free.
"""

from __future__ import annotations

import uuid

from fastapi import HTTPException, status

from app.db.models.user import User


class CompanyAccessDenied(Exception):
    """Raised by `ensure_company_access` — callers that want a 404 instead
    of this bubbling up as a 500 should catch it (most FastAPI routes just
    let `ensure_company_access` below do that itself)."""


def has_company_access(user: User, company_id: uuid.UUID, *, write: bool = False) -> bool:
    if user.is_superadmin:
        return True
    if user.company_id != company_id:
        return False
    return user.can_write() if write else True


def ensure_company_access(user: User, company_id: uuid.UUID, *, write: bool = False) -> None:
    """Raises a 404 (never 403 — see module docstring) if `user` may not
    read (or, with `write=True`, write) `company_id`'s data."""
    if not has_company_access(user, company_id, write=write):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found.")


def visible_company_id(user: User) -> uuid.UUID | None:
    """The single company a non-superadmin user may ever see — `None` for a
    superadmin, meaning "every company" (callers branch on that rather than
    trying to express "no filter" as a company id). There is deliberately
    no multi-company, partially-scoped user in this model (unlike
    debcontrol's opt-in `UserMachineGroupAccess`, which could grant several
    groups) — every non-superadmin belongs to exactly one company."""
    return None if user.is_superadmin else user.company_id
