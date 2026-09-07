"""FastAPI dependencies for routes — `app.auth.middleware` already guarantees
every non-public request has a valid session and sets `request.state.user`
before a route ever runs; these just expose that typed, and enforce
read/write + company scoping where a route needs more than "logged in".

There is no `Permission` matrix here (see `app.db.models.user`'s module
docstring) — just three questions a route ever needs answered: is this
user logged in, can they write, and is `company_id` one they're allowed to
touch (always true for a superadmin, otherwise only their own company).
"""

from __future__ import annotations

import uuid

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.api_tokens import get_user_for_api_token
from app.db.models.user import User
from app.db.session import get_db


def get_current_user(request: Request) -> User:
    user: User | None = getattr(request.state, "user", None)
    if user is None:
        # Shouldn't happen on any route reachable via the middleware's
        # allowlist logic — this is a defensive fallback, not the normal
        # "please log in" path (that's a redirect, handled in the middleware).
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")
    return user


def require_write(user: User = Depends(get_current_user)) -> User:
    """Gate for a mutating web route — the user must be a superadmin or
    hold `READ_WRITE` on their own company. Does **not** check *which*
    company is being mutated; a route touching a specific `company_id`
    must additionally call `ensure_company_access(user, company_id,
    write=True)` (see `app.auth.scope`)."""
    if not user.can_write():
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="Your account has read-only access.",
        )
    return user


def require_superadmin(user: User = Depends(get_current_user)) -> User:
    if not user.is_superadmin:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, detail="This page is restricted to superadmins."
        )
    return user


async def get_api_token_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    """Like `get_current_user`, but for routes under `/api/` — those are on
    `app.auth.middleware`'s public-prefix allowlist (no session cookie), so
    they authenticate with a bearer API token instead (see
    `app.auth.api_tokens`). Used by the read-only-by-default REST API
    (`app.web.routes.api_v1`)."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token.")
    user = await get_user_for_api_token(db, auth_header.removeprefix("Bearer ").strip())
    if user is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="Invalid, expired, or revoked API token."
        )
    # `app.auth.middleware` never sets `request.state.user` for `/api/`
    # requests (they're on its public-prefix allowlist, authenticated here
    # instead of by session cookie) — set it ourselves so `app.audit.
    # log_event`'s automatic actor resolution (`request.state.user`) works
    # the same way for an API-token request as it already does for a
    # cookie-session one.
    request.state.user = user
    return user


async def require_api_write(user: User = Depends(get_api_token_user)) -> User:
    if not user.can_write():
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, detail="This API token's account has read-only access."
        )
    return user


async def require_api_superadmin(user: User = Depends(get_api_token_user)) -> User:
    if not user.is_superadmin:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, detail="This API token's account isn't a superadmin."
        )
    return user


def ensure_company_access(user: User, company_id: uuid.UUID, *, write: bool = False) -> None:
    """The one place every route/service touching a specific company (or a
    honeypot/event scoped to one) calls before reading or writing it — see
    `app.auth.scope`'s module docstring for why this is 404, not 403, for
    an out-of-scope company."""
    from app.auth.scope import ensure_company_access as _ensure  # avoid import cycle

    _ensure(user, company_id, write=write)
