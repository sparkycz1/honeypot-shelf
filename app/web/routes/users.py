"""User accounts — CRUD, password resets, and forcing a re-login.
Superadmin-only end to end (checked at the router level).

Every route here also protects against locking everyone out: you can't
deactivate, delete, or demote your own account, and the last active
superadmin can't be deactivated, deleted, or demoted away from it either
(see `app.auth.login.count_active_superadmins`).

Creating/editing a user here means picking exactly one of two shapes:
superadmin (no company memberships at all), or one row per company this
user should have access to, each with its own READ/READ_WRITE level — see
`app.db.models.user`/`app.db.models.company_membership`'s module
docstrings. The New/Edit forms render one company-scoped `<select>` per
existing `Company` (value: "", "read", or "read_write"), submitted as
`membership__<company_id>` form fields — `_parse_memberships` below reads
those directly off the raw form body rather than declaring them as typed
FastAPI `Form(...)` parameters, since the number of companies (and so the
number of fields) isn't known ahead of time.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.datastructures import FormData
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_superadmin
from app.auth.login import count_active_superadmins
from app.auth.security import hash_password
from app.auth.sessions import revoke_all_sessions_for_user
from app.core.csrf import verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.company import Company
from app.db.models.company_membership import CompanyMembership
from app.db.models.user import AccessLevel, AuthProvider, User
from app.db.session import get_db
from app.schemas.user import MIN_PASSWORD_LENGTH, MembershipInput, UserCreate, UserUpdate
from app.web.templating import templates

router = APIRouter(prefix="/users", dependencies=[Depends(require_superadmin)])

_MEMBERSHIP_FIELD_PREFIX = "membership__"


async def _get_user_or_404(user_id: uuid.UUID, db: AsyncSession) -> User:
    result = await db.execute(
        select(User).options(selectinload(User.memberships)).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return user


async def _duplicate_username_error(
    db: AsyncSession, *, exclude_user_id: uuid.UUID, username: str
) -> str | None:
    """Proactively look for a row this write would collide with, instead of
    relying solely on catching `IntegrityError` from the commit.

    This matters specifically for *updates*, not creates: `User.updated_at`
    has `onupdate=func.now()`, so SQLAlchemy emits an implicit
    `UPDATE ... RETURNING updated_at`. Confirmed against both dialects:
    asyncpg (what production actually runs) handles a UNIQUE-violating
    RETURNING UPDATE the same way as any other failed statement, surfacing
    a normal `IntegrityError`. But under the test suite's aiosqlite backend
    (`tests/conftest.py`'s `db_session_factory`), the same failure corrupts
    aiosqlite's greenlet/asyncio bridging and surfaces as
    `sqlalchemy.exc.MissingGreenlet` instead — a driver-level quirk, not a
    real production behavior. This check sidesteps it so the common
    "edited to someone else's username" case behaves identically on both
    backends; the `IntegrityError` catch below the commit stays in place as
    a defense-in-depth backstop for a genuine update race. Ported from the
    identical fix in debcontrol.
    """
    result = await db.execute(
        select(User).where(User.id != exclude_user_id, User.username == username)
    )
    if result.scalars().first() is not None:
        return f'A user named "{username}" already exists.'
    return None


async def _get_companies(db: AsyncSession) -> list[Company]:
    result = await db.execute(select(Company).order_by(Company.name))
    return list(result.scalars().all())


async def _would_remove_last_superadmin(db: AsyncSession, target: User) -> bool:
    if not target.is_superadmin:
        return False
    remaining = await count_active_superadmins(db, excluding_user_id=target.id)
    return remaining == 0


def _parse_memberships(form: FormData) -> list[MembershipInput]:
    """Reads every `membership__<company_id>` field with a non-blank value
    off the raw form body — see the module docstring for why this isn't a
    typed `Form(...)` parameter."""
    memberships = []
    for key, value in form.multi_items():
        if not key.startswith(_MEMBERSHIP_FIELD_PREFIX) or not value:
            continue
        company_id = uuid.UUID(key.removeprefix(_MEMBERSHIP_FIELD_PREFIX))
        memberships.append(
            MembershipInput(company_id=company_id, access_level=AccessLevel(str(value)))
        )
    return memberships


def _membership_map(user: User) -> dict[uuid.UUID, AccessLevel]:
    """For pre-filling the edit form's per-company `<select>`s."""
    return {m.company_id: m.access_level for m in user.memberships}


async def _apply_memberships(
    db: AsyncSession, user: User, memberships: list[MembershipInput]
) -> None:
    """Replaces every one of `user`'s memberships with exactly the given
    set — simplest correct approach for a form re-submitting the whole
    fieldset each time, and cheap (a handful of rows at most).

    Flushes the deletes before adding the replacements: re-submitting the
    *same* (company_id, access_level) unchanged — the common case, editing
    a user for an unrelated field — would otherwise insert the new row
    before the old one's DELETE actually reaches the database, tripping
    `uq_company_membership_user_company` with a real
    `sqlite3.IntegrityError`/`psycopg` unique-violation instead of a no-op.
    SQLAlchemy's unit of work does order deletes before inserts within one
    flush in general, but only for objects it already knows about in this
    same flush — replacing the collection wholesale, both halves land in
    the *same* flush, so the ordering isn't guaranteed without this."""
    for existing in list(user.memberships):
        await db.delete(existing)
    await db.flush()
    user.memberships = [
        CompanyMembership(company_id=m.company_id, access_level=m.access_level)
        for m in memberships
    ]


def _scope_label(user: User, memberships: list[MembershipInput], companies: list[Company]) -> str:
    if user.is_superadmin:
        return "superadmin"
    names = {c.id: c.name for c in companies}
    return ", ".join(
        f"{names.get(m.company_id, m.company_id)}/{m.access_level.value}" for m in memberships
    )


@router.get("")
async def list_users(
    request: Request, db: AsyncSession = Depends(get_db), company_id: uuid.UUID | None = None
) -> Response:
    """`?company_id=` narrows the list to one company — used by that
    company's own page ("Users in this company" links here to see
    everyone, not just the ones shown inline there) as well as directly.
    Superadmin-only end to end (router-level), so no scoping check beyond
    the filter itself is needed."""
    query = select(User).options(selectinload(User.memberships)).order_by(User.username)
    if company_id is not None:
        query = query.where(User.memberships.any(CompanyMembership.company_id == company_id))
    result = await db.execute(query)
    users = result.scalars().all()
    filtered_company = await db.get(Company, company_id) if company_id is not None else None
    return templates.TemplateResponse(
        request,
        "users/list.html",
        {
            "users": users,
            "csrf_token": request.state.csrf_token,
            "filtered_company": filtered_company,
            "companies": await _get_companies(db),
            "access_levels": list(AccessLevel),
            "bulk_error": request.query_params.get("bulk_error"),
            "bulk_deleted": request.query_params.get("bulk_deleted"),
            "bulk_assigned": request.query_params.get("bulk_assigned"),
            "bulk_skipped": request.query_params.get("bulk_skipped"),
        },
    )


@router.get("/new")
async def new_user_form(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    preselect_company_id = request.query_params.get("company_id", "")
    return templates.TemplateResponse(
        request,
        "users/new.html",
        {
            "auth_providers": list(AuthProvider),
            "access_levels": list(AccessLevel),
            "companies": await _get_companies(db),
            "errors": [],
            # Pre-selects one company's `READ` row when linked from that
            # company's own page ("Add existing user") — purely a UI
            # convenience, still just regular fields the operator can change.
            "form": {"username": "", "display_name": ""},
            "membership_levels": (
                {uuid.UUID(preselect_company_id): AccessLevel.READ}
                if preselect_company_id
                else {}
            ),
            "csrf_token": request.state.csrf_token,
        },
    )


@router.post("", dependencies=[Depends(verify_csrf)])
async def create_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
    username: str = Form(...),
    display_name: str = Form(""),
    email: str = Form(""),
    auth_provider: AuthProvider = Form(...),
    password: str = Form(""),
    is_superadmin: str = Form(""),
    api_access_enabled: str = Form(""),
) -> Response:
    form = await request.form()
    try:
        memberships = _parse_memberships(form)
    except ValueError:
        # A malformed membership field (not something the rendered form can
        # actually produce) — fall through to the model's own "needs at
        # least one membership" validation rather than a raw 500.
        memberships = []

    async def _rerender(errors: list[str], status_code: int) -> Response:
        await log_event(
            db,
            request=request,
            action="user.create",
            summary=f'Rejected new user "{username}": {"; ".join(errors)}',
            outcome=AuditOutcome.FAILURE,
        )
        return templates.TemplateResponse(
            request,
            "users/new.html",
            {
                "auth_providers": list(AuthProvider),
                "access_levels": list(AccessLevel),
                "companies": await _get_companies(db),
                "errors": errors,
                "form": {
                    "username": username,
                    "display_name": display_name,
                    "email": email,
                    "auth_provider": auth_provider,
                },
                "membership_levels": {m.company_id: m.access_level for m in memberships},
                "csrf_token": request.state.csrf_token,
            },
            status_code=status_code,
        )

    try:
        payload = UserCreate(
            username=username,
            display_name=display_name or None,
            email=email or None,
            auth_provider=auth_provider,
            password=password or None,
            is_superadmin=bool(is_superadmin),
            memberships=memberships,
            api_access_enabled=bool(api_access_enabled),
        )
    except ValidationError as exc:
        return await _rerender(
            [e["msg"] for e in exc.errors()], status.HTTP_422_UNPROCESSABLE_CONTENT
        )
    except ValueError as exc:
        return await _rerender([str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT)

    user = User(
        username=payload.username,
        display_name=payload.display_name,
        email=payload.email,
        auth_provider=payload.auth_provider,
        password_hash=hash_password(payload.password) if payload.password else None,
        # An admin-set initial password must be changed on first login —
        # nobody but the account owner should keep using a password someone
        # else picked and now knows.
        must_change_password=payload.auth_provider == AuthProvider.LOCAL,
        is_superadmin=payload.is_superadmin,
        api_access_enabled=payload.api_access_enabled,
    )
    user.memberships = [
        CompanyMembership(company_id=m.company_id, access_level=m.access_level)
        for m in payload.memberships
    ]
    db.add(user)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return await _rerender(
            [f'A user named "{payload.username}" already exists.'], status.HTTP_409_CONFLICT
        )
    await db.refresh(user)

    companies = await _get_companies(db)
    scope_label = _scope_label(user, payload.memberships, companies)
    await log_event(
        db,
        request=request,
        action="user.create",
        summary=f'Created user "{user.username}" ({user.auth_provider.value}, {scope_label})',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return RedirectResponse(url="/users", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/bulk/delete", dependencies=[Depends(verify_csrf)])
async def bulk_delete_users(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    user_ids: list[uuid.UUID] = Form(default=[]),
) -> Response:
    """Deletes every selected user except your own account and the last
    active superadmin (same two guards `delete_user` enforces one at a
    time) — either is silently skipped and counted, rather than aborting
    the whole batch over one unselectable row. Declared before
    `/{user_id}/...` below — Starlette matches routes in declaration
    order, and `{user_id}` would otherwise greedily match the literal
    "bulk" segment first."""
    if not user_ids:
        return RedirectResponse(
            url="/users?bulk_error=Select+at+least+one+user.",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    deleted = 0
    skipped = 0
    for user_id in user_ids:
        user = await db.get(User, user_id)
        if user is None:
            continue
        if user.id == current_user.id or await _would_remove_last_superadmin(db, user):
            skipped += 1
            continue
        username = user.username
        await db.delete(user)
        await db.commit()
        await log_event(
            db,
            request=request,
            action="user.delete",
            summary=f'Deleted user "{username}" (bulk)',
            target_type="user",
            target_id=user_id,
            target_label=username,
        )
        deleted += 1

    return RedirectResponse(
        url=f"/users?bulk_deleted={deleted}&bulk_skipped={skipped}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/bulk/assign-company", dependencies=[Depends(verify_csrf)])
async def bulk_assign_company(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_ids: list[uuid.UUID] = Form(default=[]),
    company_id: str = Form(""),
    access_level: str = Form(""),
) -> Response:
    """Grants every selected non-superadmin user one additional company
    membership (or updates the level of an existing one) — a superadmin in
    the selection is skipped and counted (moving a superadmin *out* of
    superadmin is a deliberate, one-at-a-time decision on that account's
    own edit page, not a bulk side effect). Unlike the single-company era,
    this is additive — it never removes a user's other memberships."""
    if not user_ids:
        return RedirectResponse(
            url="/users?bulk_error=Select+at+least+one+user.",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    try:
        parsed_company_id = uuid.UUID(company_id)
        parsed_access_level = AccessLevel(access_level)
    except ValueError:
        return RedirectResponse(
            url="/users?bulk_error=Pick+a+company+and+access+level.",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    company = await db.get(Company, parsed_company_id)
    if company is None:
        return RedirectResponse(
            url="/users?bulk_error=Pick+a+company+and+access+level.",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    assigned = 0
    skipped = 0
    for user_id in user_ids:
        user = await db.get(User, user_id, options=[selectinload(User.memberships)])
        if user is None:
            continue
        if user.is_superadmin:
            skipped += 1
            continue
        existing = next((m for m in user.memberships if m.company_id == parsed_company_id), None)
        if existing is not None:
            existing.access_level = parsed_access_level
        else:
            db.add(
                CompanyMembership(
                    user_id=user.id, company_id=parsed_company_id, access_level=parsed_access_level
                )
            )
        assigned += 1

    await db.commit()
    if assigned:
        await log_event(
            db,
            request=request,
            action="user.bulk_assign_company",
            summary=(
                f'Granted {assigned} user(s) access to "{company.name}" '
                f"({parsed_access_level.value})"
            ),
            target_type="company",
            target_id=company.id,
            target_label=company.name,
            details={"assigned": assigned, "skipped": skipped},
        )

    return RedirectResponse(
        url=f"/users?bulk_assigned={assigned}&bulk_skipped={skipped}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/{user_id}/edit")
async def edit_user_form(
    request: Request, user_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    user = await _get_user_or_404(user_id, db)
    return templates.TemplateResponse(
        request,
        "users/edit.html",
        {
            "target_user": user,
            "auth_providers": list(AuthProvider),
            "access_levels": list(AccessLevel),
            "companies": await _get_companies(db),
            "membership_levels": _membership_map(user),
            "errors": [],
            "csrf_token": request.state.csrf_token,
        },
    )


@router.post("/{user_id}/edit", dependencies=[Depends(verify_csrf)])
async def update_user(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    username: str = Form(...),
    display_name: str = Form(""),
    email: str = Form(""),
    auth_provider: AuthProvider = Form(...),
    password: str = Form(""),
    is_superadmin: str = Form(""),
    api_access_enabled: str = Form(""),
    is_active: str = Form(""),
    current_user: User = Depends(get_current_user),
) -> Response:
    user = await _get_user_or_404(user_id, db)
    form = await request.form()
    try:
        memberships = _parse_memberships(form)
    except ValueError:
        # A malformed membership field (not something the rendered form can
        # actually produce) — fall through to the model's own "needs at
        # least one membership" validation rather than a raw 500.
        memberships = []

    async def _rerender(errors: list[str], status_code: int) -> Response:
        return templates.TemplateResponse(
            request,
            "users/edit.html",
            {
                "target_user": user,
                "auth_providers": list(AuthProvider),
                "access_levels": list(AccessLevel),
                "companies": await _get_companies(db),
                "membership_levels": {m.company_id: m.access_level for m in memberships},
                "errors": errors,
                "csrf_token": request.state.csrf_token,
            },
            status_code=status_code,
        )

    try:
        payload = UserUpdate(
            username=username,
            display_name=display_name or None,
            email=email or None,
            auth_provider=auth_provider,
            password=password or None,
            is_superadmin=bool(is_superadmin),
            memberships=memberships,
            api_access_enabled=bool(api_access_enabled),
            is_active=bool(is_active),
        )
    except ValidationError as exc:
        return await _rerender(
            [e["msg"] for e in exc.errors()], status.HTTP_422_UNPROCESSABLE_CONTENT
        )
    except ValueError as exc:
        return await _rerender([str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT)

    if user.id == current_user.id:
        own_company_ids = {m.company_id for m in user.memberships}
        new_company_ids = {m.company_id for m in payload.memberships}
        if payload.is_superadmin != user.is_superadmin or own_company_ids != new_company_ids:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can't change your own scope — ask another superadmin.",
            )
        if not payload.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can't deactivate your own account.",
            )

    becoming_local = payload.auth_provider == AuthProvider.LOCAL
    losing_local = user.auth_provider == AuthProvider.LOCAL and not becoming_local
    # True provider switch only — not "already local, staying local." An
    # already-local account's password is changed exclusively through the
    # "Reset password" panel below, which also revokes every existing
    # session; this field silently doing the same thing with no
    # session-revocation would be an inconsistent, easy-to-miss backdoor.
    switching_to_local = becoming_local and user.auth_provider != AuthProvider.LOCAL
    if switching_to_local and not payload.password:
        return await _rerender(
            [f'Switching "{user.username}" to a local account needs a password.'],
            status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    still_superadmin = payload.is_active and payload.is_superadmin
    if user.is_superadmin and not still_superadmin:
        remaining = await count_active_superadmins(db, excluding_user_id=user.id)
        if remaining == 0:
            return await _rerender(
                ["This is the last superadmin account — it can't lose that access."],
                status.HTTP_409_CONFLICT,
            )

    # Checked before mutating `user` in place below: once its attributes are
    # dirtied, a `SELECT` here would trigger autoflush and emit the very
    # UPDATE this check exists to get ahead of, defeating the point (see
    # `_duplicate_username_error`'s docstring).
    duplicate_error = await _duplicate_username_error(
        db, exclude_user_id=user.id, username=payload.username
    )
    if duplicate_error is not None:
        return await _rerender([duplicate_error], status.HTTP_409_CONFLICT)

    user.username = payload.username
    user.display_name = payload.display_name
    user.email = payload.email
    user.auth_provider = payload.auth_provider
    user.is_superadmin = payload.is_superadmin
    await _apply_memberships(db, user, payload.memberships)
    user.is_active = payload.is_active
    user.api_access_enabled = payload.api_access_enabled
    if switching_to_local and payload.password:
        user.password_hash = hash_password(payload.password)
        user.must_change_password = True
    if losing_local:
        user.password_hash = None
        user.must_change_password = False

    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return await _rerender(
            [f'A user named "{payload.username}" already exists.'], status.HTTP_409_CONFLICT
        )

    if not payload.is_active:
        await revoke_all_sessions_for_user(db, user.id)

    await log_event(
        db,
        request=request,
        action="user.update",
        summary=f'Updated user "{user.username}"',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return RedirectResponse(url="/users", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{user_id}/reset-password", dependencies=[Depends(verify_csrf)])
async def reset_password(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    new_password: str = Form(...),
) -> Response:
    user = await _get_user_or_404(user_id, db)
    if user.auth_provider != AuthProvider.LOCAL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only local accounts have a Honeypot Shelf password to reset.",
        )
    if len(new_password) < MIN_PASSWORD_LENGTH:
        return templates.TemplateResponse(
            request,
            "users/edit.html",
            {
                "target_user": user,
                "auth_providers": list(AuthProvider),
                "access_levels": list(AccessLevel),
                "companies": await _get_companies(db),
                "membership_levels": _membership_map(user),
                "errors": [f"Password must be at least {MIN_PASSWORD_LENGTH} characters."],
                "csrf_token": request.state.csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    user.password_hash = hash_password(new_password)
    user.must_change_password = True
    await db.commit()
    await revoke_all_sessions_for_user(db, user.id)

    await log_event(
        db,
        request=request,
        action="user.password.reset",
        summary=f'Reset password for "{user.username}" (forced to change it on next login)',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return RedirectResponse(url=f"/users/{user.id}/edit", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{user_id}/sessions/revoke-all", dependencies=[Depends(verify_csrf)])
async def revoke_user_sessions(
    request: Request, user_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    user = await _get_user_or_404(user_id, db)
    await revoke_all_sessions_for_user(db, user.id)
    await log_event(
        db,
        request=request,
        action="user.sessions.revoke_all",
        summary=f'Logged out all sessions for "{user.username}"',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return RedirectResponse(url=f"/users/{user.id}/edit", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{user_id}/delete", dependencies=[Depends(verify_csrf)])
async def delete_user(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    user = await _get_user_or_404(user_id, db)
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="You can't delete your own account."
        )
    if await _would_remove_last_superadmin(db, user):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This is the last superadmin account — it can't be deleted.",
        )

    username = user.username
    await db.delete(user)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="user.delete",
        summary=f'Deleted user "{username}"',
        target_type="user",
        target_id=user_id,
        target_label=username,
    )
    return RedirectResponse(url="/users", status_code=status.HTTP_303_SEE_OTHER)
