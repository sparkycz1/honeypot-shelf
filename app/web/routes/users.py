"""User accounts — CRUD, password resets, and forcing a re-login.
Superadmin-only end to end (checked at the router level).

Every route here also protects against locking everyone out: you can't
deactivate, delete, or demote your own account, and the last active
superadmin can't be deactivated, deleted, or demoted away from it either
(see `app.auth.login.count_active_superadmins`).

Unlike debcontrol's role selection + opt-in machine-group scope checkbox
list, creating/editing a user here means picking exactly one of two
shapes: superadmin (no company, no access level), or a company +
READ/READ_WRITE access level. See `app.db.models.user`'s module docstring.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
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
from app.db.models.user import AccessLevel, AuthProvider, User
from app.db.session import get_db
from app.schemas.user import MIN_PASSWORD_LENGTH, UserCreate, UserUpdate
from app.web.templating import templates

router = APIRouter(prefix="/users", dependencies=[Depends(require_superadmin)])


async def _get_user_or_404(user_id: uuid.UUID, db: AsyncSession) -> User:
    result = await db.execute(
        select(User).options(selectinload(User.company)).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return user


async def _get_companies(db: AsyncSession) -> list[Company]:
    result = await db.execute(select(Company).order_by(Company.name))
    return list(result.scalars().all())


async def _would_remove_last_superadmin(db: AsyncSession, target: User) -> bool:
    if not target.is_superadmin:
        return False
    remaining = await count_active_superadmins(db, excluding_user_id=target.id)
    return remaining == 0


def _resolve_scope(
    is_superadmin: str, company_id: str, access_level: str
) -> tuple[bool, uuid.UUID | None, AccessLevel | None]:
    """The three raw form fields into the (is_superadmin, company_id,
    access_level) shape `UserCreate`/`UserUpdate` validate — a checkbox
    plus a company `<select>` plus an access-level `<select>`, the latter
    two only meaningful (and only rendered) when the checkbox is off."""
    if is_superadmin:
        return True, None, None
    parsed_company_id = uuid.UUID(company_id) if company_id else None
    parsed_access_level = AccessLevel(access_level) if access_level else None
    return False, parsed_company_id, parsed_access_level


@router.get("")
async def list_users(
    request: Request, db: AsyncSession = Depends(get_db), company_id: uuid.UUID | None = None
) -> Response:
    """`?company_id=` narrows the list to one company — used by that
    company's own page ("Users in this company" links here to see
    everyone, not just the ones shown inline there) as well as directly.
    Superadmin-only end to end (router-level), so no scoping check beyond
    the filter itself is needed."""
    query = select(User).options(selectinload(User.company)).order_by(User.username)
    if company_id is not None:
        query = query.where(User.company_id == company_id)
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
        },
    )


@router.get("/new")
async def new_user_form(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    return templates.TemplateResponse(
        request,
        "users/new.html",
        {
            "auth_providers": list(AuthProvider),
            "access_levels": list(AccessLevel),
            "companies": await _get_companies(db),
            "errors": [],
            # Pre-selects the company `<select>` when linked from that
            # company's own page ("Add user") — purely a UI convenience,
            # still just a regular field on the form the operator can change.
            "form": {"company_id": request.query_params.get("company_id", "")},
            "csrf_token": request.state.csrf_token,
        },
    )


@router.post("", dependencies=[Depends(verify_csrf)])
async def create_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
    username: str = Form(...),
    display_name: str = Form(""),
    auth_provider: AuthProvider = Form(...),
    password: str = Form(""),
    is_superadmin: str = Form(""),
    company_id: str = Form(""),
    access_level: str = Form(""),
    api_access_enabled: str = Form(""),
) -> Response:
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
                    "auth_provider": auth_provider,
                },
                "csrf_token": request.state.csrf_token,
            },
            status_code=status_code,
        )

    try:
        resolved_is_superadmin, resolved_company_id, resolved_access_level = _resolve_scope(
            is_superadmin, company_id, access_level
        )
        payload = UserCreate(
            username=username,
            display_name=display_name or None,
            auth_provider=auth_provider,
            password=password or None,
            is_superadmin=resolved_is_superadmin,
            company_id=resolved_company_id,
            access_level=resolved_access_level,
            api_access_enabled=bool(api_access_enabled),
        )
    except ValueError as exc:
        return await _rerender([str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT)

    user = User(
        username=payload.username,
        display_name=payload.display_name,
        auth_provider=payload.auth_provider,
        password_hash=hash_password(payload.password) if payload.password else None,
        # An admin-set initial password must be changed on first login —
        # nobody but the account owner should keep using a password someone
        # else picked and now knows.
        must_change_password=payload.auth_provider == AuthProvider.LOCAL,
        is_superadmin=payload.is_superadmin,
        company_id=payload.company_id,
        access_level=payload.access_level,
        api_access_enabled=payload.api_access_enabled,
    )
    db.add(user)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return await _rerender(
            [f'A user named "{payload.username}" already exists.'], status.HTTP_409_CONFLICT
        )
    await db.refresh(user)

    scope_label = (
        "superadmin"
        if user.is_superadmin
        else f"{(await db.get(Company, user.company_id)).name}/{user.access_level.value}"  # type: ignore[union-attr]
    )
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
    auth_provider: AuthProvider = Form(...),
    password: str = Form(""),
    is_superadmin: str = Form(""),
    company_id: str = Form(""),
    access_level: str = Form(""),
    api_access_enabled: str = Form(""),
    is_active: str = Form(""),
    current_user: User = Depends(get_current_user),
) -> Response:
    user = await _get_user_or_404(user_id, db)

    async def _rerender(errors: list[str], status_code: int) -> Response:
        return templates.TemplateResponse(
            request,
            "users/edit.html",
            {
                "target_user": user,
                "auth_providers": list(AuthProvider),
                "access_levels": list(AccessLevel),
                "companies": await _get_companies(db),
                "errors": errors,
                "csrf_token": request.state.csrf_token,
            },
            status_code=status_code,
        )

    try:
        resolved_is_superadmin, resolved_company_id, resolved_access_level = _resolve_scope(
            is_superadmin, company_id, access_level
        )
        payload = UserUpdate(
            username=username,
            display_name=display_name or None,
            auth_provider=auth_provider,
            password=password or None,
            is_superadmin=resolved_is_superadmin,
            company_id=resolved_company_id,
            access_level=resolved_access_level,
            api_access_enabled=bool(api_access_enabled),
            is_active=bool(is_active),
        )
    except ValueError as exc:
        return await _rerender([str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT)

    if user.id == current_user.id:
        if payload.is_superadmin != user.is_superadmin or payload.company_id != user.company_id:
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
    if becoming_local and user.auth_provider != AuthProvider.LOCAL and not payload.password:
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

    user.username = payload.username
    user.display_name = payload.display_name
    user.auth_provider = payload.auth_provider
    user.is_superadmin = payload.is_superadmin
    user.company_id = payload.company_id
    user.access_level = payload.access_level
    user.is_active = payload.is_active
    user.api_access_enabled = payload.api_access_enabled
    if becoming_local:
        if payload.password:
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
            detail="Only local accounts have a HoneyHive password to reset.",
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
