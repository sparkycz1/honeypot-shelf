"""Companies (tenants) — superadmin-only CRUD, and superadmin bulk actions
(updates/power) against a company's honeypots or every honeypot in the
fleet ("All honeypots"). See the module docstring on the router
dependency below for why this whole file is superadmin-gated, unlike
debcontrol's machine groups."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_superadmin
from app.auth.scope import (
    companies_visible_to,
    count_visible_honeypots,
    honeypots_visible_to,
)
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_tag import Tag
from app.db.models.honeypot_update_run import HoneypotUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.company import CompanyCreate
from app.services.company_stats import compute_company_stats
from app.services.honeypot_actions import (
    send_power_to_honeypots,
    trigger_check_updates,
    trigger_updates,
)
from app.ssh.power import PowerAction
from app.web.honeypot_search import honeypot_search_clause
from app.web.routes.honeypots import _HONEYPOT_LIST_PAGE_SIZE
from app.web.templating import t, templates

# Companies are superadmin-only end to end (create/rename/delete, and the
# bulk update/power/tag actions below) — per the product decision recorded
# in CLAUDE.md/wiki/Home.md: only a superadmin creates or manages a
# company. A company's own READ_WRITE users manage their honeypots
# individually from /honeypots (already scoped to their company) rather
# than through this router.
router = APIRouter(prefix="/companies", dependencies=[Depends(require_superadmin)])
_manage = Depends(require_superadmin)
_updates = Depends(require_superadmin)
_power = Depends(require_superadmin)

# Typed phrase to confirm a power action against literally every honeypot —
# "All honeypots" doesn't have a single name of its own to ask someone to type.
ALL_HONEYPOTS_CONFIRM_PHRASE = "ALL HONEYPOTS"


def _company_tabs(request: Request, company: Company) -> list[tuple[str, str, str]]:
    """The (key, label, url) tabs shown on every one of this company's own
    pages. Just "Overview" — a single company's own page deliberately shows
    only its users and its honeypots (see the product decision in
    CLAUDE.md/wiki/Home.md); the fleet-wide bulk update/power tools stay on
    "All honeypots" (`companies/all.html`), not here."""
    base = f"/companies/{company.id}"
    return [
        ("overview", t(request, "honeypots.tabs.overview"), base),
    ]


async def _get_company_or_404(company_id: uuid.UUID, db: AsyncSession, user: User) -> Company:
    """The company, or a 404 — including when it exists but is outside `user`'s
    company scope. 404 rather than 403, same convention as
    `app/web/routes/honeypots.py`'s `_get_honeypot_or_404`."""
    query = companies_visible_to(user)
    result = await db.execute(
        query.options(selectinload(Company.honeypots)).where(Company.id == company_id)
    )
    company = result.scalar_one_or_none()
    if company is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Company not found.")
    return company


async def _all_visible_honeypots(db: AsyncSession, user: User) -> list[Honeypot]:
    """Every honeypot `user` can see — what the "All honeypots" virtual company
    means for this account.

    For an unrestricted account that is literally the whole fleet, exactly as
    before. For a restricted one it is their companies' honeypots and nothing
    else: acting on "all honeypots" must never reach past the boundary, and
    the page would be lying if it counted honeypots the account can't open.
    (Scheduling is the one place where "All honeypots" is refused outright
    instead of narrowed — a *stored* schedule outlives the scope that
    created it. See `app/web/routes/scheduling.py`.)"""
    query = honeypots_visible_to(user)
    result = await db.execute(query)
    return list(result.scalars().all())


async def _get_all_tags(db: AsyncSession) -> list[Tag]:
    """Every tag currently in use, alphabetical — same helper as
    `app.web.routes.honeypots`'s own (not shared as a cross-module import:
    each route module owns its own small query helpers, same convention
    as `_get_companies` existing separately in both already)."""
    result = await db.execute(select(Tag).order_by(Tag.name))
    return list(result.scalars().all())


async def _get_company_member_counts(db: AsyncSession) -> dict[uuid.UUID, int]:
    """One cheap aggregate query, not `selectinload(Company.honeypots)` —
    the list page only ever needs *how many* honeypots are in each company, not
    the honeypots themselves. At fleet sizes in the hundreds/thousands,
    eagerly loading every honeypot row (with its facts/package-count JSON
    columns) just to call `len()` on it turns one page view into loading the
    entire `honeypots` table."""
    result = await db.execute(
        select(Honeypot.company_id, func.count())
        .where(Honeypot.company_id.is_not(None))
        .group_by(Honeypot.company_id)
    )
    return {company_id: count for company_id, count in result.all() if company_id is not None}


@router.get("")
async def list_companies(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    q: str = "",
) -> Response:
    query = companies_visible_to(current_user)
    if q.strip():
        needle = f"%{q.strip()}%"
        query = query.where(
            or_(Company.name.ilike(needle), Company.notes.ilike(needle))
        )
    result = await db.execute(query.order_by(Company.name))
    companies = result.scalars().all()
    member_counts = await _get_company_member_counts(db)
    all_honeypots_count = await count_visible_honeypots(db, current_user)
    return templates.TemplateResponse(
        request,
        "companies/list.html",
        {
            "companies": companies,
            "member_counts": member_counts,
            "all_honeypots_count": all_honeypots_count or 0,
            "q": q,
        },
    )


@router.get("/new")
async def new_company_form(request: Request) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request, "companies/new.html", {"errors": [], "form": {}, "csrf_token": csrf_token}
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("", dependencies=[_manage, Depends(verify_csrf)])
async def create_company(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    name: str = Form(...),
    notes: str = Form(""),
) -> Response:
    # A restricted account creating a company would create something it can't
    # then see (a new company is in nobody's grant set) — refuse rather than
    # hand back a company that vanishes on the next request.
    if not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Your account is restricted to specific honeypot companies and can't "
                "create new ones."
            ),
        )
    try:
        payload = CompanyCreate(name=name, notes=notes or None)
    except ValueError as exc:
        await log_event(
            db,
            request=request,
            action="company.create",
            summary=f'Rejected new company "{name}": {exc}',
            outcome=AuditOutcome.FAILURE,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "companies/new.html",
            {
                "errors": [str(exc)],
                "form": {"name": name, "notes": notes},
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    company = Company(name=payload.name, notes=payload.notes)
    db.add(company)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        await log_event(
            db,
            request=request,
            action="company.create",
            summary=f'Rejected new company "{payload.name}": name already exists',
            outcome=AuditOutcome.FAILURE,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "companies/new.html",
            {
                "errors": [f'A company named "{payload.name}" already exists.'],
                "form": {"name": name, "notes": notes},
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_409_CONFLICT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    await db.refresh(company)
    await log_event(
        db,
        request=request,
        action="company.create",
        summary=f'Created company "{company.name}"',
        target_type="company",
        target_id=company.id,
        target_label=company.name,
    )
    return RedirectResponse(
        url=f"/companies/{company.id}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/all")
async def all_honeypots_company(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    q: str = "",
    tag: str = "",
    page: int = 1,
) -> Response:
    """The "All honeypots" virtual company — every honeypot, always, automatically.

    Unlike real companies, this isn't backed by any membership data (a honeypot
    can only have one real `company_id`, so it couldn't also "belong" to a
    stored All-honeypots company without a bigger many-to-many rework). Instead
    this just queries every honeypot unconditionally, which trivially and
    always satisfies "always all honeypots" without anything to keep in sync.
    Registered before `/{company_id}` — `uuid.UUID` there won't match the
    literal "all" anyway, but route order is what actually decides it.

    Paginated the same way `GET /honeypots` is — this is, after all, the same
    "every honeypot" listing under a different URL, so it has the same
    unbounded-page-size problem at fleet sizes in the hundreds/thousands.
    """
    page = max(page, 1)
    query = (honeypots_visible_to(current_user)).options(selectinload(Honeypot.company))
    if q.strip():
        query = query.where(honeypot_search_clause(q))
    if tag.strip():
        query = query.where(Honeypot.tags.any(Tag.name == tag.strip().lower()))

    offset = (page - 1) * _HONEYPOT_LIST_PAGE_SIZE
    result = await db.execute(
        query.order_by(Honeypot.name).offset(offset).limit(_HONEYPOT_LIST_PAGE_SIZE + 1)
    )
    honeypots = list(result.scalars().all())
    has_more = len(honeypots) > _HONEYPOT_LIST_PAGE_SIZE
    honeypots = honeypots[:_HONEYPOT_LIST_PAGE_SIZE]

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "companies/all.html",
        {
            "honeypots": honeypots,
            "all_tags": await _get_all_tags(db),
            "q": q,
            "tag": tag,
            "page": page,
            "has_more": has_more,
            "csrf_token": csrf_token,
            "power_skipped": request.query_params.get("power_skipped"),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/all/updates", dependencies=[_updates, Depends(verify_csrf)])
async def trigger_all_honeypots_update(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    strategy: UpgradeStrategy = Form(...),
) -> Response:
    honeypots = await _all_visible_honeypots(db, current_user)

    batch_id, skipped = await trigger_updates(db, honeypots, strategy)

    await log_event(
        db,
        request=request,
        action="all_honeypots.updates.run",
        summary=f"Triggered {strategy.value.replace('_', '-')} on all honeypots",
        target_type="all_honeypots",
        details={"strategy": strategy.value, "batch_id": str(batch_id), "skipped": skipped},
    )

    redirect_url = f"/companies/batches/{batch_id}"
    if skipped:
        redirect_url += f"?skipped={skipped}"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/all/check-updates", dependencies=[_updates, Depends(verify_csrf)])
async def trigger_all_check_updates(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    skipped = await trigger_check_updates(await _all_visible_honeypots(db, current_user))
    await log_event(
        db,
        request=request,
        action="all_honeypots.updates.check",
        summary="Checked for updates on all honeypots",
        target_type="all_honeypots",
        details={"skipped": skipped},
    )
    return RedirectResponse(url="/companies/all", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/all/power/{action}")
async def all_power_confirm(request: Request, action: PowerAction) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "companies/power_confirm.html",
        {
            "action": action,
            "target_label": "every honeypot",
            "confirm_phrase": ALL_HONEYPOTS_CONFIRM_PHRASE,
            "action_url": "/companies/all/power",
            "cancel_url": "/companies/all",
            "error": None,
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/all/power", dependencies=[_power, Depends(verify_csrf)])
async def all_power_action(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    action: PowerAction = Form(...),
    confirm_name: str = Form(...),
) -> Response:
    if confirm_name.strip() != ALL_HONEYPOTS_CONFIRM_PHRASE:
        await log_event(
            db,
            request=request,
            action=f"all_honeypots.power.{action.value}",
            summary=f"Blocked {action.value} on all honeypots: confirmation mismatch",
            outcome=AuditOutcome.DENIED,
            target_type="all_honeypots",
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "companies/power_confirm.html",
            {
                "action": action,
                "target_label": "every honeypot",
                "confirm_phrase": ALL_HONEYPOTS_CONFIRM_PHRASE,
                "action_url": "/companies/all/power",
                "cancel_url": "/companies/all",
                "error": (
                    f'That doesn\'t match — type "{ALL_HONEYPOTS_CONFIRM_PHRASE}" '
                    "exactly to confirm."
                ),
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    honeypots = await _all_visible_honeypots(db, current_user)
    skipped = await send_power_to_honeypots(honeypots, action)
    await log_event(
        db,
        request=request,
        action=f"all_honeypots.power.{action.value}",
        summary=f"Sent {action.value} to all honeypots",
        target_type="all_honeypots",
        details={"skipped": skipped},
    )
    redirect_url = "/companies/all"
    if skipped:
        redirect_url += f"?power_skipped={skipped}"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{company_id}")
async def company_detail(
    request: Request,
    company_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    q: str = "",
    tag: str = "",
) -> Response:
    """A single company's own page shows only two things, per the product
    decision recorded in CLAUDE.md/wiki/Home.md: its users, and its
    honeypots — each with a link to add another (`/users/new` and
    `/honeypots/new`, both superadmin-only forms, pre-selecting this
    company). Unlike debcontrol's machine groups, a honeypot's company
    isn't editable from here as a membership action — every `Honeypot`
    requires exactly one `Company` (DB-enforced, not nullable), so "move a
    honeypot in/out of this company" doesn't make sense the way optional
    group membership did. Reassigning a honeypot to a different company is
    part of its own edit form (`app/web/routes/honeypots.py`, superadmin-
    only there too via the company `<select>`)."""
    company = await _get_company_or_404(company_id, db, current_user)

    members_query = (
        select(Honeypot)
        .options(selectinload(Honeypot.company))
        .where(Honeypot.company_id == company_id)
    )
    if q.strip():
        members_query = members_query.where(honeypot_search_clause(q))
    if tag.strip():
        members_query = members_query.where(Honeypot.tags.any(Tag.name == tag.strip().lower()))
    result = await db.execute(members_query.order_by(Honeypot.name))
    honeypots = result.scalars().all()

    users_result = await db.execute(
        select(User).where(User.company_id == company_id).order_by(User.username)
    )
    users = users_result.scalars().all()
    stats = await compute_company_stats(db, company_id)

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "companies/detail.html",
        {
            "company": company,
            "tabs": _company_tabs(request, company),
            "active_tab": "overview",
            "honeypots": honeypots,
            "users": users,
            "stats": stats,
            "all_tags": await _get_all_tags(db),
            "q": q,
            "tag": tag,
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


async def _visible_batch_runs(
    batch_id: uuid.UUID, db: AsyncSession, user: User
) -> list[HoneypotUpdateRun]:
    """One batch's update runs, restricted to honeypots `user` can see.

    A batch is an ad-hoc set of honeypots, so it can straddle the boundary
    (an unrestricted admin triggering "All honeypots" produces one batch
    covering everything). Showing a restricted account only its own rows
    keeps the page useful without leaking the rest."""
    visible_ids = (honeypots_visible_to(user)).with_only_columns(Honeypot.id)
    result = await db.execute(
        select(HoneypotUpdateRun)
        .options(selectinload(HoneypotUpdateRun.honeypot))
        .where(
            HoneypotUpdateRun.batch_id == batch_id,
            HoneypotUpdateRun.honeypot_id.in_(visible_ids),
        )
        .order_by(HoneypotUpdateRun.created_at)
    )
    return list(result.scalars().all())


@router.get("/batches/{batch_id}")
async def update_batch_detail(
    request: Request,
    batch_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    skipped: int = 0,
) -> Response:
    runs = await _visible_batch_runs(batch_id, db, current_user)
    if not runs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Batch not found.")

    has_pending = any(r.status in (UpdateRunStatus.PENDING, UpdateRunStatus.RUNNING) for r in runs)
    return templates.TemplateResponse(
        request,
        "companies/batch.html",
        {"runs": runs, "batch_id": batch_id, "skipped": skipped, "has_pending": has_pending},
    )


@router.get("/batches/{batch_id}/status")
async def update_batch_status(
    request: Request,
    batch_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    runs = await _visible_batch_runs(batch_id, db, current_user)
    has_pending = any(r.status in (UpdateRunStatus.PENDING, UpdateRunStatus.RUNNING) for r in runs)
    return templates.TemplateResponse(
        request,
        "partials/update_batch_status.html",
        {"runs": runs, "batch_id": batch_id, "has_pending": has_pending},
    )


@router.post("/{company_id}/delete", dependencies=[_manage, Depends(verify_csrf)])
async def delete_company(
    request: Request,
    company_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    company = await _get_company_or_404(company_id, db, current_user)
    company_name = company.name
    honeypot_count = len(company.honeypots)
    # Unlike debcontrol (deleting a group just orphans its machines —
    # `group_id` is nullable there), deleting a Company here cascades to
    # delete every one of its Honeypots, and each honeypot's events with
    # it (`Company.honeypots`/`Honeypot.events` are both
    # `cascade="all, delete-orphan"`) — there is no "no company" state a
    # honeypot can be left in. The confirmation form
    # (`companies/detail.html`) makes this explicit before this route is
    # ever reached.
    await db.delete(company)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="company.delete",
        summary=f'Deleted company "{company_name}" and its {honeypot_count} honeypot(s)',
        target_type="company",
        target_id=company_id,
        target_label=company_name,
        details={"honeypot_count": honeypot_count},
    )
    return RedirectResponse(url="/companies", status_code=status.HTTP_303_SEE_OTHER)
