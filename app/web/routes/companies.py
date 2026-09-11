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
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.company import Company
from app.db.models.company_membership import CompanyMembership
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_company import honeypot_companies
from app.db.models.honeypot_tag import Tag
from app.db.models.honeypot_update_run import HoneypotUpdateRun, UpdateRunStatus
from app.db.models.user import AccessLevel, User
from app.db.session import get_db
from app.schemas.company import CompanyCreate
from app.services.company_stats import compute_company_stats
from app.services.syslog_transport import DEFAULT_SYSLOG_PORT, SyslogProtocol
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


def _company_tabs(request: Request, company: Company) -> list[tuple[str, str, str]]:
    """The (key, label, url) tabs shown on every one of this company's own
    pages. "Overview" — a single company's own page deliberately shows
    only its users and its honeypots (see the product decision in
    CLAUDE.md/wiki/Home.md) — and "Integrations", this company's own
    syslog target for its honeypot alerts (see `app.services.
    honeypot_event_syslog`). Same two-tab shape `_all_honeypots_tabs`
    below uses for the "All honeypots" virtual company."""
    base = f"/companies/{company.id}"
    return [
        ("overview", t(request, "honeypots.tabs.overview"), base),
        ("integrations", t(request, "companies.tabs.integrations"), f"{base}/integrations"),
    ]


def _all_honeypots_tabs(request: Request) -> list[tuple[str, str, str]]:
    """Same shape as `_company_tabs`, for the "All honeypots" virtual
    company (`all_honeypots_company`/`all_honeypots_integrations` below) —
    no `Company` row to hang this off, so it's a plain function rather
    than reading anything off a model."""
    return [
        ("overview", t(request, "honeypots.tabs.overview"), "/companies/all"),
        (
            "integrations",
            t(request, "companies.tabs.integrations"),
            "/companies/all/integrations",
        ),
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
        select(honeypot_companies.c.company_id, func.count())
        .group_by(honeypot_companies.c.company_id)
    )
    return {company_id: count for company_id, count in result.all()}


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
    query = honeypots_visible_to(current_user)
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
            "tabs": _all_honeypots_tabs(request),
            "active_tab": "overview",
            "honeypots": honeypots,
            "all_tags": await _get_all_tags(db),
            "q": q,
            "tag": tag,
            "page": page,
            "has_more": has_more,
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/all/integrations")
async def all_honeypots_integrations(
    request: Request, db: AsyncSession = Depends(get_db)
) -> Response:
    """The "All honeypots" page's own syslog target — same shape as a real
    company's own Integrations tab (`company_integrations` above), but
    fleet-wide: every honeypot's alerts get forwarded here *in addition
    to* its own company's target, if both are configured. Persisted on
    `AppSettings` (there's no `Company` row backing "All honeypots" at
    all — see `all_honeypots_company`'s own docstring), not a second,
    per-company-shaped table.

    Replaces the bulk update/power sections this page used to have —
    removed per explicit instruction: the Honeypots list's own bulk-select
    actions already cover the same ground with finer-grained selection,
    making a separate "confirm by typing ALL HONEYPOTS" flow here
    redundant.
    """
    app_settings = await get_or_create_app_settings(db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "companies/all_integrations.html",
        {
            "tabs": _all_honeypots_tabs(request),
            "active_tab": "integrations",
            "app_settings": app_settings,
            "csrf_token": csrf_token,
            "syslog_protocols": list(SyslogProtocol),
            "errors": [],
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/all/integrations", dependencies=[Depends(verify_csrf)])
async def update_all_honeypots_integrations(
    request: Request,
    db: AsyncSession = Depends(get_db),
    syslog_enabled: str = Form(""),
    syslog_host: str = Form(""),
    syslog_port: str = Form(str(DEFAULT_SYSLOG_PORT)),
    syslog_protocol: str = Form(SyslogProtocol.UDP.value),
) -> Response:
    app_settings = await get_or_create_app_settings(db)
    errors: list[str] = []

    host = syslog_host.strip()
    try:
        protocol = SyslogProtocol(syslog_protocol)
    except ValueError:
        errors.append("Unknown syslog protocol.")
        protocol = app_settings.fleet_alert_syslog_protocol

    try:
        port = int(syslog_port.strip() or str(DEFAULT_SYSLOG_PORT))
        if not (0 < port <= 65535):
            raise ValueError
    except ValueError:
        errors.append("Port must be a whole number between 1 and 65535.")
        port = app_settings.fleet_alert_syslog_port

    if bool(syslog_enabled) and not host:
        errors.append("Enabling syslog forwarding needs a server host/IP.")

    if errors:
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "companies/all_integrations.html",
            {
                "tabs": _all_honeypots_tabs(request),
                "active_tab": "integrations",
                "app_settings": app_settings,
                "csrf_token": csrf_token,
                "syslog_protocols": list(SyslogProtocol),
                "errors": errors,
            },
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    app_settings.fleet_alert_syslog_enabled = bool(syslog_enabled)
    app_settings.fleet_alert_syslog_host = host or None
    app_settings.fleet_alert_syslog_port = port
    app_settings.fleet_alert_syslog_protocol = protocol
    await db.commit()

    state = "enabled, " + protocol.value if app_settings.fleet_alert_syslog_enabled else "disabled"
    await log_event(
        db,
        request=request,
        action="all_honeypots.syslog.update",
        summary=f"Updated fleet-wide honeypot-alert syslog forwarding ({state})",
        target_type="all_honeypots",
    )
    return RedirectResponse(
        url="/companies/all/integrations", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/{company_id}")
async def company_detail(
    request: Request,
    company_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    q: str = "",
    tag: str = "",
) -> Response:
    """A single company's own page shows its users and its honeypots, each
    with a way to attach one that already exists (`attach_existing_user`/
    `attach_existing_honeypot` below) rather than only ever creating a
    brand new one — both `User`↔`Company` and `Honeypot`↔`Company` are
    many-to-many now (see `app.db.models.company`'s module docstring), so
    "add" here means "grant/attach", never a silent create. Creating a
    genuinely new user/honeypot from scratch still goes through
    `/users/new`/`/honeypots/new` (both superadmin-only), which this page
    also links to, pre-selecting this company."""
    company = await _get_company_or_404(company_id, db, current_user)

    members_query = select(Honeypot).where(Honeypot.companies.any(Company.id == company_id))
    if q.strip():
        members_query = members_query.where(honeypot_search_clause(q))
    if tag.strip():
        members_query = members_query.where(Honeypot.tags.any(Tag.name == tag.strip().lower()))
    result = await db.execute(members_query.order_by(Honeypot.name))
    honeypots = result.scalars().all()

    users_result = await db.execute(
        select(User)
        .where(User.memberships.any(CompanyMembership.company_id == company_id))
        .order_by(User.username)
    )
    users = users_result.scalars().all()
    stats = await compute_company_stats(db, company_id)

    member_honeypot_ids = {h.id for h in honeypots}
    member_user_ids = {u.id for u in users}
    attachable_honeypots_result = await db.execute(
        honeypots_visible_to(current_user).order_by(Honeypot.name)
    )
    attachable_honeypots = [
        h for h in attachable_honeypots_result.scalars().all() if h.id not in member_honeypot_ids
    ]
    attachable_users_result = await db.execute(select(User).order_by(User.username))
    attachable_users = [
        u
        for u in attachable_users_result.scalars().all()
        if u.id not in member_user_ids and not u.is_superadmin
    ]

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
            "attachable_honeypots": attachable_honeypots,
            "attachable_users": attachable_users,
            "access_levels": list(AccessLevel),
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


@router.post("/{company_id}/users/attach", dependencies=[Depends(verify_csrf)])
async def attach_existing_user(
    request: Request,
    company_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    user_id: uuid.UUID = Form(...),
    access_level: str = Form(...),
) -> Response:
    """Grants an already-existing (non-superadmin) user access to this
    company — additive: never touches any membership that user already
    holds elsewhere. The counterpart to `/users/new?company_id=...`, for
    the common case of a person who already has an account somewhere else
    in the fleet."""
    company = await _get_company_or_404(company_id, db, current_user)
    user = await db.get(User, user_id, options=[selectinload(User.memberships)])
    if user is None or user.is_superadmin:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    try:
        parsed_level = AccessLevel(access_level)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Unknown access level."
        ) from None

    existing = next((m for m in user.memberships if m.company_id == company_id), None)
    if existing is not None:
        existing.access_level = parsed_level
    else:
        db.add(
            CompanyMembership(user_id=user.id, company_id=company_id, access_level=parsed_level)
        )
    await db.commit()

    await log_event(
        db,
        request=request,
        action="company.user.attach",
        summary=f'Granted "{user.username}" {parsed_level.value} access to "{company.name}"',
        target_type="company",
        target_id=company.id,
        target_label=company.name,
    )
    return RedirectResponse(url=f"/companies/{company_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{company_id}/users/{user_id}/detach", dependencies=[Depends(verify_csrf)])
async def detach_user(
    request: Request,
    company_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Removes one user's membership in this company — the account itself
    is untouched (it may still hold membership elsewhere, or none at
    all)."""
    company = await _get_company_or_404(company_id, db, current_user)
    user = await db.get(User, user_id, options=[selectinload(User.memberships)])
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    membership = next((m for m in user.memberships if m.company_id == company_id), None)
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not a member.")
    await db.delete(membership)
    await db.commit()

    await log_event(
        db,
        request=request,
        action="company.user.detach",
        summary=f'Removed "{user.username}"\'s access to "{company.name}"',
        target_type="company",
        target_id=company.id,
        target_label=company.name,
    )
    return RedirectResponse(url=f"/companies/{company_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{company_id}/honeypots/attach", dependencies=[Depends(verify_csrf)])
async def attach_existing_honeypot(
    request: Request,
    company_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    honeypot_id: uuid.UUID = Form(...),
) -> Response:
    """Attaches an already-existing honeypot to this company — additive:
    a honeypot can sit under any number of companies at once, so this
    never detaches it from wherever else it already is. The counterpart
    to `/honeypots/new?company_id=...`, for a honeypot that's shared
    across companies or was provisioned before it had one."""
    company = await _get_company_or_404(company_id, db, current_user)
    result = await db.execute(honeypots_visible_to(current_user).where(Honeypot.id == honeypot_id))
    honeypot = result.scalar_one_or_none()
    if honeypot is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Honeypot not found.")

    if company not in honeypot.companies:
        honeypot.companies.append(company)
        await db.commit()

    await log_event(
        db,
        request=request,
        action="company.honeypot.attach",
        summary=f'Attached "{honeypot.name}" to "{company.name}"',
        target_type="company",
        target_id=company.id,
        target_label=company.name,
    )
    return RedirectResponse(url=f"/companies/{company_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post(
    "/{company_id}/honeypots/{honeypot_id}/detach", dependencies=[Depends(verify_csrf)]
)
async def detach_honeypot(
    request: Request,
    company_id: uuid.UUID,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Detaches a honeypot from this company only — the honeypot itself is
    never deleted, even if this was its last company (an unassigned
    honeypot is a valid, if superadmin-only-visible, state)."""
    company = await _get_company_or_404(company_id, db, current_user)
    result = await db.execute(honeypots_visible_to(current_user).where(Honeypot.id == honeypot_id))
    honeypot = result.scalar_one_or_none()
    if honeypot is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Honeypot not found.")

    if company in honeypot.companies:
        honeypot.companies.remove(company)
        await db.commit()

    await log_event(
        db,
        request=request,
        action="company.honeypot.detach",
        summary=f'Detached "{honeypot.name}" from "{company.name}"',
        target_type="company",
        target_id=company.id,
        target_label=company.name,
    )
    return RedirectResponse(url=f"/companies/{company_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{company_id}/integrations")
async def company_integrations(
    request: Request,
    company_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """This company's own syslog target for its honeypot *alerts* only —
    see `app.services.honeypot_event_syslog`'s module docstring for why
    this is per-company rather than living on the global Settings ->
    Integrations page alongside the audit-log target
    (`app.audit_syslog`)."""
    company = await _get_company_or_404(company_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "companies/integrations.html",
        {
            "company": company,
            "tabs": _company_tabs(request, company),
            "active_tab": "integrations",
            "csrf_token": csrf_token,
            "syslog_protocols": list(SyslogProtocol),
            "errors": [],
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{company_id}/integrations", dependencies=[Depends(verify_csrf)])
async def update_company_integrations(
    request: Request,
    company_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    syslog_enabled: str = Form(""),
    syslog_host: str = Form(""),
    syslog_port: str = Form(str(DEFAULT_SYSLOG_PORT)),
    syslog_protocol: str = Form(SyslogProtocol.UDP.value),
) -> Response:
    company = await _get_company_or_404(company_id, db, current_user)
    errors: list[str] = []

    host = syslog_host.strip()
    try:
        protocol = SyslogProtocol(syslog_protocol)
    except ValueError:
        errors.append("Unknown syslog protocol.")
        protocol = company.syslog_protocol

    try:
        port = int(syslog_port.strip() or str(DEFAULT_SYSLOG_PORT))
        if not (0 < port <= 65535):
            raise ValueError
    except ValueError:
        errors.append("Port must be a whole number between 1 and 65535.")
        port = company.syslog_port

    if bool(syslog_enabled) and not host:
        errors.append("Enabling syslog forwarding needs a server host/IP.")

    if errors:
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "companies/integrations.html",
            {
                "company": company,
                "tabs": _company_tabs(request, company),
                "active_tab": "integrations",
                "csrf_token": csrf_token,
                "syslog_protocols": list(SyslogProtocol),
                "errors": errors,
            },
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    company.syslog_enabled = bool(syslog_enabled)
    company.syslog_host = host or None
    company.syslog_port = port
    company.syslog_protocol = protocol
    await db.commit()

    await log_event(
        db,
        request=request,
        action="company.syslog.update",
        summary=(
            f'Updated honeypot-alert syslog forwarding for "{company.name}" '
            f"({'enabled, ' + protocol.value if company.syslog_enabled else 'disabled'})"
        ),
        target_type="company",
        target_id=company.id,
        target_label=company.name,
    )
    return RedirectResponse(
        url=f"/companies/{company.id}/integrations", status_code=status.HTTP_303_SEE_OTHER
    )


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
    member_count = len(company.memberships)
    # Unlike the old single-company model (and unlike debcontrol's own
    # `group_id`-is-nullable orphaning), deleting a Company now only ever
    # removes *links* — its `CompanyMembership` rows and its
    # `honeypot_companies` rows, both `ondelete=CASCADE` at the DB level
    # (see the `d4e5f6a7b8c9` migration). Neither a honeypot nor a user
    # account is ever deleted by this: a honeypot may still belong to
    # other companies (or none, which is now a valid state), and a user
    # may still hold membership elsewhere (or none, which just means
    # logged in but scoped to nothing). The confirmation form
    # (`companies/detail.html`) says exactly this before this route is
    # ever reached.
    await db.delete(company)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="company.delete",
        summary=(
            f'Deleted company "{company_name}" — detached {honeypot_count} honeypot(s) '
            f"and removed {member_count} user membership(s); no honeypot or user account "
            "was deleted"
        ),
        target_type="company",
        target_id=company_id,
        target_label=company_name,
        details={"honeypot_count": honeypot_count, "member_count": member_count},
    )
    return RedirectResponse(url="/companies", status_code=status.HTTP_303_SEE_OTHER)
