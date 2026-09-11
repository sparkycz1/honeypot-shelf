"""REST API for honeypots, companies, and bulk/fleet-wide actions — for
external scripts/monitoring, authenticated with a per-user API token
(`app.auth.dependencies.get_api_token_user`/`require_api_write`), not a
browser session.

Lives under `/api/`, already on `app.auth.middleware`'s public-prefix
allowlist — same reasoning as `POST /api/inform`: a honeypot-to-honeypot
surface with its own bearer-token authentication, not a cookie-based one.

Every mutating/action endpoint here calls into the exact same service
functions the equivalent web route uses (`app.services.honeypot_actions`,
`app.ssh.updates`, ...) and requires the same write access + company scope
the web route does — this is a second door into the same house, not a
looser one.
Destructive actions that the web UI gates behind a typed confirmation
phrase require an explicit `confirm` field here instead (see each route's
docstring).

What's deliberately still web-UI-only, and why: SSH key rotation
(`/settings/ssh-key/...`), LDAP/OIDC configuration, and syslog forwarding
are excluded for the reasons given in wiki/Architecture.md's "The REST
API: read and write, mirroring the web UI" section — each one is either a
secret/credential surface or carries a lock-out/blast-radius risk that's
meant to be handled deliberately, by a human, not scriptable. The
interactive SSH terminal (`app/web/routes/terminal_ws.py`) is excluded
for a different reason: it's an inherently interactive, browser-only
feature (a live WebSocket relaying keystrokes to a PTY and a real
terminal emulator's output back) with no meaningful "REST" shape to
expose — there's nothing here for a script to call that would do anything
useful without a human driving it. `POST /{id}/run-onboarding-with-
credential` (a *fresh*, one-time password submitted through the "Fix it"
flow, not the honeypot's stored credential) is excluded for the same
secret-handling reason as SSH key rotation; `POST /{id}/run-onboarding`
(using the credential already on file) has an API equivalent below. CSV
bulk import of pending honeypots is excluded too — a script importing
honeypots already has `POST /honeypots` (or `POST /api/inform` for genuine
self-registration) and doesn't need a CSV-parsing endpoint of its own.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import uuid
from datetime import datetime

# NOT the builtin `TimeoutError` — `celery.exceptions.TimeoutError` does not
# subclass it, so catching the builtin around `AsyncResult.get(timeout=...)`
# would silently never match.
from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import get_api_token_user, require_api_superadmin, require_api_write
from app.auth.scope import (
    companies_visible_to,
    has_company_access,
    honeypots_visible_to,
    visible_honeypots_by_ids,
)
from app.core.config import get_settings
from app.core.security import encrypt_secret
from app.db.models.audit_log import AuditOutcome
from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.honeypot_package import HoneypotPackage
from app.db.models.honeypot_update_run import HoneypotUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.pending_honeypot import PendingHoneypot
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.company import CompanyCreate
from app.schemas.honeypot import HoneypotCreate, HoneypotUpdate
from app.schemas.honeypot_config import HoneypotConfigExport
from app.services.honeypot_actions import (
    send_power_to_honeypots,
    trigger_check_updates,
    trigger_updates,
)
from app.services.honeypot_config import export_honeypot_config, import_honeypot_config
from app.services.honeypot_tags import (
    add_tags_to_honeypots,
    normalize_tag_names,
    remove_tags_from_honeypots,
    set_honeypot_tags,
)
from app.ssh import logs as ssh_logs
from app.ssh.client import discover_host_key_fingerprint
from app.ssh.exceptions import SSHConnectionError
from app.ssh.packages import PackageSource
from app.ssh.power import PowerAction
from app.tasks import jobs as tasks
from app.tasks.jobs import (
    preview_honeypot_update,
    rollback_honeypot_update,
    run_honeypot_update,
    send_honeypot_power_command,
)
from app.web.honeypot_search import apply_tag_filter

router = APIRouter(prefix="/api/v1")

# debcontrol gates read vs. write vs. updates/power/terminal behind four
# separate Permissions; this app has only one write tier (READ_WRITE on
# the honeypot's/company's own company — see app.db.models.user's module
# docstring), so every "read" alias below is just "authenticated with a
# token" and every "write" alias is `require_api_write`. Kept as separate
# names anyway, matching every route below exactly the way it matched
# debcontrol's own seven, so a future re-introduction of finer-grained
# tiers touches only this one spot.
_view_honeypots = Depends(get_api_token_user)
_manage_honeypots = Depends(require_api_write)
_action_terminal = Depends(require_api_write)
# Companies are superadmin-only via the API too, matching the web UI
# (app/web/routes/companies.py) — see CLAUDE.md/wiki/Home.md's product
# decision.
_view_companies = Depends(require_api_superadmin)
_manage_companies = Depends(require_api_superadmin)
_action_updates = Depends(require_api_write)
_action_power = Depends(require_api_write)

# Fingerprint shaped like "SHA256:<base64...>", as returned by AsyncSSH/OpenSSH
# — same pattern the web UI's trust-host-key form validates against.
_FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9]+:[A-Za-z0-9+/=_-]+$")

_PACKAGE_SEARCH_LIMIT = 500
_UPDATE_RUNS_PAGE_SIZE = 50

# Fixed confirmation values an API client must echo back for a destructive
# action — the API equivalent of the web UI's typed-name confirmation page.
# "SELECTED HONEYPOTS"/"ALL HONEYPOTS" mirror the phrases the web UI itself
# uses for the same ad-hoc-selection / "All honeypots" cases.
_BULK_POWER_CONFIRM_PHRASE = "SELECTED HONEYPOTS"
_ALL_HONEYPOTS_CONFIRM_PHRASE = "ALL HONEYPOTS"


def _isoformat(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _honeypot_to_dict(honeypot: Honeypot) -> dict[str, object]:
    return {
        "id": str(honeypot.id),
        "name": honeypot.name,
        "ip_address": honeypot.ip_address,
        "port": honeypot.port,
        "username": honeypot.username,
        "auth_method": honeypot.auth_method.value if honeypot.auth_method else None,
        # A honeypot can belong to any number of companies now (including
        # none) — "company"/"company_id" (singular) are gone; every API
        # consumer reads "companies" instead.
        "companies": [{"id": str(c.id), "name": c.name} for c in honeypot.companies],
        "description": honeypot.description,
        "runbook": honeypot.runbook,
        "tags": [tag.name for tag in honeypot.tags],
        "is_active": honeypot.is_active,
        "is_reachable": honeypot.is_reachable,
        "last_ping_at": _isoformat(honeypot.last_ping_at),
        "host_key_fingerprint": honeypot.host_key_fingerprint,
        "os_version": honeypot.os_version,
        "kernel_version": honeypot.kernel_version,
        "cpu_architecture": honeypot.cpu_architecture,
        "cpu_model": honeypot.cpu_model,
        "cpu_cores": honeypot.cpu_cores,
        "ram_bytes": honeypot.ram_bytes,
        "ram_speed_mhz": honeypot.ram_speed_mhz,
        "uptime_seconds": honeypot.uptime_seconds,
        "process_count": honeypot.process_count,
        "reboot_required": honeypot.reboot_required,
        "upgradable_count": honeypot.upgradable_count,
        "security_upgradable_count": honeypot.security_upgradable_count,
        "flatpak_upgradable_count": honeypot.flatpak_upgradable_count,
        "snap_upgradable_count": honeypot.snap_upgradable_count,
        "apt_upgradable_packages": honeypot.apt_upgradable_packages,
        "flatpak_upgradable_packages": honeypot.flatpak_upgradable_packages,
        "snap_upgradable_packages": honeypot.snap_upgradable_packages,
        "updates_checked_at": _isoformat(honeypot.updates_checked_at),
        "packages_updated_at": _isoformat(honeypot.packages_updated_at),
    }


def _company_to_dict(company: Company) -> dict[str, object]:
    return {
        "id": str(company.id),
        "name": company.name,
        "notes": company.notes,
        "honeypot_count": len(company.honeypots),
    }


def _package_to_dict(pkg: HoneypotPackage, *, include_honeypot: bool = False) -> dict[str, object]:
    data: dict[str, object] = {
        "id": str(pkg.id),
        "honeypot_id": str(pkg.honeypot_id),
        "source": pkg.source.value,
        "name": pkg.name,
        "version": pkg.version,
        "held": pkg.held,
    }
    if include_honeypot:
        data["honeypot_name"] = pkg.honeypot.name if pkg.honeypot else None
    return data


def _update_run_to_dict(run: HoneypotUpdateRun) -> dict[str, object]:
    return {
        "id": str(run.id),
        "honeypot_id": str(run.honeypot_id),
        "batch_id": str(run.batch_id) if run.batch_id else None,
        "strategy": run.strategy.value,
        "status": run.status.value,
        "output": run.output,
        "error": run.error,
        # Not the raw snapshot (a full package list per run is a lot to hand
        # back for something most callers only need as a yes/no) — just
        # whether "Roll back this update" is available for this run.
        "has_package_snapshot": run.package_snapshot is not None,
        "rollback_of_run_id": str(run.rollback_of_run_id) if run.rollback_of_run_id else None,
        "started_at": _isoformat(run.started_at),
        "finished_at": _isoformat(run.finished_at),
        "created_at": _isoformat(run.created_at),
    }


async def _get_honeypot_or_404(honeypot_id: uuid.UUID, db: AsyncSession, user: User) -> Honeypot:
    """Scoped exactly like the web UI's equivalent helper — a token whose
    account is restricted to specific honeypot companies gets a 404, not a 403
    and certainly not the data, for anything outside them. This API is "a
    second door into the same house, not a looser one" (see the module
    docstring), and that applies to visibility scoping too."""
    query = honeypots_visible_to(user)
    result = await db.execute(query.where(Honeypot.id == honeypot_id))
    honeypot = result.scalar_one_or_none()
    if honeypot is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Honeypot not found.")
    return honeypot


async def _get_company_or_404(company_id: uuid.UUID, db: AsyncSession, user: User) -> Company:
    query = companies_visible_to(user)
    result = await db.execute(
        query.options(selectinload(Company.honeypots)).where(Company.id == company_id)
    )
    company = result.scalar_one_or_none()
    if company is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Company not found.")
    return company


async def _require_companies_in_scope(
    db: AsyncSession, user: User, company_ids: list[uuid.UUID]
) -> list[Company]:
    """A company-scoped account may only file a honeypot into companies it
    can write — any number, including none (see
    app/db/models/company.py's module docstring). A 403 rather than a
    404: the caller submitted these ids itself, so there is nothing left
    to conceal. Returns the resolved `Company` rows (also validates every
    id actually exists)."""
    for company_id in company_ids:
        if not has_company_access(user, company_id, write=True):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail='"company_ids" must only name companies this account has write access to.',
            )
    result = await db.execute(select(Company).where(Company.id.in_(company_ids)))
    return list(result.scalars().all())


async def _visible_honeypots(db: AsyncSession, user: User) -> list[Honeypot]:
    """Every honeypot this token's account can see — what "All honeypots"
    means for it. Same reasoning as the web UI's `_all_visible_honeypots`."""
    result = await db.execute(honeypots_visible_to(user))
    return list(result.scalars().all())


# --- Honeypots: reads --------------------------------------------------------


@router.get("/honeypots", dependencies=[_view_honeypots])
async def list_honeypots_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
    tag: list[str] = Query(default=[]),
    tag_mode: str = "or",
) -> list[dict[str, object]]:
    query = honeypots_visible_to(user)
    query = apply_tag_filter(query, tag, tag_mode if tag_mode == "and" else "or")
    result = await db.execute(query)
    return [_honeypot_to_dict(m) for m in result.scalars().all()]


@router.get("/honeypots/package-search", dependencies=[_view_honeypots])
async def package_search_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
    q: str = "",
    pkg_source: str = "",
) -> dict[str, object]:
    """Fleet-wide package search — the API equivalent of `GET
    /honeypots/package-search`. See that route for the reasoning behind the
    500-row cap."""
    if not q.strip():
        return {"results": [], "truncated": False}
    visible_ids = (honeypots_visible_to(user)).with_only_columns(Honeypot.id)
    query = (
        select(HoneypotPackage)
        .options(selectinload(HoneypotPackage.honeypot))
        .where(
            HoneypotPackage.name.ilike(f"%{q.strip()}%"),
            HoneypotPackage.honeypot_id.in_(visible_ids),
        )
    )
    if pkg_source in {source.value for source in PackageSource}:
        query = query.where(HoneypotPackage.source == PackageSource(pkg_source))
    query = query.order_by(HoneypotPackage.name).limit(_PACKAGE_SEARCH_LIMIT + 1)
    result = await db.execute(query)
    results = list(result.scalars().all())
    truncated = len(results) > _PACKAGE_SEARCH_LIMIT
    results = results[:_PACKAGE_SEARCH_LIMIT]
    return {
        "results": [_package_to_dict(p, include_honeypot=True) for p in results],
        "truncated": truncated,
    }


@router.get("/honeypots/config/export", dependencies=[_view_honeypots])
async def export_honeypot_config_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> HoneypotConfigExport:
    """The API equivalent of `GET /honeypots/config/export?format=json` — see
    `app.services.honeypot_config`'s module docstring for exactly what's
    included/excluded and why. No CSV variant here (the web UI's is a plain
    download link for a browser; a script consuming this API wants JSON)."""
    return await export_honeypot_config(db, user)


@router.post("/honeypots/config/import", dependencies=[_manage_honeypots])
async def import_honeypot_config_api(
    request: Request, payload: HoneypotConfigExport, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    """The API equivalent of `POST /honeypots/config/import` — same
    conflict-handling/security policy, see `app.services.honeypot_config`."""
    result = await import_honeypot_config(db, payload)
    await log_event(
        db,
        request=request,
        action="honeypot.config_import",
        summary=result.summary(),
        details=result.to_dict(),
    )
    return result.to_dict()


# --- Pending honeypots (self-registration review queue) -----------------------
# Registered here, before `/honeypots/{honeypot_id}` below, so "pending" is
# never swallowed as an attempted (and invalid) honeypot UUID — FastAPI/
# Starlette matches path routes in registration order and commits to the
# first one whose shape fits, same reasoning as `/honeypots/package-search`
# and `/honeypots/config/export` above.


def _pending_honeypot_to_dict(pending: PendingHoneypot) -> dict[str, object]:
    return {
        "id": str(pending.id),
        "ip_address": pending.ip_address,
        "reported_hostname": pending.reported_hostname,
        "os_version": pending.os_version,
        "kernel_version": pending.kernel_version,
        "cpu_cores": pending.cpu_cores,
        "ram_bytes": pending.ram_bytes,
        "disks": pending.disks,
        "source_ip": pending.source_ip,
        "created_at": _isoformat(pending.created_at),
    }


@router.get("/honeypots/pending", dependencies=[_view_honeypots])
async def list_pending_honeypots_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, object]]:
    """Honeypots that announced themselves via `POST /api/inform` and are
    awaiting review — see `app.db.models.pending_honeypot`'s module
    docstring. Not scoped by honeypot company: a pending entry isn't a real
    `Honeypot` yet, so there's nothing to scope against."""
    result = await db.execute(select(PendingHoneypot).order_by(PendingHoneypot.created_at.desc()))
    return [_pending_honeypot_to_dict(p) for p in result.scalars().all()]


@router.post("/honeypots/pending/{pending_id}/dismiss", dependencies=[_manage_honeypots])
async def dismiss_pending_honeypot_api(
    request: Request,
    pending_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    pending = await db.get(PendingHoneypot, pending_id)
    if pending is not None:
        await db.delete(pending)
        await db.commit()
        await log_event(
            db,
            request=request,
            action="honeypot.pending.dismiss",
            summary=f'Dismissed pending honeypot "{pending.ip_address}"',
            target_type="pending_honeypot",
            target_id=pending_id,
            target_label=pending.ip_address,
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/honeypots/{honeypot_id}", dependencies=[_view_honeypots])
async def get_honeypot_api(
    honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    return _honeypot_to_dict(await _get_honeypot_or_404(honeypot_id, db, user))


@router.get("/honeypots/{honeypot_id}/packages", dependencies=[_view_honeypots])
async def list_honeypot_packages_api(
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    q: str = "",
    pkg_source: str = "",
    held_only: bool = False,
    user: User = Depends(get_api_token_user),
) -> list[dict[str, object]]:
    await _get_honeypot_or_404(honeypot_id, db, user)
    query = select(HoneypotPackage).where(HoneypotPackage.honeypot_id == honeypot_id)
    if q.strip():
        query = query.where(HoneypotPackage.name.ilike(f"%{q.strip()}%"))
    if pkg_source in {source.value for source in PackageSource}:
        query = query.where(HoneypotPackage.source == PackageSource(pkg_source))
    if held_only:
        query = query.where(HoneypotPackage.held.is_(True))
    result = await db.execute(query.order_by(HoneypotPackage.source, HoneypotPackage.name))
    return [_package_to_dict(p) for p in result.scalars().all()]


@router.get("/honeypots/{honeypot_id}/packages/held", dependencies=[_view_honeypots])
async def list_honeypot_held_packages_api(
    honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, object]]:
    await _get_honeypot_or_404(honeypot_id, db, user)
    result = await db.execute(
        select(HoneypotPackage)
        .where(HoneypotPackage.honeypot_id == honeypot_id, HoneypotPackage.held.is_(True))
        .order_by(HoneypotPackage.name)
    )
    return [_package_to_dict(p) for p in result.scalars().all()]


@router.get("/honeypots/{honeypot_id}/update-runs", dependencies=[_view_honeypots])
async def list_honeypot_update_runs_api(
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    status_filter: str = "",
    page: int = 1,
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """The API equivalent of `GET /honeypots/{id}/updates` — every update run
    for this honeypot, newest first, paginated/filterable the same way."""
    await _get_honeypot_or_404(honeypot_id, db, user)
    page = max(page, 1)

    query = select(HoneypotUpdateRun).where(HoneypotUpdateRun.honeypot_id == honeypot_id)
    if status_filter in {s.value for s in UpdateRunStatus}:
        query = query.where(HoneypotUpdateRun.status == UpdateRunStatus(status_filter))

    offset = (page - 1) * _UPDATE_RUNS_PAGE_SIZE
    result = await db.execute(
        query.order_by(HoneypotUpdateRun.created_at.desc())
        .offset(offset)
        .limit(_UPDATE_RUNS_PAGE_SIZE + 1)
    )
    runs = list(result.scalars().all())
    has_older = len(runs) > _UPDATE_RUNS_PAGE_SIZE
    runs = runs[:_UPDATE_RUNS_PAGE_SIZE]
    return {
        "runs": [_update_run_to_dict(r) for r in runs],
        "page": page,
        "has_older": has_older,
    }


# --- Honeypots: writes --------------------------------------------------------


@router.post("/honeypots", dependencies=[_manage_honeypots], status_code=status.HTTP_201_CREATED)
async def create_honeypot_api(
    request: Request, payload: HoneypotCreate, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    companies = await _require_companies_in_scope(db, user, payload.company_ids)
    honeypot = Honeypot(
        name=payload.name,
        ip_address=payload.ip_address,
        port=payload.port,
        username=payload.username,
        auth_method=payload.auth_method,
        secret_encrypted=encrypt_secret(payload.secret) if payload.secret else None,
        companies=companies,
        description=payload.description,
        runbook=payload.runbook,
    )
    db.add(honeypot)
    await db.commit()
    await db.refresh(honeypot)
    honeypot = await _get_honeypot_or_404(honeypot.id, db, user)
    await set_honeypot_tags(db, honeypot, payload.tags)
    await db.commit()
    honeypot = await _get_honeypot_or_404(honeypot.id, db, user)

    await log_event(
        db,
        request=request,
        action="honeypot.create",
        summary=f'Created honeypot "{honeypot.name}" ({honeypot.ip_address})',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
    )
    return _honeypot_to_dict(honeypot)


@router.put("/honeypots/{honeypot_id}", dependencies=[_manage_honeypots])
async def update_honeypot_api(
    request: Request,
    honeypot_id: uuid.UUID,
    payload: HoneypotUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    companies = await _require_companies_in_scope(db, user, payload.company_ids)
    # Preserve any company this honeypot is *also* attached to outside this
    # token's write scope, invisible to (and unvalidated by) the call above
    # — same reasoning as the web UI's edit form, never silently detach
    # what this request couldn't see in the first place.
    outside_scope = [
        c for c in honeypot.companies if not has_company_access(user, c.id, write=True)
    ]
    companies = companies + [c for c in outside_scope if c not in companies]

    connection_target_changed = (
        payload.ip_address != honeypot.ip_address or payload.port != honeypot.port
    )

    honeypot.name = payload.name
    honeypot.ip_address = payload.ip_address
    honeypot.port = payload.port
    honeypot.username = payload.username
    honeypot.auth_method = payload.auth_method
    honeypot.companies = companies
    honeypot.description = payload.description
    honeypot.runbook = payload.runbook
    honeypot.is_active = payload.is_active
    await set_honeypot_tags(db, honeypot, payload.tags)

    if payload.auth_method == AuthMethod.PASSWORD:
        if payload.secret:
            honeypot.secret_encrypted = encrypt_secret(payload.secret)
    else:
        honeypot.secret_encrypted = None

    if connection_target_changed:
        honeypot.host_key_fingerprint = None
        honeypot.discovered_hostname = None
        honeypot.os_version = None
        honeypot.os_id = None
        honeypot.kernel_version = None
        honeypot.cpu_cores = None
        honeypot.cpu_model = None
        honeypot.ram_bytes = None
        honeypot.ram_speed_mhz = None
        honeypot.disks = None
        honeypot.facts_updated_at = None

    await db.commit()
    honeypot = await _get_honeypot_or_404(honeypot.id, db, user)

    await log_event(
        db,
        request=request,
        action="honeypot.update",
        summary=f'Updated honeypot "{honeypot.name}"',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"connection_target_changed": connection_target_changed},
    )
    return _honeypot_to_dict(honeypot)


class _ConfirmDelete(BaseModel):
    """Echoing the target's own name back is the API equivalent of the web
    UI's typed-confirmation page for an irreversible action."""

    confirm_name: str = Field(min_length=1)


@router.delete("/honeypots/{honeypot_id}", dependencies=[_manage_honeypots])
async def delete_honeypot_api(
    request: Request,
    honeypot_id: uuid.UUID,
    payload: _ConfirmDelete,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    if payload.confirm_name.strip() != honeypot.name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f'"confirm_name" must exactly match the honeypot\'s name ("{honeypot.name}").',
        )
    honeypot_name = honeypot.name
    await db.delete(honeypot)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="honeypot.delete",
        summary=f'Deleted honeypot "{honeypot_name}"',
        target_type="honeypot",
        target_id=honeypot_id,
        target_label=honeypot_name,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Honeypots: on-demand checks and refreshes --------------------------------
# Each of these blocks on the same background job the web UI's equivalent
# button waits for, and returns once it's done rather than requiring the
# caller to poll — see each web route in `app/web/routes/honeypots.py` for
# the identical pattern this mirrors.


@router.post("/honeypots/{honeypot_id}/test-connection", dependencies=[_manage_honeypots])
async def test_connection_api(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    settings = get_settings()

    async_result = tasks.test_honeypot_connection.delay(str(honeypot.id))
    result: dict[str, object] | None = None
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 5
        )
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.test_connection",
        summary=f'Tested connection to "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return result or {"ok": True}


@router.post("/honeypots/{honeypot_id}/discover-host-key", dependencies=[_manage_honeypots])
async def discover_host_key_api(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    settings = get_settings()

    fingerprint: str | None = None
    error: str | None = None
    if not honeypot.ip_address:
        error = "This honeypot has no IP address configured."
    else:
        try:
            fingerprint = await discover_host_key_fingerprint(
                honeypot.ip_address, honeypot.port, settings.ssh_connect_timeout
            )
        except SSHConnectionError as exc:
            error = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.host_key.discover",
        summary=f'Discovered host key fingerprint for "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {"fingerprint": fingerprint}


class _TrustHostKey(BaseModel):
    fingerprint: str = Field(min_length=1)


@router.post("/honeypots/{honeypot_id}/trust-host-key", dependencies=[_manage_honeypots])
async def trust_host_key_api(
    request: Request,
    honeypot_id: uuid.UUID,
    payload: _TrustHostKey,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    fingerprint = payload.fingerprint.strip()
    if not _FINGERPRINT_RE.match(fingerprint):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid fingerprint format."
        )
    honeypot.host_key_fingerprint = fingerprint
    await db.commit()

    await log_event(
        db,
        request=request,
        action="honeypot.host_key.trust",
        summary=f'Trusted host key fingerprint for "{honeypot.name}"',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"fingerprint": fingerprint},
    )
    # Same follow-up the web UI's equivalent kicks off: an initial facts pass
    # and a readiness check, both fire-and-forget.
    tasks.refresh_honeypot_facts.delay(str(honeypot.id))
    tasks.check_honeypot_readiness.delay(str(honeypot.id))
    return {"ok": True}


@router.post("/honeypots/{honeypot_id}/refresh-facts", dependencies=[_manage_honeypots])
async def refresh_facts_api(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    settings = get_settings()

    async_result = tasks.refresh_honeypot_facts.delay(str(honeypot.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 5
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        error = str(exc)

    if error is None:
        honeypot = await _get_honeypot_or_404(honeypot_id, db, user)

    await log_event(
        db,
        request=request,
        action="honeypot.facts.refresh",
        summary=f'Refreshed facts for "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return _honeypot_to_dict(honeypot)


@router.post("/honeypots/{honeypot_id}/refresh-packages", dependencies=[_manage_honeypots])
async def refresh_packages_api(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    settings = get_settings()

    async_result = tasks.refresh_honeypot_packages.delay(str(honeypot.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 15
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.packages.refresh",
        summary=f'Refreshed installed packages for "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {"ok": True}


@router.post("/honeypots/{honeypot_id}/refresh-services", dependencies=[_manage_honeypots])
async def refresh_services_api(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    settings = get_settings()

    async_result = tasks.refresh_honeypot_services.delay(str(honeypot.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 15
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.services.refresh",
        summary=f'Refreshed services for "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {"ok": True}


@router.post("/honeypots/{honeypot_id}/run-onboarding", dependencies=[_manage_honeypots])
async def run_onboarding_api(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Runs initial setup using the credential already stored on the
    honeypot record. See this module's docstring for why the "Fix it"
    variant that submits a fresh one-time credential is not exposed here."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    settings = get_settings()

    async_result = tasks.run_honeypot_onboarding.delay(str(honeypot.id))
    error: str | None = None
    output: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 120
        )
        if isinstance(result, dict):
            if result.get("ok"):
                output = str(result.get("output") or "")
            else:
                error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The setup script did not finish in time."
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.onboarding.run",
        summary=f'Ran initial setup on "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )
    if error is None:
        tasks.check_honeypot_readiness.delay(str(honeypot.id))
    else:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {"ok": True, "output": output}


@router.post("/honeypots/{honeypot_id}/fix-readiness-directly", dependencies=[_manage_honeypots])
async def fix_readiness_directly_api(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Installs `ncurses-term` using the credential already stored on the
    honeypot record — the readiness banner's "Install now" button for a
    honeypot connected as root, where there is no sudo gap left to fix (see
    `app.ssh.readiness`'s module docstring). Uses only the credential
    already on file, same as `run_onboarding_api` above, so it's exposed
    here for the same reason that one is."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    settings = get_settings()

    async_result = tasks.fix_root_readiness.delay(str(honeypot.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 60
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "Timed out."
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.readiness.fix_directly",
        summary=f'Installed missing readiness packages directly on "{honeypot.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"error": error} if error else None,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {"ok": True}


@router.post("/honeypots/{honeypot_id}/recheck-readiness", dependencies=[_manage_honeypots])
async def recheck_readiness_api(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    settings = get_settings()

    async_result = tasks.check_honeypot_readiness.delay(str(honeypot.id))
    with contextlib.suppress(Exception):
        await asyncio.to_thread(async_result.get, timeout=settings.ssh_connect_timeout + 15)
    return {"ok": True}


@router.get("/honeypots/{honeypot_id}/logs", dependencies=[_action_terminal])
async def honeypot_logs_api(
    request: Request,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    path: str = "",
    lines: int = ssh_logs.DEFAULT_LINE_LIMIT,
    search: str = "",
    since: str = "",
    until: str = "",
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """The API equivalent of `GET /honeypots/{id}/logs` — journal by default,
    or one allow-listed file when `path` is given. Gated behind
    `ACTION_TERMINAL`, same as the web route, not `HONEYPOT_VIEW` — see
    `app.ssh.logs`'s module docstring for why. Never stored anywhere."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    settings = get_settings()

    if not honeypot.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before viewing logs.",
        )

    clamped_lines = max(1, min(lines, ssh_logs.MAX_LINE_LIMIT))
    output: str | None = None
    error: str | None = None
    try:
        if path.strip():
            async_result = tasks.view_honeypot_log_file.delay(
                str(honeypot.id), path=path.strip(), lines=clamped_lines, search=search
            )
        else:
            async_result = tasks.view_honeypot_journal.delay(
                str(honeypot.id), lines=clamped_lines, search=search, since=since, until=until
            )
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 15
        )
        if isinstance(result, dict):
            if result.get("ok"):
                output = str(result.get("output") or "")
            else:
                error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The command did not finish in time."
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="honeypot.logs.view",
        summary=(
            f'Viewed log file "{path.strip()}" on "{honeypot.name}"'
            if path.strip()
            else f'Viewed journal on "{honeypot.name}"'
        ),
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"search": search} if search.strip() else None,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {"output": output or ""}


# --- Bulk actions (ad-hoc selection from the honeypot list) ------------------


class _BulkHoneypotIds(BaseModel):
    honeypot_ids: list[uuid.UUID] = Field(min_length=1)


class _BulkUpdatesTrigger(_BulkHoneypotIds):
    strategy: UpgradeStrategy


class _BulkPowerAction(_BulkHoneypotIds):
    action: PowerAction
    confirm: str = Field(
        min_length=1,
        description=f'Must be exactly "{_BULK_POWER_CONFIRM_PHRASE}" to confirm.',
    )


class _BulkTags(_BulkHoneypotIds):
    tags: list[str] = Field(min_length=1)

    @field_validator("tags")
    @classmethod
    def _normalize_tags(cls, value: list[str]) -> list[str]:
        return normalize_tag_names(value)


async def _get_honeypots_by_ids(
    honeypot_ids: list[uuid.UUID], db: AsyncSession, user: User
) -> list[Honeypot]:
    """Submitted ids, minus anything outside this account's scope — dropped
    silently, same as the web UI's bulk endpoints."""
    return await visible_honeypots_by_ids(db, user, honeypot_ids)


@router.post("/honeypots/bulk/check-updates", dependencies=[_action_updates])
async def bulk_check_updates_api(
    request: Request, payload: _BulkHoneypotIds, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    honeypots = await _get_honeypots_by_ids(payload.honeypot_ids, db, user)
    skipped = await trigger_check_updates(honeypots)
    await log_event(
        db,
        request=request,
        action="honeypots.bulk.updates.check",
        summary=f"Checked for updates on {len(honeypots)} selected honeypot(s)",
        details={"honeypot_count": len(honeypots), "skipped": skipped},
    )
    return {"honeypot_count": len(honeypots), "skipped": skipped}


@router.post("/honeypots/bulk/updates", dependencies=[_action_updates])
async def bulk_trigger_updates_api(
    request: Request, payload: _BulkUpdatesTrigger, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    honeypots = await _get_honeypots_by_ids(payload.honeypot_ids, db, user)
    batch_id, skipped = await trigger_updates(db, honeypots, payload.strategy)
    await log_event(
        db,
        request=request,
        action="honeypots.bulk.updates.run",
        summary=(
            f'Triggered {payload.strategy.value.replace("_", "-")} on '
            f"{len(honeypots)} selected honeypot(s)"
        ),
        details={"strategy": payload.strategy.value, "batch_id": str(batch_id), "skipped": skipped},
    )
    return {"batch_id": str(batch_id), "skipped": skipped}


@router.post("/honeypots/bulk/power", dependencies=[_action_power])
async def bulk_power_action_api(
    request: Request, payload: _BulkPowerAction, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    if payload.confirm.strip() != _BULK_POWER_CONFIRM_PHRASE:
        await log_event(
            db,
            request=request,
            action=f"honeypots.bulk.power.{payload.action.value}",
            summary=(
                f"Blocked {payload.action.value} on {len(payload.honeypot_ids)} selected "
                "honeypot(s): confirmation mismatch"
            ),
            outcome=AuditOutcome.DENIED,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f'"confirm" must be exactly "{_BULK_POWER_CONFIRM_PHRASE}".',
        )
    honeypots = await _get_honeypots_by_ids(payload.honeypot_ids, db, user)
    skipped = await send_power_to_honeypots(honeypots, payload.action)
    await log_event(
        db,
        request=request,
        action=f"honeypots.bulk.power.{payload.action.value}",
        summary=f"Sent {payload.action.value} to {len(honeypots)} selected honeypot(s)",
        details={"skipped": skipped},
    )
    return {"honeypot_count": len(honeypots), "skipped": skipped}


@router.post("/honeypots/bulk/tags/add", dependencies=[_manage_honeypots])
async def bulk_add_tags_api(
    request: Request, payload: _BulkTags, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Add `payload.tags` to every honeypot in `payload.honeypot_ids`, leaving
    each honeypot's other tags untouched — the API equivalent of the honeypot
    list's bulk "Add tags" button."""
    honeypots = await _get_honeypots_by_ids(payload.honeypot_ids, db, user)
    await add_tags_to_honeypots(db, [m.id for m in honeypots], payload.tags)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="honeypots.bulk.tags.add",
        summary=(
            f'Added tag(s) {", ".join(payload.tags)} to {len(honeypots)} selected honeypot(s)'
        ),
        details={"tags": payload.tags, "honeypot_count": len(honeypots)},
    )
    return {"honeypot_count": len(honeypots), "tags": payload.tags}


@router.post("/honeypots/bulk/tags/remove", dependencies=[_manage_honeypots])
async def bulk_remove_tags_api(
    request: Request, payload: _BulkTags, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Remove `payload.tags` from every honeypot in `payload.honeypot_ids` —
    a no-op for any honeypot that didn't have a given tag, never an error."""
    honeypots = await _get_honeypots_by_ids(payload.honeypot_ids, db, user)
    await remove_tags_from_honeypots(db, [m.id for m in honeypots], payload.tags)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="honeypots.bulk.tags.remove",
        summary=(
            f'Removed tag(s) {", ".join(payload.tags)} from {len(honeypots)} selected honeypot(s)'
        ),
        details={"tags": payload.tags, "honeypot_count": len(honeypots)},
    )
    return {"honeypot_count": len(honeypots), "tags": payload.tags}


@router.get("/honeypots/{honeypot_id}/updates/preview", dependencies=[_action_updates])
async def preview_honeypot_update_api(
    request: Request,
    honeypot_id: uuid.UUID,
    strategy: UpgradeStrategy = UpgradeStrategy.DIST_UPGRADE,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """The API equivalent of the web UI's `GET /honeypots/{id}/updates/preview`
    — a dry-run simulation (apt's `-s` flag; nothing on the honeypot changes)
    of what `POST /honeypots/{id}/updates` would do, most importantly what
    `autoremove` would remove.

    Unlike the web UI, `POST /honeypots/{id}/updates` below is **not** forced
    through this preview first — a scripted/API caller presumably already
    knows what it's asking for (that's the whole point of automating it),
    the same reasoning that already applies to every other unconfirmed
    single-honeypot trigger in this file. This preview is offered as an
    optional tool for a caller that *wants* to check before triggering (or
    wants to render its own preview UI), not a mandatory gate — see this
    module's docstring for how that compares to the destructive actions
    here that *do* require an explicit `confirm`/`confirm_name` field."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    if not honeypot.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before previewing updates.",
        )

    async_result = preview_honeypot_update.delay(str(honeypot.id), strategy.value)
    settings = get_settings()
    try:
        # `AsyncResult.get()` is a blocking, synchronous call — off the event
        # loop it goes, or it would stall every other in-flight request for
        # as long as this preview takes.
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.update_timeout_seconds + 5
        )
    except CeleryTimeoutError as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="The background job did not respond in time.",
        ) from exc
    if not isinstance(result, dict) or not result.get("ok"):
        error = str(result.get("error")) if isinstance(result, dict) else "Unknown error."
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {
        "to_install_or_upgrade": result.get("to_install_or_upgrade") or [],
        "to_remove": result.get("to_remove") or [],
    }


class _UpdatesTrigger(BaseModel):
    strategy: UpgradeStrategy


@router.post("/honeypots/{honeypot_id}/updates", dependencies=[_action_updates])
async def trigger_honeypot_update_api(
    request: Request,
    honeypot_id: uuid.UUID,
    payload: _UpdatesTrigger,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    if not honeypot.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before running updates.",
        )
    run = HoneypotUpdateRun(honeypot_id=honeypot.id, strategy=payload.strategy)
    db.add(run)
    await db.commit()
    await db.refresh(run)
    run_honeypot_update.delay(str(run.id))

    await log_event(
        db,
        request=request,
        action="honeypot.updates.run",
        summary=f'Triggered {payload.strategy.value.replace("_", "-")} on "{honeypot.name}"',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"strategy": payload.strategy.value, "run_id": str(run.id)},
    )
    return _update_run_to_dict(run)


@router.post("/honeypots/{honeypot_id}/updates/{run_id}/rollback", dependencies=[_action_updates])
async def rollback_honeypot_update_api(
    request: Request,
    honeypot_id: uuid.UUID,
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """The API equivalent of `POST /honeypots/{id}/updates/{run_id}/rollback`
    — see `app/web/routes/honeypots.py`'s `rollback_honeypot_update_endpoint`
    and `app.tasks.jobs._rollback_honeypot_update`."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    source_run = await db.get(HoneypotUpdateRun, run_id)
    if source_run is None or source_run.honeypot_id != honeypot.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Update run not found.")
    if source_run.status != UpdateRunStatus.SUCCEEDED or not source_run.package_snapshot:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This update run has no captured package snapshot to roll back to.",
        )
    if source_run.rollback_of_run_id is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Can't roll back a rollback."
        )

    rollback_run = HoneypotUpdateRun(
        honeypot_id=honeypot.id, strategy=source_run.strategy, rollback_of_run_id=source_run.id
    )
    db.add(rollback_run)
    await db.commit()
    await db.refresh(rollback_run)
    rollback_honeypot_update.delay(str(rollback_run.id))

    await log_event(
        db,
        request=request,
        action="honeypot.updates.rollback",
        summary=f'Triggered rollback of update run {source_run.id} on "{honeypot.name}"',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"source_run_id": str(source_run.id), "rollback_run_id": str(rollback_run.id)},
    )
    return _update_run_to_dict(rollback_run)


@router.post("/honeypots/{honeypot_id}/check-updates", dependencies=[_action_updates])
async def check_honeypot_updates_api(
    request: Request, honeypot_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    skipped = await trigger_check_updates([honeypot])
    await log_event(
        db,
        request=request,
        action="honeypot.updates.check",
        summary=f'Checked for updates on "{honeypot.name}"',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
        details={"skipped": skipped},
    )
    return {"skipped": skipped}


class _PowerAction(BaseModel):
    action: PowerAction
    confirm_name: str = Field(min_length=1)


@router.post("/honeypots/{honeypot_id}/power", dependencies=[_action_power])
async def honeypot_power_api(
    request: Request,
    honeypot_id: uuid.UUID,
    payload: _PowerAction,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    if payload.confirm_name.strip() != honeypot.name:
        await log_event(
            db,
            request=request,
            action=f"honeypot.power.{payload.action.value}",
            summary=f'Blocked {payload.action.value} on "{honeypot.name}": confirmation mismatch',
            outcome=AuditOutcome.DENIED,
            target_type="honeypot",
            target_id=honeypot.id,
            target_label=honeypot.name,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f'"confirm_name" must exactly match the honeypot\'s name ("{honeypot.name}").',
        )
    if not honeypot.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before sending power commands.",
        )
    send_honeypot_power_command.delay(str(honeypot.id), payload.action.value)
    await log_event(
        db,
        request=request,
        action=f"honeypot.power.{payload.action.value}",
        summary=f'Sent {payload.action.value} to "{honeypot.name}"',
        target_type="honeypot",
        target_id=honeypot.id,
        target_label=honeypot.name,
    )
    return {"ok": True}




# --- Honeypot companies ----------------------------------------------------------


@router.get("/companies", dependencies=[_view_companies])
async def list_companies_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, object]]:
    query = (companies_visible_to(user)).options(selectinload(Company.honeypots))
    result = await db.execute(query)
    return [_company_to_dict(g) for g in result.scalars().all()]


@router.post(
    "/companies", dependencies=[_manage_companies], status_code=status.HTTP_201_CREATED
)
async def create_company_api(
    request: Request, payload: CompanyCreate, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    company = Company(name=payload.name, notes=payload.notes)
    db.add(company)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'A company named "{payload.name}" already exists.',
        ) from None
    company = await _get_company_or_404(company.id, db, user)
    await log_event(
        db,
        request=request,
        action="company.create",
        summary=f'Created company "{company.name}"',
        target_type="company",
        target_id=company.id,
        target_label=company.name,
    )
    return _company_to_dict(company)


@router.get("/companies/{company_id}", dependencies=[_view_companies])
async def get_company_api(
    company_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    return _company_to_dict(await _get_company_or_404(company_id, db, user))


@router.get("/companies/{company_id}/members", dependencies=[_view_companies])
async def list_company_members_api(
    company_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, object]]:
    company = await _get_company_or_404(company_id, db, user)
    return [_honeypot_to_dict(h) for h in company.honeypots]


@router.put("/companies/{company_id}", dependencies=[_manage_companies])
async def update_company_api(
    request: Request,
    company_id: uuid.UUID,
    payload: CompanyCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    company = await _get_company_or_404(company_id, db, user)
    company.name = payload.name
    company.notes = payload.notes
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'A company named "{payload.name}" already exists.',
        ) from None
    company = await _get_company_or_404(company.id, db, user)
    await log_event(
        db,
        request=request,
        action="company.update",
        summary=f'Updated company "{company.name}"',
        target_type="company",
        target_id=company.id,
        target_label=company.name,
    )
    return _company_to_dict(company)


@router.delete("/companies/{company_id}", dependencies=[_manage_companies])
async def delete_company_api(
    request: Request, company_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    company = await _get_company_or_404(company_id, db, user)
    company_name = company.name
    honeypot_count = len(company.honeypots)
    member_count = len(company.memberships)
    # Only removes *links* — this company's `CompanyMembership` and
    # `honeypot_companies` rows — never a honeypot or user account itself.
    # See app/web/routes/companies.py's delete_company for the full
    # reasoning.
    await db.delete(company)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="company.delete",
        summary=(
            f'Deleted company "{company_name}" — detached {honeypot_count} honeypot(s) '
            f"and removed {member_count} user membership(s)"
        ),
        target_type="company",
        target_id=company_id,
        target_label=company_name,
        details={"honeypot_count": honeypot_count},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# Note: no POST/DELETE .../honeypots membership endpoints here (yet) — a
# honeypot's company set can be changed via `PUT /api/v1/honeypots/{id}`
# (its `company_ids` field, replacing the whole set), same as the web UI's
# create/edit forms. The web UI's company detail page additionally offers
# a one-at-a-time attach/detach action
# (`app/web/routes/companies.py`'s `attach_existing_honeypot`/
# `detach_honeypot`) with no REST equivalent yet.


# --- "All honeypots" (the built-in virtual company) -----------------------------


@router.post("/companies/all/updates", dependencies=[_action_updates])
async def trigger_all_honeypots_update_api(
    request: Request,
    payload: _UpdatesTrigger,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    honeypots = await _visible_honeypots(db, user)
    batch_id, skipped = await trigger_updates(db, honeypots, payload.strategy)
    await log_event(
        db,
        request=request,
        action="all_honeypots.updates.run",
        summary=f"Triggered {payload.strategy.value.replace('_', '-')} on all honeypots",
        target_type="all_honeypots",
        details={"strategy": payload.strategy.value, "batch_id": str(batch_id), "skipped": skipped},
    )
    return {"batch_id": str(batch_id), "skipped": skipped}


@router.post("/companies/all/check-updates", dependencies=[_action_updates])
async def trigger_all_check_updates_api(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    skipped = await trigger_check_updates(await _visible_honeypots(db, user))
    await log_event(
        db,
        request=request,
        action="all_honeypots.updates.check",
        summary="Checked for updates on all honeypots",
        target_type="all_honeypots",
        details={"skipped": skipped},
    )
    return {"skipped": skipped}


class _AllHoneypotsPowerAction(BaseModel):
    action: PowerAction
    confirm: str = Field(
        min_length=1, description=f'Must be exactly "{_ALL_HONEYPOTS_CONFIRM_PHRASE}" to confirm.'
    )


@router.post("/companies/all/power", dependencies=[_action_power])
async def all_power_action_api(
    request: Request,
    payload: _AllHoneypotsPowerAction,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    if payload.confirm.strip() != _ALL_HONEYPOTS_CONFIRM_PHRASE:
        await log_event(
            db,
            request=request,
            action=f"all_honeypots.power.{payload.action.value}",
            summary=f"Blocked {payload.action.value} on all honeypots: confirmation mismatch",
            outcome=AuditOutcome.DENIED,
            target_type="all_honeypots",
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f'"confirm" must be exactly "{_ALL_HONEYPOTS_CONFIRM_PHRASE}".',
        )
    honeypots = await _visible_honeypots(db, user)
    skipped = await send_power_to_honeypots(honeypots, payload.action)
    await log_event(
        db,
        request=request,
        action=f"all_honeypots.power.{payload.action.value}",
        summary=f"Sent {payload.action.value} to all honeypots",
        target_type="all_honeypots",
        details={"skipped": skipped},
    )
    return {"ok": True, "skipped": skipped}


@router.post("/companies/{company_id}/updates", dependencies=[_action_updates])
async def trigger_company_update_api(
    request: Request,
    company_id: uuid.UUID,
    payload: _UpdatesTrigger,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    company = await _get_company_or_404(company_id, db, user)
    batch_id, skipped = await trigger_updates(db, company.honeypots, payload.strategy)
    await log_event(
        db,
        request=request,
        action="company.updates.run",
        summary=f'Triggered {payload.strategy.value.replace("_", "-")} on company "{company.name}"',
        target_type="company",
        target_id=company.id,
        target_label=company.name,
        details={"strategy": payload.strategy.value, "batch_id": str(batch_id), "skipped": skipped},
    )
    return {"batch_id": str(batch_id), "skipped": skipped}


@router.post("/companies/{company_id}/check-updates", dependencies=[_action_updates])
async def trigger_company_check_updates_api(
    request: Request, company_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    company = await _get_company_or_404(company_id, db, user)
    skipped = await trigger_check_updates(company.honeypots)
    await log_event(
        db,
        request=request,
        action="company.updates.check",
        summary=f'Checked for updates on company "{company.name}"',
        target_type="company",
        target_id=company.id,
        target_label=company.name,
        details={"skipped": skipped},
    )
    return {"skipped": skipped}


class _GroupPowerAction(BaseModel):
    action: PowerAction
    confirm_name: str = Field(min_length=1)


@router.post("/companies/{company_id}/power", dependencies=[_action_power])
async def company_power_action_api(
    request: Request,
    company_id: uuid.UUID,
    payload: _GroupPowerAction,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    company = await _get_company_or_404(company_id, db, user)
    if payload.confirm_name.strip() != company.name:
        await log_event(
            db,
            request=request,
            action=f"company.power.{payload.action.value}",
            summary=(
                f'Blocked {payload.action.value} on company "{company.name}": '
                "confirmation mismatch"
            ),
            outcome=AuditOutcome.DENIED,
            target_type="company",
            target_id=company.id,
            target_label=company.name,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f'"confirm_name" must exactly match the company\'s name ("{company.name}").',
        )
    skipped = await send_power_to_honeypots(company.honeypots, payload.action)
    await log_event(
        db,
        request=request,
        action=f"company.power.{payload.action.value}",
        summary=f'Sent {payload.action.value} to company "{company.name}"',
        target_type="company",
        target_id=company.id,
        target_label=company.name,
        details={"skipped": skipped},
    )
    return {"ok": True, "skipped": skipped}



@router.get("/companies/batches/{batch_id}", dependencies=[_view_honeypots])
async def update_batch_detail_api(
    batch_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    # Restricted to this account's own honeypots, so a batch that straddles
    # the boundary (an unrestricted admin's "All honeypots" run) reports only
    # the part this account can see.
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
    runs = list(result.scalars().all())
    if not runs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Batch not found.")
    return {"batch_id": str(batch_id), "runs": [_update_run_to_dict(r) for r in runs]}
