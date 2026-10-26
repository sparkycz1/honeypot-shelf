"""REST API for what a company's own page does beyond create/rename/
delete: granting an existing user access, attaching an existing honeypot
(both additive — never touching other companies), and the company's
syslog target for its honeypot alerts, plus the fleet-wide "All
honeypots" target. Superadmin-only, like every company page and the rest
of `/api/v1/companies`."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import require_api_superadmin
from app.core.app_settings import get_or_create_app_settings
from app.db.models.company import Company
from app.db.models.company_membership import CompanyMembership
from app.db.models.honeypot import Honeypot
from app.db.models.user import AccessLevel, User
from app.db.session import get_db
from app.services.syslog_transport import DEFAULT_SYSLOG_PORT, SyslogProtocol

router = APIRouter(prefix="/api/v1/companies", dependencies=[Depends(require_api_superadmin)])


async def _company_or_404(company_id: uuid.UUID, db: AsyncSession) -> Company:
    company = await db.get(Company, company_id)
    if company is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Company not found.")
    return company


async def _user_or_404(user_id: uuid.UUID, db: AsyncSession) -> User:
    user = await db.get(User, user_id, options=[selectinload(User.memberships)])
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return user


async def _honeypot_or_404(honeypot_id: uuid.UUID, db: AsyncSession) -> Honeypot:
    honeypot = await db.get(Honeypot, honeypot_id)
    if honeypot is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Honeypot not found.")
    return honeypot


# --- Users ---------------------------------------------------------------------


class AccessGrant(BaseModel):
    access_level: AccessLevel


@router.put("/{company_id}/users/{user_id}")
async def grant_company_access_api(
    request: Request,
    company_id: uuid.UUID,
    user_id: uuid.UUID,
    payload: AccessGrant,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Grants an existing account access to this company, or changes the
    level it already has here. Its access to other companies is untouched.
    A superadmin account needs no membership and is refused (404)."""
    company = await _company_or_404(company_id, db)
    user = await _user_or_404(user_id, db)
    if user.is_superadmin:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    existing = next((m for m in user.memberships if m.company_id == company.id), None)
    if existing is not None:
        existing.access_level = payload.access_level
    else:
        db.add(
            CompanyMembership(
                user_id=user.id, company_id=company.id, access_level=payload.access_level
            )
        )
    await db.commit()
    await log_event(
        db,
        request=request,
        action="company.user.attach",
        summary=(
            f'Granted "{user.username}" {payload.access_level.value} access to "{company.name}"'
        ),
        target_type="company",
        target_id=company.id,
        target_label=company.name,
    )
    return {
        "company_id": str(company.id),
        "user_id": str(user.id),
        "access_level": payload.access_level.value,
    }


@router.delete("/{company_id}/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_company_access_api(
    request: Request,
    company_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Removes the account's access to this company only; the account
    itself stays."""
    company = await _company_or_404(company_id, db)
    user = await _user_or_404(user_id, db)
    membership = next((m for m in user.memberships if m.company_id == company.id), None)
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
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Honeypots -------------------------------------------------------------------


async def _link_honeypot(
    request: Request,
    company_id: uuid.UUID,
    honeypot_id: uuid.UUID,
    db: AsyncSession,
    *,
    attach: bool,
) -> None:
    # Honeypot first: loading the company also loads its honeypots, and a
    # honeypot already in the session would come back without `companies`.
    honeypot = await _honeypot_or_404(honeypot_id, db)
    company = await _company_or_404(company_id, db)
    if attach and company not in honeypot.companies:
        honeypot.companies.append(company)
    elif not attach and company in honeypot.companies:
        honeypot.companies.remove(company)
    await db.commit()
    verb = "Attached" if attach else "Detached"
    await log_event(
        db,
        request=request,
        action="company.honeypot.attach" if attach else "company.honeypot.detach",
        summary=f'{verb} "{honeypot.name}" {"to" if attach else "from"} "{company.name}"',
        target_type="company",
        target_id=company.id,
        target_label=company.name,
    )


@router.put("/{company_id}/honeypots/{honeypot_id}", status_code=status.HTTP_204_NO_CONTENT)
async def attach_honeypot_api(
    request: Request,
    company_id: uuid.UUID,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Adds an existing honeypot to this company. It stays in every other
    company it already belongs to. Repeating it changes nothing."""
    await _link_honeypot(request, company_id, honeypot_id, db, attach=True)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/{company_id}/honeypots/{honeypot_id}", status_code=status.HTTP_204_NO_CONTENT)
async def detach_honeypot_api(
    request: Request,
    company_id: uuid.UUID,
    honeypot_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Takes the honeypot out of this company only — never deletes it, even
    when this was its last company."""
    await _link_honeypot(request, company_id, honeypot_id, db, attach=False)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Syslog ----------------------------------------------------------------------


class SyslogTarget(BaseModel):
    enabled: bool
    host: str | None = Field(default=None, max_length=255)
    port: int = Field(default=DEFAULT_SYSLOG_PORT, ge=1, le=65535)
    protocol: SyslogProtocol = SyslogProtocol.UDP

    @model_validator(mode="after")
    def _host_when_enabled(self) -> SyslogTarget:
        self.host = (self.host or "").strip() or None
        if self.enabled and not self.host:
            raise ValueError("Enabling syslog forwarding needs a server host/IP.")
        return self


@router.get("/all/syslog")
async def fleet_syslog_api(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """The fleet-wide target: every honeypot's alerts go here, in addition
    to its own company's target."""
    s = await get_or_create_app_settings(db)
    return {
        "enabled": s.fleet_alert_syslog_enabled,
        "host": s.fleet_alert_syslog_host,
        "port": s.fleet_alert_syslog_port,
        "protocol": s.fleet_alert_syslog_protocol.value,
    }


@router.put("/all/syslog")
async def update_fleet_syslog_api(
    request: Request, payload: SyslogTarget, db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    s = await get_or_create_app_settings(db)
    s.fleet_alert_syslog_enabled = payload.enabled
    s.fleet_alert_syslog_host = payload.host
    s.fleet_alert_syslog_port = payload.port
    s.fleet_alert_syslog_protocol = payload.protocol
    await db.commit()
    state = "enabled, " + payload.protocol.value if payload.enabled else "disabled"
    await log_event(
        db,
        request=request,
        action="all_honeypots.syslog.update",
        summary=f"Updated fleet-wide honeypot-alert syslog forwarding ({state})",
        target_type="all_honeypots",
    )
    return await fleet_syslog_api(db)


def _company_syslog(company: Company) -> dict[str, Any]:
    return {
        "enabled": company.syslog_enabled,
        "host": company.syslog_host,
        "port": company.syslog_port,
        "protocol": company.syslog_protocol.value,
    }


@router.get("/{company_id}/syslog")
async def company_syslog_api(
    company_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    """Where this company's honeypot alerts are forwarded."""
    return _company_syslog(await _company_or_404(company_id, db))


@router.put("/{company_id}/syslog")
async def update_company_syslog_api(
    request: Request,
    company_id: uuid.UUID,
    payload: SyslogTarget,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    company = await _company_or_404(company_id, db)
    company.syslog_enabled = payload.enabled
    company.syslog_host = payload.host
    company.syslog_port = payload.port
    company.syslog_protocol = payload.protocol
    await db.commit()
    state = "enabled, " + payload.protocol.value if payload.enabled else "disabled"
    await log_event(
        db,
        request=request,
        action="company.syslog.update",
        summary=f'Updated honeypot-alert syslog forwarding for "{company.name}" ({state})',
        target_type="company",
        target_id=company.id,
        target_label=company.name,
    )
    return _company_syslog(company)
