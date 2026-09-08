"""Export/import of honeypot & company *configuration* — shared between the
web routes (`app/web/routes/honeypots.py`) and the REST API
(`app/web/routes/api_v1.py`), same "one service function, two doors"
convention as `app.services.honeypot_actions`.

**This is a structural/config export, not a credentials backup.** Consistent
with this app's "no blind trust" SSH security model (see
wiki/Architecture.md's host-key-pinning section), the export/import
deliberately never touches:

- `Honeypot.secret_encrypted` — the encrypted password/key material for
  `AuthMethod.PASSWORD` honeypots.
- `Honeypot.host_key_fingerprint` — the pinned SSH host key. An imported
  honeypot always starts with none, exactly like a freshly hand-added one:
  the normal "Discover key fingerprint" + manual outside-the-app
  confirmation flow applies before anything can connect to it.

Consequences of that for import:

- A honeypot whose original `auth_method` was `ssh_key` imports cleanly —
  the app's shared SSH identity key needs nothing honeypot-specific.
- A honeypot whose original `auth_method` was `password` can't be
  re-created with that method (there's no secret to import) — it's
  imported as `ssh_key` instead, and the honeypot's name is surfaced in
  `ImportResult.auth_method_warnings` so an operator knows to revisit its
  credentials.

Conflict handling: a honeypot name that already exists **within the
same company** is skipped, not overwritten — silently clobbering an
existing honeypot's connection details (and forcing host-key
re-confirmation on it) is a worse default than asking an operator to
resolve the conflict by hand. Companies are the opposite case: matched-or-
created by name is harmless (there's no credential/trust state on a
company to lose), so an existing company is simply reused for membership.

Unlike debcontrol (single-tenant), every honeypot belongs to exactly one
company (`HoneypotExport.company`, required, not optional) — import always
creates or reuses that company by name, never leaves a honeypot
unattached.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth.scope import companies_visible_to, honeypots_visible_to
from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.user import User
from app.schemas.honeypot_config import CompanyExport, HoneypotConfigExport, HoneypotExport
from app.services.honeypot_tags import set_honeypot_tags

# Shown once per import result, regardless of how many honeypots were
# created — every one of them starts with no pinned host key.
HOST_KEY_WARNING = (
    "Every imported honeypot has no pinned host-key fingerprint, exactly like "
    "a freshly hand-added honeypot. Use \"Discover key fingerprint\" and confirm "
    "it (outside this app) before anything connects to it."
)


async def export_honeypot_config(db: AsyncSession, user: User) -> HoneypotConfigExport:
    """Every `Honeypot` and every `Company` **that `user` can see**, in the
    import-compatible shape.

    Scoped through `app.auth.scope` like every other read path: an export
    is a listing, and a company-scoped account must not be able to read
    out another company's connection details through a download link. A
    company's `members` list is filtered to visible honeypots for the same
    reason (a superadmin exporting sees everything; a company account only
    ever sees its own company anyway, so this mainly matters for a
    superadmin's own consistency between the two lists).

    Import is deliberately not scope-checked in the same way — it only
    ever creates brand-new rows or reuses a company by name, so there is
    nothing existing to check read access against. See
    `import_honeypot_config`."""
    honeypot_result = await db.execute(
        honeypots_visible_to(user)
        .options(selectinload(Honeypot.company))
        .order_by(Honeypot.name)
    )
    honeypots = [
        HoneypotExport(
            name=h.name,
            ip_address=h.ip_address,
            port=h.port,
            username=h.username,
            auth_method=h.auth_method,
            company=h.company.name,
            location=h.location,
            description=h.description,
            runbook=h.runbook,
            tags=[tag.name for tag in h.tags],
            is_active=h.is_active,
        )
        for h in honeypot_result.scalars().all()
    ]

    company_result = await db.execute(
        companies_visible_to(user).options(selectinload(Company.honeypots)).order_by(Company.name)
    )
    companies = [
        CompanyExport(
            name=c.name,
            notes=c.notes,
            members=sorted(h.name for h in c.honeypots),
        )
        for c in company_result.scalars().all()
    ]

    return HoneypotConfigExport(honeypots=honeypots, companies=companies)


@dataclass
class ImportResult:
    created_honeypots: list[str] = field(default_factory=list)
    created_companies: list[str] = field(default_factory=list)
    skipped_honeypots: list[dict[str, str]] = field(default_factory=list)
    auth_method_warnings: list[str] = field(default_factory=list)
    host_key_warning: str = HOST_KEY_WARNING

    def to_dict(self) -> dict[str, object]:
        return {
            "created_honeypots": self.created_honeypots,
            "created_companies": self.created_companies,
            "skipped_honeypots": self.skipped_honeypots,
            "auth_method_warnings": self.auth_method_warnings,
            "host_key_warning": self.host_key_warning,
        }

    def summary(self) -> str:
        parts = [
            f"{len(self.created_honeypots)} honeypot(s)",
            f"{len(self.created_companies)} "
            f"compan{'y' if len(self.created_companies) == 1 else 'ies'}",
        ]
        summary = f"Imported {', '.join(parts)}"
        if self.skipped_honeypots:
            summary += f", skipped {len(self.skipped_honeypots)} honeypot(s) (name already exists)"
        if self.auth_method_warnings:
            summary += (
                f", {len(self.auth_method_warnings)} imported as ssh_key "
                "(original auth method was password)"
            )
        return summary


async def import_honeypot_config(db: AsyncSession, payload: HoneypotConfigExport) -> ImportResult:
    """Create real `Honeypot`/`Company` rows directly from `payload` — not
    the pending-review queue self-registration uses, since this is for
    restoring/migrating *known* configuration, not discovering unknown
    hosts. See the module docstring for the full conflict/security policy
    this implements. **Superadmin-only** at the route level (this function
    itself performs no authorization) — it can create honeypots in any
    company by name."""
    result = ImportResult()

    existing_honeypot_names = set((await db.execute(select(Honeypot.name))).scalars().all())
    companies_by_name: dict[str, Company] = {
        c.name: c for c in (await db.execute(select(Company))).scalars().all()
    }

    # Create every company named anywhere in the payload first (either in
    # the `companies` list itself, or only referenced from a honeypot's
    # `company` field) so every honeypot below has somewhere to attach to.
    wanted_company_names = {c.name for c in payload.companies} | {
        m.company for m in payload.honeypots
    }
    company_notes = {c.name: c.notes for c in payload.companies}
    for name in sorted(wanted_company_names):
        if name in companies_by_name:
            continue
        company = Company(name=name, notes=company_notes.get(name))
        db.add(company)
        companies_by_name[name] = company
        result.created_companies.append(name)
    if result.created_companies:
        await db.flush()  # assign IDs before honeypots reference them below.

    for honeypot in payload.honeypots:
        if honeypot.name in existing_honeypot_names:
            result.skipped_honeypots.append(
                {"name": honeypot.name, "reason": "A honeypot with this name already exists."}
            )
            continue

        auth_method = honeypot.auth_method
        if auth_method == AuthMethod.PASSWORD:
            auth_method = AuthMethod.SSH_KEY
            result.auth_method_warnings.append(honeypot.name)

        new_honeypot = Honeypot(
            name=honeypot.name,
            ip_address=honeypot.ip_address,
            port=honeypot.port,
            username=honeypot.username,
            auth_method=auth_method,
            secret_encrypted=None,
            host_key_fingerprint=None,
            company_id=companies_by_name[honeypot.company].id,
            location=honeypot.location,
            description=honeypot.description,
            runbook=honeypot.runbook,
            is_active=honeypot.is_active,
        )
        db.add(new_honeypot)
        if honeypot.tags:
            await db.flush()  # assign an id before set_honeypot_tags needs one
            await set_honeypot_tags(db, new_honeypot, honeypot.tags)
        existing_honeypot_names.add(honeypot.name)
        result.created_honeypots.append(honeypot.name)

    await db.commit()
    return result
