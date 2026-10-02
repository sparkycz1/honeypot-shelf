"""Localized audit log labels (`app.web.templating.audit_text`) and the
grouped "Administration" navigation menu — ported from debcontrol."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from sqlalchemy import select

from app.audit import log_event
from app.db.models.user import AccessLevel, User
from tests.conftest import create_company

_ROOT = Path(__file__).resolve().parent.parent
# One character class, no nested quantifier (linear time); the "has a dot"
# check happens in `_audit_codes`.
_ACTION = re.compile(r'action=f?"([a-z_.{}]+)"')
_CONDITIONAL = re.compile(r'"([a-z_]+(?:\.[a-z_]+)+)" if [^\n]+? else "([a-z_]+(?:\.[a-z_]+)+)"')


def _strings(code: str) -> dict[str, str]:
    path = _ROOT / "app" / "i18n" / "locales" / f"{code}.json"
    return json.loads(path.read_text(encoding="utf-8"))["strings"]


def _audit_codes() -> set[str]:
    codes: set[str] = set()
    for path in (_ROOT / "app").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for match in _ACTION.finditer(text):
            # An f-string code (`honeypot.power.{action.value}`) is labelled
            # by its fixed prefix.
            code = match.group(1).split(".{")[0]
            if "." in code and not code.startswith(".") and "{" not in code:
                codes.add(code)
        for match in _CONDITIONAL.finditer(text):
            codes.update(
                c for c in match.groups() if not c.startswith(("maintenance.", "notifications."))
            )
    return codes


def _labelled(code: str, strings: dict[str, str]) -> bool:
    while code:
        if f"audit.action_label.{code}" in strings:
            return True
        code = code.rpartition(".")[0]
    return False


@pytest.mark.parametrize("locale", ["en", "cs"])
def test_every_audit_action_has_a_label(locale):
    strings = _strings(locale)
    codes = _audit_codes()
    assert len(codes) > 50, "the action-code scan no longer finds log_event calls"
    missing = sorted(c for c in codes if not _labelled(c, strings))
    assert not missing, f"audit actions without a {locale} label: {missing}"


@pytest.mark.asyncio
async def test_audit_log_shows_labels_in_czech_and_summaries_in_english(client, db_session_factory):
    async with db_session_factory() as db:
        await log_event(
            db,
            action="maintenance_window.create",
            summary='Scheduled maintenance window "Re-flash" (all honeypots of Acme)',
            actor="someone",
            details={"pause_scheduled_tasks": True, "scope": "all honeypots of Acme"},
        )

    english = await client.get("/audit")
    assert 'Scheduled maintenance window "Re-flash"' in english.text.replace("&#34;", '"')
    assert "pause_scheduled_tasks: True · scope: all honeypots of Acme" in english.text

    async with db_session_factory() as db:
        user = (await db.execute(select(User).where(User.is_superadmin))).scalars().first()
        assert user is not None
        user.locale = "cs"
        await db.commit()
    czech = await client.get("/audit")
    assert "Naplánování okna údržby" in czech.text


@pytest.mark.asyncio
async def test_superadmin_gets_an_administration_menu(client):
    page = await client.get("/dashboard")
    assert '<details class="nav-menu">' in page.text
    menu = page.text.split('<details class="nav-menu">', 1)[1].split("</details>", 1)[0]
    for href in ("/companies", "/users", "/audit", "/settings"):
        assert f'href="{href}"' in menu


@pytest.mark.asyncio
async def test_administration_menu_is_marked_active_on_its_pages(client):
    page = await client.get("/audit")
    assert '<summary class="active">' in page.text


@pytest.mark.asyncio
async def test_read_only_user_has_no_administration_menu(client, db_session_factory, login_as):
    company = await create_company(db_session_factory)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ)
    page = await client.get("/dashboard")
    assert 'class="nav-menu"' not in page.text
    assert 'href="/honeypots"' in page.text
