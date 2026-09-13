"""Regression guard: the Honeypots list's per-honeypot select checkbox
had a hardcoded, untranslated `aria-label="Select {name}"` in the compact
list view, and no `aria-label` at all in the table view — only the Cards
view's own checkbox went through `t()`. Found during an app-wide audit;
`honeypots.list.select_aria` already existed and was already used
correctly by the Cards view, so this was a "missed the other two view
modes" gap, not a missing translation."""

from __future__ import annotations

import pytest

from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


async def _make_honeypot(db_session_factory, *, name: str = "acme-honey1"):
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(companies=[await db.get(Company, company.id)], name=name)
        db.add(honeypot)
        await db.commit()


async def test_every_view_mode_translates_the_select_checkbox_aria_label(
    client, db_session_factory
):
    await _make_honeypot(db_session_factory)

    for view_mode in ("cards", "list", "table"):
        client.cookies.set("honeypots_view", view_mode)
        response = await client.get("/honeypots")
        assert response.status_code == 200
        assert 'aria-label="Select acme-honey1"' in response.text, view_mode
