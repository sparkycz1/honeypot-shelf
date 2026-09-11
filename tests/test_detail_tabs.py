"""Honeypot Overview: reboot/shut down live there directly — there's no
separate "Power" tab any more (see `honeypots._honeypot_tabs`) — and the
terminal page loads the CSP-safe canvas addon for ANSI colors."""

from __future__ import annotations

import pytest

from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.user import AccessLevel
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


async def _create_pinned_honeypot(db_session_factory, company_id) -> Honeypot:
    async with db_session_factory() as db:
        company = await db.get(Company, company_id)
        honeypot = Honeypot(
            companies=[company],
            name="acme-honey1",
            ip_address="192.0.2.10",
            port=22,
            username="honeyhive",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fake-fingerprint-for-tests",
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
    return honeypot


async def test_honeypot_overview_has_reboot_and_shutdown_links(client, db_session_factory):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)

    response = await client.get(f"/honeypots/{honeypot.id}")
    assert response.status_code == 200
    assert f'href="/honeypots/{honeypot.id}/power/reboot"' in response.text
    assert f'href="/honeypots/{honeypot.id}/power/shutdown"' in response.text


async def test_honeypot_overview_hides_power_without_write_access(
    client, login_as, db_session_factory
):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)

    await login_as(
        client, is_superadmin=False, company_id=company.id, access_level=AccessLevel.READ
    )
    response = await client.get(f"/honeypots/{honeypot.id}")
    assert response.status_code == 200
    assert f'href="/honeypots/{honeypot.id}/power/reboot"' not in response.text


async def test_old_power_tab_url_redirects_to_overview(client, db_session_factory):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)

    response = await client.get(f"/honeypots/{honeypot.id}/power", follow_redirects=False)
    assert response.status_code == 301
    assert response.headers["location"] == f"/honeypots/{honeypot.id}"


async def test_terminal_page_loads_the_canvas_addon(client, db_session_factory):
    """Regression guard: xterm.js's default DOM renderer draws ANSI colors
    via a dynamically injected <style> element, which this app's CSP
    (`style-src 'self'`, no `unsafe-inline`) silently blocks — every color
    code renders as plain foreground-only text, with no error visible
    anywhere except the browser console. The canvas addon draws colors via
    <canvas> instead, which CSP's style-src has no say over. See
    `terminal.js`'s own comment for the full story."""
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)

    response = await client.get(f"/honeypots/{honeypot.id}/terminal")

    assert response.status_code == 200
    assert '<script src="/static/js/xterm-addon-canvas.min.js">' in response.text
