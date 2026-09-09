"""Regression guard: `/account` ("My account") used to be almost entirely
hardcoded English — Password/2FA/Passkeys/Sessions/API tokens sections and
several `data-confirm` prompts never went through `t()` at all, despite
CLAUDE.md/wiki claiming complete i18n coverage. Asserts the Czech locale
actually shows Czech text on this page, not an English fallback."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def test_account_page_renders_in_czech(client, login_as):
    await login_as(client, is_superadmin=True, locale="cs")

    response = await client.get("/account")

    assert response.status_code == 200
    # Was hardcoded "Password"/"Passkeys"/"Sessions"/"API tokens" before.
    assert "Heslo" in response.text
    assert "Passkeys" in response.text  # not translated, brand-name-like — stays as-is
    assert "Relace" in response.text
    assert "API tokeny" in response.text
    assert "Změnit heslo" in response.text


async def test_account_page_renders_in_english(client, login_as):
    await login_as(client, is_superadmin=True, locale="en")

    response = await client.get("/account")

    assert response.status_code == 200
    assert "Change password" in response.text
    assert "API tokens" in response.text
