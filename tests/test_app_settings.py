"""`app.core.app_settings.get_or_create_app_settings` — the singleton
`AppSettings` row's defaults on first creation."""

from __future__ import annotations

import pytest

from app.core.app_settings import get_or_create_app_settings

pytestmark = pytest.mark.asyncio


async def test_audit_log_retention_defaults_to_90_days(db_session_factory):
    """Explicit product decision, matching every other retention setting
    in this app (see EVENT_RETENTION_DAYS's own default) — not "keep
    forever" any more, though that's still available by setting it back
    to blank from Settings."""
    async with db_session_factory() as db:
        settings = await get_or_create_app_settings(db)
        assert settings.audit_log_retention_days == 90
