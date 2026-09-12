"""Settings → Notifications: the shared, superadmin-editable email
templates behind `app.services.notifications`."""

from __future__ import annotations

import re

import pytest

from app.core.app_settings import get_or_create_app_settings

pytestmark = pytest.mark.asyncio


def _csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


async def test_notifications_tab_renders(client):
    response = await client.get("/settings", params={"tab": "notifications"})
    assert response.status_code == 200
    assert "notification_alert_subject" in response.text


async def test_save_custom_templates(client, db_session_factory):
    form = await client.get("/settings", params={"tab": "notifications"})
    response = await client.post(
        "/settings/notifications/templates",
        data={
            "csrf_token": _csrf_from(form),
            "notification_alert_subject": "Custom alert: {honeypot_name}",
            "notification_alert_body": "custom body",
            "notification_unavailable_subject": "",
            "notification_unavailable_body": "",
            "notification_recovered_subject": "",
            "notification_recovered_body": "",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        assert app_settings.notification_alert_subject == "Custom alert: {honeypot_name}"
        assert app_settings.notification_alert_body == "custom body"
        # A blank field resets to "use the default" (None), not an
        # empty-string override.
        assert app_settings.notification_unavailable_subject is None
        assert app_settings.notification_unavailable_body is None


async def test_read_only_user_cannot_reach_settings(client, login_as):
    from app.db.models.user import AccessLevel

    await login_as(client, access_level=AccessLevel.READ, is_superadmin=False)
    response = await client.get("/settings", params={"tab": "notifications"})
    assert response.status_code == 403
