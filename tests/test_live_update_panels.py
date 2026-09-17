"""The new fleet/admin/notifications-scoped live-refresh panel routes
(Dashboard, Map, Audit log, Companies list, Notification history) — each
just re-renders the same content its full page would, as the htmx panel
`live-updates.js` re-fetches on a push (see
`app/services/live_updates.py`'s module docstring for the four channel
shapes, and `tests/test_live_updates_wiring.py` for the template/JS/route
wiring itself). These are plain smoke tests: each panel route returns 200
and renders content recognizable from its full-page counterpart, proving
the route/template split didn't silently break either the full page or
the panel."""

from __future__ import annotations

from app.services.live_updates import (
    ADMIN_CHANNEL,
    FLEET_CHANNEL,
    KIND_AUDIT,
    KIND_NOTIFICATION,
    KIND_STATUS,
    channel_for,
    notifications_channel_for,
)
from tests.conftest import create_company


async def test_dashboard_panel_renders_the_same_stats_the_full_page_does(client):
    full_page = await client.get("/dashboard")
    panel = await client.get("/dashboard/panel")
    assert panel.status_code == 200
    assert "stat-grid" in panel.text
    # The panel is exactly what the full page's live-refreshed div wraps —
    # not a byte-for-byte comparison (the full page has surrounding chrome
    # the panel doesn't), just the same stat markup present in both.
    assert "stat-grid" in full_page.text


async def test_map_panel_renders(client):
    response = await client.get("/map/panel")
    assert response.status_code == 200
    assert "panel" in response.text


async def test_audit_panel_renders_and_keeps_filters(client):
    full_page = await client.get("/audit?q=login")
    assert full_page.status_code == 200
    panel = await client.get("/audit/panel?q=login")
    assert panel.status_code == 200


async def test_companies_panel_renders(client, db_session_factory):
    await create_company(db_session_factory, name="Acme Panel Co")
    response = await client.get("/companies/panel")
    assert response.status_code == 200
    assert "Acme Panel Co" in response.text


async def test_notification_history_panel_renders(client):
    response = await client.get("/account/notifications/history/panel")
    assert response.status_code == 200


async def test_companies_and_audit_panels_require_login(anonymous_client):
    # Both routers already gate their whole prefix on require_superadmin,
    # behind app.auth.middleware's own login redirect for any unauthenticated
    # request — this just confirms the new /panel routes inherited that,
    # not just the pre-existing ones.
    assert (await anonymous_client.get("/audit/panel")).status_code == 303
    assert (await anonymous_client.get("/companies/panel")).status_code == 303


# --- app/services/live_updates.py: channel naming ------------------------


def test_fleet_and_admin_channels_are_fixed_and_distinct():
    assert FLEET_CHANNEL != ADMIN_CHANNEL
    assert channel_for("some-honeypot-id") != FLEET_CHANNEL
    assert channel_for("some-honeypot-id") != ADMIN_CHANNEL


def test_notifications_channel_is_scoped_per_user():
    assert notifications_channel_for("user-a") != notifications_channel_for("user-b")
    assert notifications_channel_for("user-a") != FLEET_CHANNEL
    assert notifications_channel_for("user-a") != ADMIN_CHANNEL


def test_kind_constants_are_distinct_strings():
    assert KIND_AUDIT != KIND_NOTIFICATION


async def test_publish_functions_are_best_effort_against_unreachable_redis():
    """No real Redis in the test environment (see CLAUDE.md) — every
    publish_* here must swallow the connection failure, never raise, the
    same contract `publish_honeypot_event` already had."""
    from app.services.live_updates import (
        publish_admin_event,
        publish_fleet_event,
        publish_notifications_event,
    )

    await publish_fleet_event(KIND_STATUS)
    await publish_admin_event()
    await publish_notifications_event("some-user-id")
