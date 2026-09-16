"""Regression guard for the live-update WebSocket wiring — the browser
half (`app/web/static/js/live-updates.js`), every template that opts into
it, and the server routes it connects to (`app/web/routes/live_ws.py`).
These are three separately-edited files agreeing on the same data
attribute names and URL shapes, with nothing enforcing that at runtime —
a mismatch fails silently (the socket simply never opens, or the script
finds no anchor and no-ops entirely), with no error anywhere a human
would notice short of watching the browser console. See
wiki/Honeypot-Management.md's "Live updates over WebSocket" section
("Small but worth knowing").

This is exactly the class of bug this app shipped with from its very
first commit, found live this session: a debcontrol leftover — the JS's
selector/URL never got updated to match this app's own `data-live-
honeypot-id` attribute and `/honeypots/{id}/live/ws` route — silently
left every page's live-update socket a permanent no-op behind an
always-on polling fallback, with zero errors anywhere, for as long as
nobody happened to open the browser console.

Four scopes now share this same wiring shape (honeypot, fleet, admin,
per-user notifications) — see `app/services/live_updates.py`'s module
docstring for what each covers."""

from __future__ import annotations

from pathlib import Path

from app.main import app

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATES_DIR = _REPO_ROOT / "app" / "web" / "templates"
_LIVE_UPDATES_JS = (_REPO_ROOT / "app" / "web" / "static" / "js" / "live-updates.js").read_text(
    encoding="utf-8"
)

_DATA_ATTR_ID = "data-live-honeypot-id"
_DATA_ATTR_NAME = "data-live-honeypot-name"


def test_live_updates_js_selector_matches_the_data_attribute_every_page_sets():
    assert f'"[{_DATA_ATTR_ID}]"' in _LIVE_UPDATES_JS
    assert f'getAttribute("{_DATA_ATTR_ID}")' in _LIVE_UPDATES_JS
    assert f'getAttribute("{_DATA_ATTR_NAME}")' in _LIVE_UPDATES_JS


def test_live_updates_js_builds_the_url_the_live_ws_route_actually_serves():
    # The JS builds this by string interpolation, so there's nothing to
    # literally execute here — assert on the literal template instead...
    assert "/honeypots/${encodeURIComponent(honeypotId)}/live/ws" in _LIVE_UPDATES_JS

    # ...and that a websocket route genuinely exists at that same shape
    # (the Python-side equivalent of the JS's `{honeypotId}` placeholder) —
    # `url_path_for` on the route's own function name is Starlette's public
    # route-resolution API, so this stays correct across an internal
    # routing refactor rather than reaching into `app.router.routes`.
    assert (
        app.url_path_for("honeypot_live_websocket", honeypot_id="123")
        == "/honeypots/123/live/ws"
    )


def test_every_template_that_includes_live_updates_js_sets_a_live_data_attribute():
    """Walks every template under app/web/templates/ — a template that
    `<script src=".../live-updates.js">`s in must also set one of the four
    `data-live-*` anchors somewhere in the same file, or the script loads
    and immediately no-ops with no indication why."""
    live_attrs = (
        _DATA_ATTR_ID,
        "data-live-fleet",
        "data-live-admin",
        "data-live-notifications",
    )
    offenders = []
    for template_path in _TEMPLATES_DIR.rglob("*.html"):
        text = template_path.read_text(encoding="utf-8")
        if "live-updates.js" not in text:
            continue
        if not any(attr in text for attr in live_attrs):
            offenders.append(str(template_path.relative_to(_REPO_ROOT)))

    assert offenders == [], (
        f"these templates include live-updates.js but never set any of {live_attrs}, "
        f"so their live-update socket silently no-ops: {offenders}"
    )


def test_at_least_the_known_honeypot_pages_wire_up_live_updates():
    """Not exhaustive by design (the test above already is) — this just
    keeps the pages this feature was actually built for from quietly
    losing the include during an unrelated template refactor."""
    for relative_path in (
        "honeypots/detail.html",
        "honeypots/monitoring.html",
        "honeypots/status.html",
        "honeypots/update_history.html",
    ):
        text = (_TEMPLATES_DIR / relative_path).read_text(encoding="utf-8")
        assert "live-updates.js" in text, f"{relative_path} no longer includes live-updates.js"
        assert _DATA_ATTR_ID in text, f"{relative_path} no longer sets {_DATA_ATTR_ID}"


# --- Fleet/admin/notifications scopes ------------------------------------


def test_live_updates_js_builds_the_urls_the_other_three_routes_serve():
    assert "/live/fleet/ws" in _LIVE_UPDATES_JS
    assert "/live/admin/ws" in _LIVE_UPDATES_JS
    assert "/live/notifications/ws" in _LIVE_UPDATES_JS

    assert app.url_path_for("fleet_live_websocket") == "/live/fleet/ws"
    assert app.url_path_for("admin_live_websocket") == "/live/admin/ws"
    assert app.url_path_for("notifications_live_websocket") == "/live/notifications/ws"


def test_at_least_the_known_fleet_scoped_pages_wire_up_live_updates():
    for relative_path in ("dashboard/index.html", "map/index.html"):
        text = (_TEMPLATES_DIR / relative_path).read_text(encoding="utf-8")
        assert "live-updates.js" in text, f"{relative_path} no longer includes live-updates.js"
        assert "data-live-fleet" in text, f"{relative_path} no longer sets data-live-fleet"


def test_at_least_the_known_admin_scoped_pages_wire_up_live_updates():
    for relative_path in ("audit/list.html", "companies/list.html"):
        text = (_TEMPLATES_DIR / relative_path).read_text(encoding="utf-8")
        assert "live-updates.js" in text, f"{relative_path} no longer includes live-updates.js"
        assert "data-live-admin" in text, f"{relative_path} no longer sets data-live-admin"


def test_notification_history_wires_up_its_own_per_user_live_updates():
    text = (_TEMPLATES_DIR / "notifications/history.html").read_text(encoding="utf-8")
    assert "live-updates.js" in text
    assert "data-live-notifications" in text
