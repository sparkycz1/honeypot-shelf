"""Things a walk through the pages turned up: two different measurements
both called "online", an audit column headed "UTC" over local times, a
failed update check nobody could see, an English-only notification toggle,
a hint pointing the wrong way, and audit failures without their reason."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from app.audit import log_event
from app.db.models.audit_log import AuditOutcome
from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.user import User
from app.ssh.exceptions import SSHConnectionError
from app.ssh.updates import UpdateCheckResult, apt_refresh_error
from tests.conftest import create_company

_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATES = _ROOT / "app" / "web" / "templates"


async def _honeypot(db_session_factory: Any, **fields: Any) -> tuple[uuid.UUID, uuid.UUID]:
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, company.id)],
            name="hp-review",
            ip_address="10.7.7.7",
            port=22,
            username="root",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fakefingerprint",
            **fields,
        )
        db.add(honeypot)
        await db.commit()
        return honeypot.id, company.id


async def _use_czech(db_session_factory: Any) -> None:
    async with db_session_factory() as db:
        user = (await db.execute(select(User).where(User.is_superadmin))).scalars().first()
        assert user is not None
        user.locale = "cs"
        await db.commit()


# --- "Online" meant two different things ---------------------------------


@pytest.mark.asyncio
async def test_ssh_and_opencanary_state_are_named_apart_on_every_page(
    client: Any, db_session_factory: Any
) -> None:
    """Reachable over SSH, but its OpenCanary log was last read an hour ago."""
    honeypot_id, company_id = await _honeypot(
        db_session_factory,
        is_reachable=True,
        last_seen_at=datetime.now(UTC) - timedelta(hours=1),
    )

    for url in ("/honeypots", f"/honeypots/{honeypot_id}"):
        page = (await client.get(url)).text
        assert "SSH reachable" in page, url
        assert "OpenCanary silent" in page, url

    dashboard = (await client.get("/dashboard")).text
    for label in ("OpenCanary reporting", "OpenCanary silent", "SSH reachable"):
        assert f'<span class="stat-label">{label}</span>' in dashboard

    company = (await client.get(f"/companies/{company_id}")).text
    assert '<span class="stat-label">SSH reachable</span>' in company
    assert '<span class="stat-label">OpenCanary reporting</span>' in company


@pytest.mark.asyncio
async def test_a_honeypot_never_polled_is_not_called_silent(
    client: Any, db_session_factory: Any
) -> None:
    await _honeypot(db_session_factory, is_reachable=None)
    page = (await client.get("/honeypots")).text
    assert "SSH not checked yet" in page
    assert "OpenCanary: no data yet" in page


@pytest.mark.parametrize("locale", ["en", "cs"])
def test_no_bare_online_label_is_left(locale: str) -> None:
    path = _ROOT / "app" / "i18n" / "locales" / f"{locale}.json"
    strings = json.loads(path.read_text(encoding="utf-8"))["strings"]
    assert not [k for k, v in strings.items() if v.strip().lower() in {"online", "offline"}]


# --- Audit log -----------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_time_column_does_not_claim_utc(client: Any, db_session_factory: Any) -> None:
    async with db_session_factory() as db:
        await log_event(db, action="user.create", summary='Created user "eve"', actor="someone")
    page = (await client.get("/audit")).text
    assert "<th>Time</th>" in page
    assert "Time (UTC)" not in page


@pytest.mark.asyncio
async def test_a_failed_audit_entry_shows_why_in_another_language(
    client: Any, db_session_factory: Any
) -> None:
    async with db_session_factory() as db:
        await log_event(
            db,
            action="user.create",
            summary='Rejected new user "bob": Username is already taken.',
            actor="someone",
            outcome=AuditOutcome.FAILURE,
        )
        await log_event(db, action="user.create", summary='Created user "eve"', actor="someone")
    await _use_czech(db_session_factory)

    page = (await client.get("/audit")).text
    assert '<span class="hint">Rejected new user &#34;bob&#34;: Username is already taken.' in page
    # A successful entry keeps just its translated label.
    assert '<span class="hint">Created user' not in page


# --- A failed update check -----------------------------------------------


def test_apt_refresh_error_keeps_what_apt_said_before_the_first_section() -> None:
    raw = (
        "W: something minor\n"
        "E: Failed to fetch http://deb.example/dists/stable/InRelease  404  Not Found\n"
        "E: Some index files failed to download.\n"
        "===APT_UPGRADABLE===\n===FLATPAK===\norg.example.App\t1.0\n"
    )
    assert apt_refresh_error(raw).splitlines() == [
        "W: something minor",
        "E: Failed to fetch http://deb.example/dists/stable/InRelease  404  Not Found",
        "E: Some index files failed to download.",
    ]
    assert apt_refresh_error("===APT_UPGRADABLE===\nfoo/stable 2 amd64\n") == ""


async def _run_check(
    db_session_factory: Any, monkeypatch: Any, honeypot_id: uuid.UUID, outcome: Any
) -> dict[str, Any]:
    from app.tasks import jobs

    async def _check(*_args: Any, **_kwargs: Any) -> UpdateCheckResult:
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    async def _nothing(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    monkeypatch.setattr(jobs, "check_updates", _check)
    monkeypatch.setattr(jobs, "resolve_honeypot_credential", _nothing)
    monkeypatch.setattr(jobs, "publish_honeypot_event", _nothing)
    monkeypatch.setattr(jobs, "publish_fleet_event", _nothing)
    return await jobs._check_honeypot_updates(str(honeypot_id))


def _result(exit_status: int, output: str = "") -> UpdateCheckResult:
    return UpdateCheckResult(
        exit_status=exit_status,
        upgradable_count=0,
        security_upgradable_count=0,
        flatpak_upgradable_count=0,
        snap_upgradable_count=0,
        output=output,
    )


@pytest.mark.asyncio
async def test_a_failed_update_check_is_remembered_and_shown(
    client: Any, db_session_factory: Any, monkeypatch: Any
) -> None:
    honeypot_id, _company_id = await _honeypot(db_session_factory, is_reachable=True)
    failed = await _run_check(
        db_session_factory,
        monkeypatch,
        honeypot_id,
        _result(100, "E: Some index files failed to download.\n===APT_UPGRADABLE===\n"),
    )
    assert failed["ok"] is False

    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, honeypot_id)
        assert honeypot is not None
        assert honeypot.updates_check_error == (
            "apt-get update exited with status 100.\nE: Some index files failed to download."
        )

    listing = (await client.get("/honeypots")).text
    assert '<span class="badge badge-error" title="apt-get update exited with status 100.' in (
        listing
    )
    assert "check failed" in listing

    # The Updates tab shows it on a plain reload, not only right after the
    # request that ran the check.
    panel = (await client.get(f"/honeypots/{honeypot_id}/update-availability-panel")).text
    assert "Could not check for updates:" in panel
    assert "E: Some index files failed to download." in panel

    ok = await _run_check(db_session_factory, monkeypatch, honeypot_id, _result(0))
    assert ok == {"ok": True}
    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, honeypot_id)
        assert honeypot is not None and honeypot.updates_check_error is None
    assert "check failed" not in (await client.get("/honeypots")).text


@pytest.mark.asyncio
async def test_an_unreachable_honeypot_fails_its_update_check_visibly(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    honeypot_id, _company_id = await _honeypot(db_session_factory, is_reachable=False)
    await _run_check(
        db_session_factory, monkeypatch, honeypot_id, SSHConnectionError("Connection refused")
    )
    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, honeypot_id)
        assert honeypot is not None and honeypot.updates_check_error == "Connection refused"


# --- Notification toggle, Notifications page, map ------------------------


@pytest.mark.asyncio
async def test_notification_toggle_texts_reach_the_script_translated(
    client: Any, db_session_factory: Any
) -> None:
    honeypot_id, _company_id = await _honeypot(db_session_factory, is_reachable=True)
    await _use_czech(db_session_factory)
    page = (await client.get(f"/honeypots/{honeypot_id}")).text
    tag = page.split("js/live-updates.js", 1)[1].split("</script>", 1)[0]
    strings = json.loads(tag.split("data-i18n='", 1)[1].split("'", 1)[0])
    assert strings["blocked"] == "🔕 Oznámení zablokována"
    assert "nastavení webu" in strings["blocked_hint"]
    assert strings["kind.activity"] == "Nová aktivita OpenCanary"


def test_live_updates_script_has_no_untranslatable_button_text() -> None:
    script = (_ROOT / "app" / "web" / "static" / "js" / "live-updates.js").read_text(
        encoding="utf-8"
    )
    assert "button.textContent = tr(" in script
    assert 'button.textContent = "' not in script
    # Every page loads it through the one partial that carries the texts.
    direct = [
        path.name
        for path in _TEMPLATES.rglob("*.html")
        if "js/live-updates.js')" in path.read_text(encoding="utf-8")
        and path.name != "_live_updates_script.html"
    ]
    assert not direct


@pytest.mark.asyncio
async def test_empty_notifications_page_points_at_the_button_above(client: Any) -> None:
    page = (await client.get("/account/notifications")).text
    assert "button above" in page
    assert "add one below" not in page
    assert page.index("Add rule") < page.index("button above")


def test_map_svg_has_no_invalid_height() -> None:
    template = (_TEMPLATES / "partials" / "_map_content.html").read_text(encoding="utf-8")
    assert 'height="auto"' not in template


# --- NetBird version pin -------------------------------------------------


def test_netbird_version_is_pinned_in_env_not_in_the_dockerfile() -> None:
    dockerfile = (_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "ARG NETBIRD_VERSION\n" in dockerfile
    assert "ARG NETBIRD_VERSION=" not in dockerfile
    assert "\nNETBIRD_VERSION=0.80.0\n" in (_ROOT / ".env.example").read_text(encoding="utf-8")
    compose = (_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "NETBIRD_VERSION: ${NETBIRD_VERSION:?" in compose
