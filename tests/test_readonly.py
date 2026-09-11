"""The Honeypot Config tab's read-only root filesystem toggle. See
app.ssh.readonly and app.web.routes.honeypots's status/config routes.
"""

from __future__ import annotations

import re

from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.user import AccessLevel
from app.ssh.readonly import build_status_command, build_toggle_command, parse_status
from tests.conftest import create_company


def test_parse_status_overlay_means_enabled():
    assert parse_status("overlay\n") == "enabled"


def test_parse_status_anything_else_means_disabled():
    assert parse_status("ext4\n") == "disabled"
    assert parse_status("") == "disabled"


def test_build_status_command_checks_root_fstype():
    assert build_status_command() == "findmnt -n -o FSTYPE /"


def test_build_toggle_command_enable_uses_flag_zero():
    command = build_toggle_command(enable=True)
    assert "do_overlayfs 0" in command


def test_build_toggle_command_disable_uses_flag_one():
    command = build_toggle_command(enable=False)
    assert "do_overlayfs 1" in command


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


async def test_status_tab_is_the_activity_tab_not_the_readonly_toggle(client, db_session_factory):
    """The Status URL (`/status`) is the Activity tab (OpenCanary log
    activity — see `tests/test_canary_activity_route.py`), a separate page
    from Config's read-only-root toggle tested below."""
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)

    response = await client.get(f"/honeypots/{honeypot.id}/status")
    assert response.status_code == 200
    assert "Read-only root filesystem" not in response.text


async def test_config_tab_shows_readonly_toggle_for_a_write_user(
    client, db_session_factory, celery_calls
):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)
    celery_calls.result_for["app.tasks.jobs.check_honeypot_readonly_status"] = {
        "ok": True,
        "state": "disabled",
    }

    response = await client.get(f"/honeypots/{honeypot.id}/config")
    assert response.status_code == 200
    assert "Read-only root filesystem" in response.text
    assert "writable" in response.text


async def test_config_tab_is_hidden_and_forbidden_for_read_only_user(
    client, login_as, db_session_factory
):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ)

    overview = await client.get(f"/honeypots/{honeypot.id}")
    assert 'href="/honeypots/' + str(honeypot.id) + '/config"' not in overview.text

    assert (await client.get(f"/honeypots/{honeypot.id}/config")).status_code == 403


async def test_status_activity_tab_is_visible_for_read_only_user(
    client, login_as, db_session_factory
):
    """Unlike Config/Terminal/Logs/Updates/Settings, the Activity tab is
    read-only-visible — a read-only account can already see what
    OpenCanary has actually caught without being able to manage the
    honeypot."""
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ)

    overview = await client.get(f"/honeypots/{honeypot.id}")
    assert 'href="/honeypots/' + str(honeypot.id) + '/status"' in overview.text

    assert (await client.get(f"/honeypots/{honeypot.id}/status")).status_code == 200


async def test_enable_readonly_dispatches_task_and_redirects(
    client, db_session_factory, celery_calls
):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)

    form = await client.get(f"/honeypots/{honeypot.id}/config")
    match = re.search(r'name="csrf_token" value="([^"]+)"', form.text)
    assert match
    csrf_token = match.group(1)

    response = await client.post(
        f"/honeypots/{honeypot.id}/config/readonly",
        data={"enable": "true", "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"/honeypots/{honeypot.id}/config?readonly_saved=enable"
    names = celery_calls.names
    assert "app.tasks.jobs.set_honeypot_readonly" in names
    call = next(c for c in celery_calls if c[0] == "app.tasks.jobs.set_honeypot_readonly")
    assert call[1][0] == str(honeypot.id)
    assert call[2] == {"enable": True}


async def test_readonly_toggle_success_shows_a_banner_after_redirect(
    client, db_session_factory, celery_calls
):
    """Regression guard: a successful toggle used to redirect to a plain
    `/config` with no indication anything happened — since the toggle
    itself only ever changes what the *next* boot looks like, the page
    looked identical to a silent no-op. See app.web.routes.honeypots.
    honeypot_config_tab's own comment on `readonly_saved`/`readonly_error`."""
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)

    form = await client.get(f"/honeypots/{honeypot.id}/config")
    match = re.search(r'name="csrf_token" value="([^"]+)"', form.text)
    assert match
    csrf_token = match.group(1)

    response = await client.post(
        f"/honeypots/{honeypot.id}/config/readonly",
        data={"enable": "true", "csrf_token": csrf_token},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "takes effect after the device reboots" in response.text


async def test_readonly_toggle_failure_is_surfaced_after_redirect_not_lost(
    client, db_session_factory, celery_calls
):
    """Same class of bug as the success case above, but for a genuine
    failure (e.g. a missing sudoers grant) — it used to vanish on redirect
    too, indistinguishable from success or a no-op."""
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)
    celery_calls.result_for["app.tasks.jobs.set_honeypot_readonly"] = {
        "ok": False,
        "error": "raspi-config exited 1: sudo: a password is required",
    }

    form = await client.get(f"/honeypots/{honeypot.id}/config")
    match = re.search(r'name="csrf_token" value="([^"]+)"', form.text)
    assert match
    csrf_token = match.group(1)

    response = await client.post(
        f"/honeypots/{honeypot.id}/config/readonly",
        data={"enable": "true", "csrf_token": csrf_token},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "sudo: a password is required" in response.text
