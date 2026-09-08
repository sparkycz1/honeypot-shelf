"""The Honeypot Status tab's read-only root filesystem toggle. See
app.ssh.readonly and app.web.routes.honeypots's status/config routes.
"""

from __future__ import annotations

import re

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
        honeypot = Honeypot(
            company_id=company_id,
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


async def test_status_tab_shows_up_for_a_write_user(client, db_session_factory, celery_calls):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)
    celery_calls.result_for["app.tasks.jobs.check_honeypot_readonly_status"] = {
        "ok": True,
        "state": "disabled",
    }

    response = await client.get(f"/honeypots/{honeypot.id}/status")
    assert response.status_code == 200
    assert "Read-only root filesystem" in response.text
    assert "writable" in response.text


async def test_status_tab_is_hidden_and_forbidden_for_read_only_user(
    client, login_as, db_session_factory
):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ)

    overview = await client.get(f"/honeypots/{honeypot.id}")
    assert 'href="/honeypots/' + str(honeypot.id) + '/status"' not in overview.text

    response = await client.get(f"/honeypots/{honeypot.id}/status")
    assert response.status_code == 403


async def test_config_tab_renders_for_a_write_user(client, db_session_factory):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)

    response = await client.get(f"/honeypots/{honeypot.id}/config")
    assert response.status_code == 200
    assert "Honeypot config" in response.text


async def test_enable_readonly_dispatches_task_and_redirects(
    client, db_session_factory, celery_calls
):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)

    form = await client.get(f"/honeypots/{honeypot.id}/status")
    match = re.search(r'name="csrf_token" value="([^"]+)"', form.text)
    assert match
    csrf_token = match.group(1)

    response = await client.post(
        f"/honeypots/{honeypot.id}/status/readonly",
        data={"enable": "true", "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"/honeypots/{honeypot.id}/status"
    names = celery_calls.names
    assert "app.tasks.jobs.set_honeypot_readonly" in names
    call = next(c for c in celery_calls if c[0] == "app.tasks.jobs.set_honeypot_readonly")
    assert call[1][0] == str(honeypot.id)
    assert call[2] == {"enable": True}
