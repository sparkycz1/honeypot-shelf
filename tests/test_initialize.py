"""The "Initialize" top-nav action — provisions a brand new device over SSH
before it's ever added to HoneyHive. See app.web.routes.initialize and
app.ssh.initialize.
"""

from __future__ import annotations

import re

from app.db.models.user import AccessLevel
from app.ssh.initialize import build_initialize_command, service_user_for, wrap_for_sudo
from tests.conftest import create_company


def _csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


async def test_nav_shows_initialize_for_a_write_user(client):
    response = await client.get("/dashboard")
    assert response.status_code == 200
    assert 'href="/initialize"' in response.text


async def test_nav_hides_initialize_for_a_read_only_user(client, login_as, db_session_factory):
    company = await create_company(db_session_factory)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ)
    response = await client.get("/dashboard")
    assert response.status_code == 200
    assert 'href="/initialize"' not in response.text


async def test_get_initialize_form_has_expected_fields(client):
    response = await client.get("/initialize")
    assert response.status_code == 200
    for field in ("ip_address", "device_name", "username", "port", "auth_method", "password",
                  "netbird_setup_key"):
        assert f'name="{field}"' in response.text


async def test_read_only_user_cannot_reach_initialize(client, login_as, db_session_factory):
    company = await create_company(db_session_factory)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ)
    response = await client.get("/initialize")
    assert response.status_code == 403


async def test_post_initialize_dispatches_task_and_shows_output(client, celery_calls):
    form = await client.get("/initialize")
    csrf_token = _csrf_from(form)

    response = await client.post(
        "/initialize",
        data={
            "ip_address": "192.0.2.10",
            "device_name": "acme-honey1",
            "username": "root",
            "port": "22",
            "auth_method": "ssh_key",
            "password": "",
            "netbird_setup_key": "",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 200
    assert "app.tasks.jobs.run_honeypot_initialize" in celery_calls.names
    args = celery_calls[-1][1]
    assert args[0] == "192.0.2.10"
    assert args[3] == "acme-honey1"


async def test_post_initialize_rejects_invalid_device_name(client, celery_calls):
    form = await client.get("/initialize")
    csrf_token = _csrf_from(form)

    response = await client.post(
        "/initialize",
        data={
            "ip_address": "192.0.2.10",
            "device_name": "not a valid hostname/",
            "username": "root",
            "port": "22",
            "auth_method": "ssh_key",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 200
    assert "app.tasks.jobs.run_honeypot_initialize" not in celery_calls.names


async def test_post_initialize_without_csrf_is_rejected(client):
    response = await client.post(
        "/initialize",
        data={
            "ip_address": "192.0.2.10",
            "device_name": "acme-honey1",
            "username": "root",
            "port": "22",
            "auth_method": "ssh_key",
        },
    )
    assert response.status_code == 403


def test_service_user_for_root_falls_back_to_pi():
    assert service_user_for("root") == "pi"
    assert service_user_for("pi") == "pi"
    assert service_user_for("alice") == "alice"


def test_build_initialize_command_includes_hostname_and_no_netbird_up_without_key():
    script = build_initialize_command(
        device_name="acme-honey1",
        service_user="pi",
        netbird_setup_key=None,
        netbird_management_url=None,
    )
    assert "hostnamectl set-hostname acme-honey1" in script
    assert "acme-honey1" in script  # /etc/hosts line
    assert "apt-get install -y netbird" in script
    assert "netbird up" not in script
    assert "User=pi" in script


def test_build_initialize_command_joins_netbird_when_setup_key_given():
    script = build_initialize_command(
        device_name="acme-honey1",
        service_user="pi",
        netbird_setup_key="abc123",
        netbird_management_url="https://netbird.example.com:443",
    )
    expected = "netbird up --setup-key abc123 --management-url https://netbird.example.com:443"
    assert expected in script


def test_wrap_for_sudo_root_needs_no_sudo():
    script = "echo hi\n"
    assert wrap_for_sudo(script, ssh_username="root", sudo_password=None) == script


def test_wrap_for_sudo_non_root_without_password_uses_sudo_dash_n():
    wrapped = wrap_for_sudo("echo hi\n", ssh_username="pi", sudo_password=None)
    assert "sudo -n bash /tmp/.honeyhive-initialize.sh" in wrapped
    assert "sudo -S" not in wrapped


def test_wrap_for_sudo_non_root_with_password_pipes_it_to_sudo_dash_capital_s():
    wrapped = wrap_for_sudo("echo hi\n", ssh_username="pi", sudo_password="hunter2")
    assert "echo hunter2 | sudo -S" in wrapped
