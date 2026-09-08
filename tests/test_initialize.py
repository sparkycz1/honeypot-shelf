"""The "Initialize" top-nav action — provisions a brand new device over SSH
before it's ever added to HoneyHive. See app.web.routes.initialize and
app.ssh.initialize.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

from app.db.models.user import AccessLevel, User
from app.ssh.initialize import build_initialize_command, service_user_for, wrap_for_sudo
from app.web.routes.initialize import PENDING_RUNS, PendingInitializeRun
from app.web.routes.initialize_ws import _persist_initialize_run
from tests.conftest import ADMIN_USERNAME, create_company


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
                  "netbird_setup_key", "netbird_management_url"):
        assert f'name="{field}"' in response.text


async def test_read_only_user_cannot_reach_initialize(client, login_as, db_session_factory):
    company = await create_company(db_session_factory)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ)
    response = await client.get("/initialize")
    assert response.status_code == 403


async def test_post_initialize_stages_a_pending_run_and_redirects(client):
    """POST doesn't run anything inline (it can take up to an hour) — it
    stages a `PendingInitializeRun` and redirects to the run page, which
    connects `initialize_ws`'s WebSocket to actually do the work. See
    app.web.routes.initialize's module docstring."""
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
            "netbird_management_url": "https://netbird.example.com:443",
            "csrf_token": csrf_token,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/initialize/run/")
    run_id = location.removeprefix("/initialize/run/")

    run = PENDING_RUNS.get(run_id)
    assert run is not None
    assert run.ip_address == "192.0.2.10"
    assert run.device_name == "acme-honey1"
    assert run.auth_method == "ssh_key"
    assert run.netbird_management_url == "https://netbird.example.com:443"

    run_page = await client.get(location)
    assert run_page.status_code == 200
    assert f'data-ws-path="/initialize/run/{run_id}/ws"' in run_page.text
    assert "acme-honey1" in run_page.text

    PENDING_RUNS.pop(run_id, None)


async def test_post_initialize_rejects_malformed_netbird_url(client):
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
            "netbird_management_url": "not-a-url",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 200
    assert "http://" in response.text


async def test_initialize_run_history(client, db_session_factory):
    """`_persist_initialize_run` (called from `initialize_ws`'s `finally`
    block once a run finishes) is what makes a failed provisioning
    debuggable after the WebSocket/tab is gone — see `InitializeRun`'s
    module docstring. Exercised directly here rather than through a real
    SSH connection, same as the rest of this file does for the script
    builder."""
    user = User(username=ADMIN_USERNAME, is_superadmin=True)
    run = PendingInitializeRun(
        ip_address="192.0.2.20",
        port=22,
        username="root",
        device_name="acme-honey2",
        auth_method="ssh_key",
        password=None,
        netbird_setup_key=None,
        netbird_management_url=None,
    )
    await _persist_initialize_run(
        db_session_factory,
        user=user,
        run=run,
        started_at=datetime.now(UTC),
        error="Setup script exited 1.",
        fingerprint=None,
        output_lines=["line one", "line two"],
    )

    history = await client.get("/initialize/history")
    assert history.status_code == 200
    assert "acme-honey2" in history.text

    match = re.search(r'/initialize/history/([0-9a-f-]+)"', history.text)
    assert match, "no history detail link found"
    run_id = uuid.UUID(match.group(1))

    detail = await client.get(f"/initialize/history/{run_id}")
    assert detail.status_code == 200
    assert "line one" in detail.text
    assert "Setup script exited 1." in detail.text


async def test_get_run_page_for_an_unknown_run_id_redirects_to_the_form(client):
    response = await client.get("/initialize/run/does-not-exist", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/initialize"


async def test_post_initialize_rejects_invalid_device_name(client):
    form = await client.get("/initialize")
    csrf_token = _csrf_from(form)

    before = set(PENDING_RUNS)
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
    assert set(PENDING_RUNS) == before


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


def test_build_initialize_command_sets_up_tmpfs_ramdisk():
    from app.ssh.initialize import TMPFS_PATH, TMPFS_SIZE_MB

    script = build_initialize_command(
        device_name="acme-honey1",
        service_user="pi",
        netbird_setup_key=None,
        netbird_management_url=None,
    )
    assert f"mkdir -p {TMPFS_PATH}" in script
    assert f"size={TMPFS_SIZE_MB}M" in script
    assert f"mountpoint -q {TMPFS_PATH} || mount {TMPFS_PATH}" in script


def test_build_initialize_command_repoints_opencanary_log_to_tmpfs():
    from app.ssh.logs import HONEYPOT_LOG_PATH

    script = build_initialize_command(
        device_name="acme-honey1",
        service_user="pi",
        netbird_setup_key=None,
        netbird_management_url=None,
    )
    assert f'"filename"] = "{HONEYPOT_LOG_PATH}"' in script


def test_build_initialize_command_generates_config_only_if_missing():
    script = build_initialize_command(
        device_name="acme-honey1",
        service_user="pi",
        netbird_setup_key=None,
        netbird_management_url=None,
    )
    assert "[ -f /etc/opencanaryd/opencanary.conf ] ||" in script
    assert "opencanaryd --copyconfig" in script


def test_build_initialize_command_prepares_portscan():
    script = build_initialize_command(
        device_name="acme-honey1",
        service_user="pi",
        netbird_setup_key=None,
        netbird_management_url=None,
    )
    assert 'module(load="imjournal")' in script
    assert "kern.log" in script
    assert "update-alternatives --set iptables /usr/sbin/iptables-legacy" in script
    assert '"portscan.iptables_path"' in script


def test_build_initialize_command_prepares_samba_with_service_disabled():
    script = build_initialize_command(
        device_name="acme-honey1",
        service_user="pi",
        netbird_setup_key=None,
        netbird_management_url=None,
    )
    assert "/etc/samba/smb.conf" in script
    assert "vfs object = full_audit" in script
    assert "netbios name = acme-honey1" in script
    assert '"smb.auditfile"' in script
    assert "systemctl disable --now smbd" in script
    assert "systemctl disable --now nmbd" in script
    # Prepared, not switched on — enabling either module is a separate,
    # deliberate manual step.
    assert '"smb.enabled": true' not in script
    assert '"portscan.enabled": true' not in script


def test_build_initialize_command_emits_step_markers():
    from app.ssh.initialize import STEP_MARKER_PREFIX

    script = build_initialize_command(
        device_name="acme-honey1",
        service_user="pi",
        netbird_setup_key=None,
        netbird_management_url=None,
    )
    assert f"echo '{STEP_MARKER_PREFIX}Installing packages'" in script
    assert f"echo '{STEP_MARKER_PREFIX}Preparing Samba (service left disabled)'" in script


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
