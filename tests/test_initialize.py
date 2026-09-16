"""The "Initialize" top-nav action — provisions a brand new device over SSH
before it's ever added to Honeypot Shelf. See app.web.routes.initialize and
app.ssh.initialize.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from app.db.models.user import AccessLevel, User
from app.ssh.initialize import build_initialize_command, service_user_for, wrap_for_sudo
from app.ssh.platform_detect import DetectedPlatform
from app.web.routes.initialize import PENDING_RUNS, PendingInitializeRun
from app.web.routes.initialize_ws import _persist_initialize_run
from tests.conftest import ADMIN_USERNAME, create_company

if TYPE_CHECKING:
    from fastapi import WebSocket

# Every existing test below predates cross-distro support and exercises
# what was, at the time, the only target: Raspberry Pi OS. Kept as the
# default `platform=` for all of them rather than touching each one's own
# assertions - app.ssh.platform_detect's own tests cover detection/parsing,
# and test_platform_specific_initialize_behavior below covers the actual
# Debian/Ubuntu fork (tmpfs vs. persistent log, "pi" vs. distro-default
# service user).
_RPI_PLATFORM = DetectedPlatform(
    distro="debian", codename="trixie", label="Debian 13 (trixie)", has_raspi_config=True
)


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
    for field in ("ip_address", "device_name", "username", "port", "new_ssh_port",
                  "auth_method", "password", "vpn_provider", "netbird_setup_key",
                  "netbird_management_url", "wireguard_config"):
        assert f'name="{field}"' in response.text


async def test_get_initialize_form_defaults_new_ssh_port_to_22222(client):
    from app.ssh.initialize import NEW_SSH_PORT

    assert NEW_SSH_PORT == 22222
    response = await client.get("/initialize")
    assert response.status_code == 200
    assert 'name="new_ssh_port"' in response.text
    assert f'value="{NEW_SSH_PORT}"' in response.text


async def test_get_initialize_form_prefills_from_query_params(client):
    """Used by the run page's "Back to Initialize" link so a failed run's
    fields don't have to be retyped — see `initialize_form`'s docstring."""
    response = await client.get(
        "/initialize",
        params={
            "ip_address": "192.0.2.50",
            "device_name": "acme-honey2",
            "username": "pi",
            "port": "2222",
            "auth_method": "password",
            "vpn_provider": "netbird",
            "new_ssh_port": "33333",
        },
    )
    assert response.status_code == 200
    assert 'value="192.0.2.50"' in response.text
    assert 'value="acme-honey2"' in response.text
    assert 'value="pi"' in response.text
    assert 'value="2222"' in response.text
    assert 'value="33333"' in response.text


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
    from app.ssh.initialize import NEW_SSH_PORT

    assert run.new_ssh_port == NEW_SSH_PORT  # not given in the form -> Form(NEW_SSH_PORT) default

    run_page = await client.get(location)
    assert run_page.status_code == 200
    assert f'data-ws-path="/initialize/run/{run_id}/ws"' in run_page.text
    assert "acme-honey1" in run_page.text
    # "Back to Initialize" carries the (non-secret) fields forward so a
    # failed run's inputs don't have to be retyped to retry.
    back_link = 'href="/initialize?ip_address=192.0.2.10&device_name=acme-honey1'
    assert back_link in run_page.text
    assert f"new_ssh_port={NEW_SSH_PORT}" in run_page.text

    PENDING_RUNS.pop(run_id, None)


async def test_post_initialize_with_a_custom_new_ssh_port_is_used(client):
    form = await client.get("/initialize")
    csrf_token = _csrf_from(form)

    response = await client.post(
        "/initialize",
        data={
            "ip_address": "192.0.2.11",
            "device_name": "acme-honey3",
            "username": "root",
            "port": "22",
            "new_ssh_port": "2222",
            "auth_method": "ssh_key",
            "password": "",
            "csrf_token": csrf_token,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    run_id = response.headers["location"].removeprefix("/initialize/run/")
    run = PENDING_RUNS.get(run_id)
    assert run is not None
    assert run.new_ssh_port == 2222
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
        vpn_provider="none",
        netbird_setup_key=None,
        netbird_management_url=None,
        wireguard_config=None,
        new_ssh_port=22222,
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
    assert service_user_for("root", _RPI_PLATFORM) == "pi"
    assert service_user_for("pi", _RPI_PLATFORM) == "pi"
    assert service_user_for("alice", _RPI_PLATFORM) == "alice"


def test_build_initialize_command_includes_hostname_and_installs_no_vpn_by_default():
    script = build_initialize_command(
        platform=_RPI_PLATFORM,
        device_name="acme-honey1",
        service_user="pi",
    )
    assert "hostnamectl set-hostname acme-honey1" in script
    assert "acme-honey1" in script  # /etc/hosts line
    assert "netbird" not in script
    assert "wireguard" not in script.lower()


def test_build_initialize_command_runs_opencanary_service_as_root():
    """Regression guard for a real bug found live: `User=<login account>`
    on the systemd unit meant opencanaryd could only bind privileged ports
    (ftp/http/https/...) by re-exec'ing itself via `sudo`, which only
    works when that account already has usable passwordless sudo (true
    for Raspberry Pi OS's default `pi` account, not guaranteed for any
    other). Running the unit as root (no `User=` line) sidesteps that
    assumption entirely."""
    script = build_initialize_command(
        platform=_RPI_PLATFORM, device_name="acme-honey1", service_user="pi"
    )
    assert "User=" not in script
    assert "ExecStart=/opt/myenv/bin/opencanaryd --start --uid=nobody --gid=nogroup" in script


def test_build_initialize_command_opencanary_service_is_type_forking():
    """Regression guard for a real crash-loop found live: `opencanaryd
    --start` launches the actual long-running daemon (`twistd`) as a
    separate process and exits itself almost immediately — under the
    default `Type=simple`, systemd saw its tracked "main" process exit
    right after every start and restarted the whole unit forever
    (`systemctl status` showed `Result: start-limit-hit` after 11 rapid
    restarts). `Type=forking` + the same `PIDFile` opencanaryd already
    writes fixes it — confirmed live against the actual crash-looping
    device before landing."""
    script = build_initialize_command(
        platform=_RPI_PLATFORM, device_name="acme-honey1", service_user="pi"
    )
    assert "Type=forking" in script
    assert "PIDFile=/var/run/opencanaryd.pid" in script


def test_build_initialize_command_installs_netbird_without_joining_when_no_key():
    script = build_initialize_command(
        platform=_RPI_PLATFORM,
        device_name="acme-honey1",
        service_user="pi",
        vpn_provider="netbird",
        netbird_setup_key=None,
        netbird_management_url=None,
    )
    assert "apt-get install -y netbird" in script
    assert "netbird up" not in script


def test_build_initialize_command_gpg_dearmor_never_prompts_on_a_rerun():
    """Regression guard: without --batch --yes, gpg silently asks
    "overwrite existing file?" when the NetBird keyring already exists
    from an earlier run — and since this runs over a plain SSH exec with
    no pty, gpg can't read that prompt at all, crashing with "cannot open
    '/dev/tty'" (confirmed live) instead of just overwriting it."""
    script = build_initialize_command(
        platform=_RPI_PLATFORM,
        device_name="acme-honey1", service_user="pi", vpn_provider="netbird"
    )
    assert "gpg --batch --yes --dearmor" in script


def test_build_initialize_command_joins_netbird_when_setup_key_given():
    script = build_initialize_command(
        platform=_RPI_PLATFORM,
        device_name="acme-honey1",
        service_user="pi",
        vpn_provider="netbird",
        netbird_setup_key="abc123",
        netbird_management_url="https://netbird.example.com:443",
    )
    expected = "netbird up --setup-key abc123 --management-url https://netbird.example.com:443"
    assert expected in script


def test_build_initialize_command_joins_wireguard_when_config_given():
    config = "[Interface]\nPrivateKey = abc\n[Peer]\nPublicKey = xyz\nEndpoint = 1.2.3.4:51820"
    script = build_initialize_command(
        platform=_RPI_PLATFORM,
        device_name="acme-honey1",
        service_user="pi",
        vpn_provider="wireguard",
        wireguard_config=config,
    )
    assert "apt-get install -y wireguard-tools" in script
    assert "wg-quick up wg0" in script
    assert "PrivateKey = abc" in script
    assert "netbird" not in script


def test_build_initialize_command_sets_up_tmpfs_ramdisk():
    from app.ssh.initialize import TMPFS_PATH, TMPFS_SIZE_MB

    script = build_initialize_command(
        platform=_RPI_PLATFORM,
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
        platform=_RPI_PLATFORM,
        device_name="acme-honey1",
        service_user="pi",
        netbird_setup_key=None,
        netbird_management_url=None,
    )
    assert f'"filename"] = "{HONEYPOT_LOG_PATH}"' in script


def test_build_initialize_command_skips_tmpfs_and_uses_persistent_log_without_raspi_config():
    """Debian/Ubuntu: no SD card, no reason to keep OpenCanary's log off
    real storage — see PERSISTENT_LOG_PATH's own comment."""
    from app.ssh.initialize import PERSISTENT_LOG_PATH, TMPFS_PATH

    debian_platform = DetectedPlatform(
        distro="debian", codename="bookworm", label="Debian 12 (bookworm)", has_raspi_config=False
    )
    script = build_initialize_command(
        platform=debian_platform,
        device_name="acme-honey1",
        service_user="debian",
        netbird_setup_key=None,
        netbird_management_url=None,
    )
    assert f"mkdir -p {TMPFS_PATH}" not in script
    assert "mountpoint -q" not in script
    assert f"install -d -m 1777 {PERSISTENT_LOG_PATH.rsplit('/', 1)[0]}" in script
    assert f'"filename"] = "{PERSISTENT_LOG_PATH}"' in script


def test_build_initialize_command_ubuntu_also_uses_persistent_log():
    from app.ssh.initialize import PERSISTENT_LOG_PATH

    ubuntu_platform = DetectedPlatform(
        distro="ubuntu",
        codename="noble",
        label="Ubuntu 24.04 LTS (Noble Numbat)",
        has_raspi_config=False,
    )
    script = build_initialize_command(
        platform=ubuntu_platform,
        device_name="acme-honey1",
        service_user="ubuntu",
        netbird_setup_key=None,
        netbird_management_url=None,
    )
    assert f'"filename"] = "{PERSISTENT_LOG_PATH}"' in script


def test_service_user_for_falls_back_to_distro_default_when_no_raspi_config():
    debian_platform = DetectedPlatform(
        distro="debian", codename="bookworm", label="Debian 12 (bookworm)", has_raspi_config=False
    )
    ubuntu_platform = DetectedPlatform(
        distro="ubuntu",
        codename="noble",
        label="Ubuntu 24.04 LTS (Noble Numbat)",
        has_raspi_config=False,
    )
    assert service_user_for("root", debian_platform) == "debian"
    assert service_user_for("root", ubuntu_platform) == "ubuntu"
    assert service_user_for("root", _RPI_PLATFORM) == "pi"
    # A non-root login account is always used as-is, regardless of platform.
    assert service_user_for("alice", debian_platform) == "alice"


def test_build_initialize_command_generates_config_only_if_missing():
    script = build_initialize_command(
        platform=_RPI_PLATFORM,
        device_name="acme-honey1",
        service_user="pi",
        netbird_setup_key=None,
        netbird_management_url=None,
    )
    assert "[ -f /etc/opencanaryd/opencanary.conf ] ||" in script
    assert "opencanaryd --copyconfig" in script


def test_build_initialize_command_prepares_portscan():
    script = build_initialize_command(
        platform=_RPI_PLATFORM,
        device_name="acme-honey1",
        service_user="pi",
        netbird_setup_key=None,
        netbird_management_url=None,
    )
    assert 'module(load="imjournal")' in script
    assert "kern.log" in script
    assert "update-alternatives --set iptables /usr/sbin/iptables-legacy" in script
    assert '"portscan.iptables_path"' in script


def test_build_initialize_command_makes_kern_log_world_readable():
    """Regression guard: rsyslog's own default $FileCreateMode/$FileOwner/
    $FileGroup (0640 root:adm) would otherwise make a freshly created
    kern.log unreadable by opencanaryd's unprivileged nobody:nogroup once
    the portscan module tails it."""
    script = build_initialize_command(
        platform=_RPI_PLATFORM, device_name="acme-honey1", service_user="pi"
    )
    assert "touch /var/log/kern.log" in script
    assert "chmod 644 /var/log/kern.log" in script


def test_build_initialize_command_prepares_samba_with_service_disabled():
    script = build_initialize_command(
        platform=_RPI_PLATFORM,
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


def test_build_initialize_command_does_not_chown_to_the_nonexistent_syslog_user():
    """Regression guard: `chown syslog:adm` used to crash the whole run
    with "invalid user: 'syslog'" — Debian trixie's rsyslog package no
    longer creates that dedicated system user (rsyslogd runs as root via
    systemd capabilities instead). `chmod 644` (root-owned) is all the
    file actually needs — rsyslogd itself runs as root regardless of file
    ownership, and opencanaryd's smb module, which tails this file as
    nobody:nogroup, only needs world-read."""
    script = build_initialize_command(
        platform=_RPI_PLATFORM, device_name="acme-honey1", service_user="pi"
    )
    assert "syslog:adm" not in script
    assert "chmod 644 /var/log/samba-audit.log" in script
    assert '"portscan.enabled": true' not in script


def test_build_initialize_command_does_not_install_mlocate():
    """Regression guard: mlocate was dropped from the Debian archive as of
    trixie (13, what Raspberry Pi OS 13 is based on) — `apt-get install
    mlocate` fails outright there. `plocate` is its drop-in replacement."""
    script = build_initialize_command(
        platform=_RPI_PLATFORM, device_name="acme-honey1", service_user="pi"
    )
    assert "mlocate" not in script
    assert "plocate" in script


def test_build_initialize_command_moves_ssh_to_the_new_port_last():
    from app.ssh.initialize import INITIALIZE_SUCCESS_MARKER, NEW_SSH_PORT

    script = build_initialize_command(
        platform=_RPI_PLATFORM, device_name="acme-honey1", service_user="pi"
    )
    assert (
        f"echo 'Port {NEW_SSH_PORT}' > /etc/ssh/sshd_config.d/honeypotshelf-ssh-port.conf"
        in script
    )
    assert "sshd -t" in script
    assert "systemctl restart ssh" in script
    # Validated (and, if invalid, `set -e` aborts) before ever restarting —
    # a broken generated config must never take down the running daemon.
    assert script.index("sshd -t") < script.index("systemctl restart ssh")
    # Last of all real work, right before the success marker — every other
    # step must already have succeeded before this one ever runs.
    assert script.index("systemctl restart ssh") < script.index(INITIALIZE_SUCCESS_MARKER)
    apt_install_index = script.index("apt-get install -y ")
    assert apt_install_index < script.index("systemctl restart ssh")


def test_build_initialize_command_honors_a_custom_new_ssh_port():
    script = build_initialize_command(
        platform=_RPI_PLATFORM,
        device_name="acme-honey1", service_user="pi", new_ssh_port=2222
    )
    assert "echo 'Port 2222' > /etc/ssh/sshd_config.d/honeypotshelf-ssh-port.conf" in script
    assert "Port 22222" not in script


def test_build_initialize_command_installs_authorized_keys_when_given():
    key = "ssh-ed25519 AAAAfake honeypotshelf"
    script = build_initialize_command(
        platform=_RPI_PLATFORM,
        device_name="acme-honey1",
        service_user="pi",
        ssh_username="pi",
        authorized_keys=[key],
    )
    assert "getent passwd" in script
    assert key in script
    # Installed before the port change, never after — see the module
    # docstring for why the port change stays strictly last.
    assert script.index(key) < script.index("systemctl restart ssh")


def test_build_initialize_command_skips_authorized_keys_step_when_none_given():
    script = build_initialize_command(
        platform=_RPI_PLATFORM, device_name="acme-honey1", service_user="pi"
    )
    assert "getent passwd" not in script


def test_build_initialize_command_grants_passwordless_sudo_for_a_non_root_connection():
    script = build_initialize_command(
        platform=_RPI_PLATFORM,
        device_name="acme-honey1", service_user="pi", ssh_username="pi"
    )
    assert "pi ALL=(root) NOPASSWD" in script
    assert "/usr/bin/apt-get" in script
    assert "/usr/sbin/shutdown" in script
    assert "/usr/sbin/dmidecode" in script
    assert "/usr/bin/systemctl" in script
    assert "visudo -cf" in script


def test_build_initialize_command_skips_sudo_grant_for_a_root_connection():
    """Root never needs sudo granted to itself — see app.ssh.readiness's
    module docstring for the same reasoning applied on the read side."""
    script = build_initialize_command(
        platform=_RPI_PLATFORM,
        device_name="acme-honey1", service_user="pi", ssh_username="root"
    )
    assert "NOPASSWD" not in script


def test_build_initialize_command_skips_sudo_grant_when_no_ssh_username_given():
    script = build_initialize_command(
        platform=_RPI_PLATFORM, device_name="acme-honey1", service_user="pi"
    )
    assert "NOPASSWD" not in script


def test_build_initialize_command_installs_ncurses_term():
    script = build_initialize_command(
        platform=_RPI_PLATFORM, device_name="acme-honey1", service_user="pi"
    )
    assert "ncurses-term" in script


def test_build_initialize_command_reboots_last_of_all():
    from app.ssh.initialize import INITIALIZE_SUCCESS_MARKER

    script = build_initialize_command(
        platform=_RPI_PLATFORM, device_name="acme-honey1", service_user="pi"
    )
    assert "reboot" in script
    # After the success marker, not before — a reader (app.web.routes.
    # initialize_ws) must see "the script succeeded" before the reboot
    # trigger, since the connection may not survive much longer either way.
    assert script.index(INITIALIZE_SUCCESS_MARKER) < script.rindex("reboot")
    assert script.rstrip().endswith("disown")


def test_build_initialize_command_emits_step_markers():
    from app.ssh.initialize import STEP_MARKER_PREFIX

    script = build_initialize_command(
        platform=_RPI_PLATFORM,
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
    assert "sudo -n bash /tmp/.honeypotshelf-initialize.sh" in wrapped
    assert "sudo -S" not in wrapped


def test_wrap_for_sudo_non_root_with_password_pipes_it_to_sudo_dash_capital_s():
    wrapped = wrap_for_sudo("echo hi\n", ssh_username="pi", sudo_password="hunter2")
    assert "echo hunter2 | sudo -S" in wrapped


# --- _wait_for_reboot: the post-script "did it actually come back up"
# phase — mocked SSH probe, no network, and every timing constant patched
# down to ~0 so the tests run instantly instead of waiting out the real
# multi-minute budget. ---


class _FakeWebSocket:
    def __init__(self) -> None:
        self.sent: list[dict[str, object]] = []

    async def send_text(self, text: str) -> None:
        import json

        self.sent.append(json.loads(text))


async def test_wait_for_reboot_succeeds_once_the_device_answers_again(monkeypatch):
    import app.web.routes.initialize_ws as initialize_ws_module

    monkeypatch.setattr(initialize_ws_module, "REBOOT_GRACE_SECONDS", 0)
    monkeypatch.setattr(initialize_ws_module, "REBOOT_POLL_INTERVAL_SECONDS", 0)
    monkeypatch.setattr(initialize_ws_module, "REBOOT_WAIT_MAX_SECONDS", 5)

    async def fake_discover(host: str, port: int, timeout_seconds: int) -> str:
        return "SHA256:samefingerprint"

    monkeypatch.setattr(initialize_ws_module, "discover_host_key_fingerprint", fake_discover)

    websocket = _FakeWebSocket()
    error = await initialize_ws_module._wait_for_reboot(
        cast("WebSocket", websocket), "192.0.2.10", 22222, "SHA256:samefingerprint"
    )
    assert error is None
    assert any(m.get("label") == "Back up after reboot" for m in websocket.sent)


async def test_wait_for_reboot_reports_a_fingerprint_mismatch_immediately(monkeypatch):
    import app.web.routes.initialize_ws as initialize_ws_module

    monkeypatch.setattr(initialize_ws_module, "REBOOT_GRACE_SECONDS", 0)
    monkeypatch.setattr(initialize_ws_module, "REBOOT_POLL_INTERVAL_SECONDS", 0)
    monkeypatch.setattr(initialize_ws_module, "REBOOT_WAIT_MAX_SECONDS", 5)

    async def fake_discover(host: str, port: int, timeout_seconds: int) -> str:
        return "SHA256:adifferentfingerprint"

    monkeypatch.setattr(initialize_ws_module, "discover_host_key_fingerprint", fake_discover)

    websocket = _FakeWebSocket()
    error = await initialize_ws_module._wait_for_reboot(
        cast("WebSocket", websocket), "192.0.2.10", 22222, "SHA256:originalfingerprint"
    )
    assert error is not None
    assert "different SSH host key" in error


async def test_wait_for_reboot_times_out_if_the_device_never_comes_back(monkeypatch):
    import app.web.routes.initialize_ws as initialize_ws_module
    from app.ssh.exceptions import SSHConnectionError

    monkeypatch.setattr(initialize_ws_module, "REBOOT_GRACE_SECONDS", 0)
    monkeypatch.setattr(initialize_ws_module, "REBOOT_POLL_INTERVAL_SECONDS", 0)
    monkeypatch.setattr(initialize_ws_module, "REBOOT_WAIT_MAX_SECONDS", 0)

    async def fake_discover(host: str, port: int, timeout_seconds: int) -> str:
        raise SSHConnectionError("connection refused")

    monkeypatch.setattr(initialize_ws_module, "discover_host_key_fingerprint", fake_discover)

    websocket = _FakeWebSocket()
    error = await initialize_ws_module._wait_for_reboot(
        cast("WebSocket", websocket), "192.0.2.10", 22222, "SHA256:originalfingerprint"
    )
    assert error is not None
    assert "didn't come back up" in error
