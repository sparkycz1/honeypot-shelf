"""The Honeypot Config tab's OpenCanary module editor. See
app.ssh.opencanary_config and app.web.routes.honeypots's config routes.
"""

from __future__ import annotations

import re

from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.ssh.opencanary_config import (
    OPENCANARY_CONFIG_PATH,
    OPENCANARY_MODULES,
    apply_form_to_config,
    build_read_command,
    build_write_command,
    field_value,
    module_enabled,
    parse_config,
)
from tests.conftest import create_company

_SAMPLE_CONFIG = {
    "device.node_id": "opencanary-1",
    "ftp.enabled": True,
    "ftp.port": 21,
    "ftp.banner": "FTP server ready",
    "http.enabled": False,
    "http.port": 80,
    "smb.enabled": False,
    "smb.auditfile": "/var/log/samba-audit.log",
    "portscan.ignore_ports": [22, 8080],
    "logger": {"class": "PyLogger"},
    "telnet.honeycreds": [{"username": "admin", "password": "hunter2"}],
}


def test_parse_config_reads_flat_dotted_json():
    config = parse_config('{"ftp.enabled": true, "ftp.port": 21}')
    assert config == {"ftp.enabled": True, "ftp.port": 21}


def test_module_enabled_true_and_false():
    ftp = next(m for m in OPENCANARY_MODULES if m.key == "ftp")
    http = next(m for m in OPENCANARY_MODULES if m.key == "http")
    assert module_enabled(_SAMPLE_CONFIG, ftp) is True
    assert module_enabled(_SAMPLE_CONFIG, http) is False


def test_module_enabled_none_for_always_on_module():
    general = next(m for m in OPENCANARY_MODULES if m.key == "general")
    assert general.enabled_key is None
    assert module_enabled(_SAMPLE_CONFIG, general) is True


def test_field_value_scalar_and_list():
    ftp_port = next(
        f for m in OPENCANARY_MODULES if m.key == "ftp" for f in m.fields if f.key == "ftp.port"
    )
    assert field_value(_SAMPLE_CONFIG, ftp_port) == 21

    ignore_ports = next(
        f
        for m in OPENCANARY_MODULES
        if m.key == "portscan"
        for f in m.fields
        if f.key == "portscan.ignore_ports"
    )
    assert field_value(_SAMPLE_CONFIG, ignore_ports) == "22, 8080"


def test_field_value_falls_back_to_default_when_missing():
    mysql_port = next(
        f
        for m in OPENCANARY_MODULES
        if m.key == "mysql"
        for f in m.fields
        if f.key == "mysql.port"
    )
    assert field_value({}, mysql_port) == 3306


def test_apply_form_to_config_preserves_unmanaged_keys():
    updated = apply_form_to_config(_SAMPLE_CONFIG, {})
    assert updated["logger"] == {"class": "PyLogger"}
    assert updated["telnet.honeycreds"] == [{"username": "admin", "password": "hunter2"}]


def test_apply_form_to_config_toggles_enabled_and_updates_fields():
    updated = apply_form_to_config(
        _SAMPLE_CONFIG,
        {
            "ftp.enabled": "on",  # present -> checked
            "ftp.port": "2121",
            "ftp.banner": "custom banner",
            # http.enabled absent -> stays disabled
            "smb.enabled": "on",
        },
    )
    assert updated["ftp.enabled"] is True
    assert updated["ftp.port"] == 2121
    assert updated["ftp.banner"] == "custom banner"
    assert updated["http.enabled"] is False
    assert updated["smb.enabled"] is True


def test_apply_form_to_config_parses_list_fields():
    updated = apply_form_to_config(
        _SAMPLE_CONFIG, {"portscan.ignore_ports": "22, 80, 443"}
    )
    assert updated["portscan.ignore_ports"] == ["22", "80", "443"]


def test_apply_form_to_config_ignores_unparseable_int():
    updated = apply_form_to_config(_SAMPLE_CONFIG, {"ftp.port": "not-a-number"})
    assert updated["ftp.port"] == 21  # unchanged, not crashed


def test_apply_form_to_config_does_not_mutate_input():
    original = dict(_SAMPLE_CONFIG)
    apply_form_to_config(_SAMPLE_CONFIG, {"ftp.enabled": "on"})
    assert _SAMPLE_CONFIG == original


def test_build_read_command_reads_the_conf_path():
    command = build_read_command()
    assert OPENCANARY_CONFIG_PATH in command
    assert "sudo -n" in command


def test_build_write_command_restarts_opencanary_and_toggles_smb():
    disabled = build_write_command({**_SAMPLE_CONFIG, "smb.enabled": False})
    assert "systemctl restart opencanary" in disabled
    assert "systemctl disable --now smbd nmbd" in disabled
    assert "systemctl enable --now smbd nmbd" not in disabled

    enabled = build_write_command({**_SAMPLE_CONFIG, "smb.enabled": True})
    assert "systemctl enable --now smbd nmbd" in enabled


def test_every_module_and_field_label_key_is_distinct_from_its_value():
    # Sanity check on the schema itself: every key referenced actually
    # looks like an i18n key (namespaced, lowercase, dotted) rather than a
    # literal English string accidentally left in a label_key/name_key/
    # hint_key slot.
    for module in OPENCANARY_MODULES:
        assert module.name_key.startswith("honeypots.config.")
        if module.hint_key:
            assert module.hint_key.startswith("honeypots.config.")
        for f in module.fields:
            assert f.label_key.startswith("honeypots.config.")


async def _create_pinned_honeypot(db_session_factory, company_id) -> Honeypot:
    async with db_session_factory() as db:
        company = await db.get(Company, company_id)
        honeypot = Honeypot(
            companies=[company],
            name="acme-honey1",
            ip_address="192.0.2.10",
            port=22,
            username="honeypotshelf",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fake-fingerprint-for-tests",
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
    return honeypot


async def test_config_tab_shows_module_states_from_ssh_read(
    client, db_session_factory, celery_calls
):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)
    celery_calls.result_for["app.tasks.jobs.read_honeypot_opencanary_config"] = {
        "ok": True,
        "config": {"ftp.enabled": True, "http.enabled": False},
    }

    response = await client.get(f"/honeypots/{honeypot.id}/config")
    assert response.status_code == 200
    assert "OpenCanary modules" in response.text
    assert "FTP" in response.text


async def test_save_modules_reads_merges_and_writes_config(
    client, db_session_factory, celery_calls
):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)
    celery_calls.result_for["app.tasks.jobs.read_honeypot_opencanary_config"] = {
        "ok": True,
        "config": {"ftp.enabled": False, "ftp.port": 21},
    }
    celery_calls.result_for["app.tasks.jobs.write_honeypot_opencanary_config"] = {"ok": True}

    form = await client.get(f"/honeypots/{honeypot.id}/config")
    match = re.search(r'name="csrf_token" value="([^"]+)"', form.text)
    assert match
    csrf_token = match.group(1)

    response = await client.post(
        f"/honeypots/{honeypot.id}/config/modules",
        data={"csrf_token": csrf_token, "ftp.enabled": "on", "ftp.port": "2121"},
    )
    assert response.status_code == 200
    assert "Config saved and applied." in response.text

    write_call = next(
        c for c in celery_calls if c[0] == "app.tasks.jobs.write_honeypot_opencanary_config"
    )
    sent_honeypot_id, sent_config = write_call[1]
    assert sent_honeypot_id == str(honeypot.id)
    assert sent_config["ftp.enabled"] is True
    assert sent_config["ftp.port"] == 2121


async def test_save_modules_requires_write_access(client, login_as, db_session_factory):
    from app.db.models.user import AccessLevel

    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ)

    response = await client.post(
        f"/honeypots/{honeypot.id}/config/modules",
        data={"csrf_token": "x"},
    )
    assert response.status_code == 403


async def test_save_modules_tags_the_honeypot_with_enabled_modules_and_untags_disabled(
    client, db_session_factory, celery_calls
):
    """Regression guard for an explicit feature request: saving the module
    editor should tag the honeypot with exactly its enabled modules,
    untag whichever got turned off, and never touch a manually-added tag
    (here, "prod")."""
    from sqlalchemy import select

    from app.db.models.honeypot_tag import Tag, honeypot_tags
    from app.services.honeypot_tags import set_honeypot_tags

    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)
    async with db_session_factory() as db:
        db_honeypot = await db.get(Honeypot, honeypot.id)
        assert db_honeypot is not None
        # Already tagged "http" (as if a previous save enabled it) and
        # "prod" (added by hand) — http should be dropped once its module
        # is off in the new config, "prod" must survive untouched.
        await set_honeypot_tags(db, db_honeypot, ["http", "prod"])
        await db.commit()

    celery_calls.result_for["app.tasks.jobs.read_honeypot_opencanary_config"] = {
        "ok": True,
        "config": {"ftp.enabled": False, "http.enabled": True, "ssh.enabled": True},
    }
    celery_calls.result_for["app.tasks.jobs.write_honeypot_opencanary_config"] = {"ok": True}

    form = await client.get(f"/honeypots/{honeypot.id}/config")
    match = re.search(r'name="csrf_token" value="([^"]+)"', form.text)
    assert match
    csrf_token = match.group(1)

    response = await client.post(
        f"/honeypots/{honeypot.id}/config/modules",
        data={
            "csrf_token": csrf_token,
            "ftp.enabled": "on",  # turning ftp ON
            # http.enabled deliberately omitted — an unchecked checkbox
            # never submits at all, turning http OFF.
            "ssh.enabled": "on",  # left ON
        },
    )
    assert response.status_code == 200

    async with db_session_factory() as db:
        result = await db.execute(
            select(Tag.name)
            .select_from(honeypot_tags)
            .join(Tag, Tag.id == honeypot_tags.c.tag_id)
            .where(honeypot_tags.c.honeypot_id == honeypot.id)
        )
        names = set(result.scalars().all())

    assert names == {"ftp", "ssh", "prod"}


def test_enabled_module_tag_names_only_lists_toggled_on_modules():
    from app.ssh.opencanary_config import enabled_module_tag_names

    config = {"ftp.enabled": True, "http.enabled": False, "ssh.enabled": True}
    names = enabled_module_tag_names(config)
    assert "ftp" in names
    assert "ssh" in names
    assert "http" not in names
    assert "general" not in names  # config-only, never a toggleable service
