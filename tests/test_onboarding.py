"""app.ssh.onboarding — the honeypot-onboarding script builder, and
`build_sudoers_grant_command`, the scoped passwordless-sudo grant it
shares with `app.ssh.initialize` (see that module's own tests)."""

from __future__ import annotations

from app.ssh.onboarding import (
    ONBOARD_SUCCESS_MARKER,
    ONBOARD_USERNAME,
    build_onboarding_command,
    build_sudoers_grant_command,
)


def test_build_sudoers_grant_command_grants_exactly_the_readiness_scope():
    command = build_sudoers_grant_command("pi")
    assert "/usr/bin/apt-get" in command
    assert "/usr/sbin/shutdown" in command
    assert "/usr/sbin/dmidecode" in command
    assert "/usr/bin/systemctl" in command
    assert "NOPASSWD" in command
    assert "visudo -cf" in command  # validated before ever taking effect


def test_build_sudoers_grant_command_grants_raspi_config_and_honeyhive_scripts():
    command = build_sudoers_grant_command("pi")
    assert "/usr/bin/raspi-config" in command
    assert "/usr/bin/bash /tmp/.honeyhive-*" in command


def test_build_sudoers_grant_command_conditionally_grants_flatpak_snap():
    command = build_sudoers_grant_command("pi")
    assert "/usr/bin/flatpak" in command
    assert "/usr/bin/snap" in command
    assert 'command -v flatpak' in command


def test_build_onboarding_command_includes_the_sudoers_grant():
    script = build_onboarding_command("ssh-ed25519 AAAAfake honeyhive")
    assert f"{ONBOARD_USERNAME} ALL=(root) NOPASSWD" in script
    assert "/usr/bin/apt-get" in script
    assert script.rstrip().endswith(ONBOARD_SUCCESS_MARKER)


def test_build_onboarding_command_installs_the_given_key_idempotently():
    key = "ssh-ed25519 AAAAfake honeyhive"
    script = build_onboarding_command(key)
    assert script.count("grep -qxF") == 1
    assert key in script
