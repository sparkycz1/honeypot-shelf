"""app.ssh.readiness's parsing — including the `systemctl` sudo probe
added for the Honeypot Config tab's module editor (app.ssh.opencanary_config
needs `sudo systemctl restart opencanary`/`enable`/`disable` to apply a
save)."""

from __future__ import annotations

from app.ssh.readiness import missing_requirements, parse_readiness_output


def test_parse_readiness_output_all_ok():
    raw = (
        "===NCURSES_TERM===\nok\n"
        "===APT_SUDO===\nok\n"
        "===SHUTDOWN_SUDO===\nok\n"
        "===DMIDECODE_SUDO===\nok\n"
        "===SYSTEMCTL_SUDO===\nok\n"
        "===RASPI_CONFIG_SUDO===\nok\n"
        "===FLATPAK_SNAP_PRESENT===\nno\n"
        "===FLATPAK_SNAP_SUDO===\nok\n"
    )
    result = parse_readiness_output(raw)
    assert result["systemctl_sudo_ok"] is True
    assert result["raspi_config_sudo_ok"] is True
    assert missing_requirements(result) == []


def test_parse_readiness_output_missing_systemctl_sudo():
    raw = (
        "===NCURSES_TERM===\nok\n"
        "===APT_SUDO===\nok\n"
        "===SHUTDOWN_SUDO===\nok\n"
        "===DMIDECODE_SUDO===\nok\n"
        "===SYSTEMCTL_SUDO===\nmissing\n"
        "===RASPI_CONFIG_SUDO===\nok\n"
        "===FLATPAK_SNAP_PRESENT===\nno\n"
        "===FLATPAK_SNAP_SUDO===\nok\n"
    )
    result = parse_readiness_output(raw)
    assert result["systemctl_sudo_ok"] is False
    missing = missing_requirements(result)
    assert any("systemctl" in item for item in missing)


def test_parse_readiness_output_missing_raspi_config_sudo():
    raw = (
        "===NCURSES_TERM===\nok\n"
        "===APT_SUDO===\nok\n"
        "===SHUTDOWN_SUDO===\nok\n"
        "===DMIDECODE_SUDO===\nok\n"
        "===SYSTEMCTL_SUDO===\nok\n"
        "===RASPI_CONFIG_SUDO===\nmissing\n"
        "===FLATPAK_SNAP_PRESENT===\nno\n"
        "===FLATPAK_SNAP_SUDO===\nok\n"
    )
    result = parse_readiness_output(raw)
    assert result["raspi_config_sudo_ok"] is False
    missing = missing_requirements(result)
    assert any("raspi-config" in item for item in missing)


def test_parse_readiness_output_missing_section_reads_as_not_ok():
    # A dropped connection partway through — everything after that point
    # should read as "not ok", never silently "fine".
    result = parse_readiness_output("===NCURSES_TERM===\nok\n")
    assert result["systemctl_sudo_ok"] is False
