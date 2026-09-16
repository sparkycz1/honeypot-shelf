"""app.ssh.readiness's parsing — including the `systemctl` sudo probe
added for the Honeypot Config tab's module editor (app.ssh.opencanary_config
needs `sudo systemctl restart opencanary`/`enable`/`disable` to apply a
save), and the raspi-config presence/sudo split (app.ssh.platform_detect)
— raspi-config genuinely doesn't exist on Debian/Ubuntu, so
`missing_requirements` must never report its sudo grant as missing on a
device that was never going to have it."""

from __future__ import annotations

from app.ssh.readiness import missing_requirements, parse_readiness_output


def test_parse_readiness_output_all_ok():
    raw = (
        "===NCURSES_TERM===\nok\n"
        "===APT_SUDO===\nok\n"
        "===SHUTDOWN_SUDO===\nok\n"
        "===DMIDECODE_SUDO===\nok\n"
        "===SYSTEMCTL_SUDO===\nok\n"
        "===RASPI_CONFIG_PRESENT===\nyes\n"
        "===RASPI_CONFIG_SUDO===\nok\n"
        "===FLATPAK_SNAP_PRESENT===\nno\n"
        "===FLATPAK_SNAP_SUDO===\nok\n"
    )
    result = parse_readiness_output(raw)
    assert result["systemctl_sudo_ok"] is True
    assert result["raspi_config_present"] is True
    assert result["raspi_config_sudo_ok"] is True
    assert missing_requirements(result) == []


def test_parse_readiness_output_missing_systemctl_sudo():
    raw = (
        "===NCURSES_TERM===\nok\n"
        "===APT_SUDO===\nok\n"
        "===SHUTDOWN_SUDO===\nok\n"
        "===DMIDECODE_SUDO===\nok\n"
        "===SYSTEMCTL_SUDO===\nmissing\n"
        "===RASPI_CONFIG_PRESENT===\nyes\n"
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
        "===RASPI_CONFIG_PRESENT===\nyes\n"
        "===RASPI_CONFIG_SUDO===\nmissing\n"
        "===FLATPAK_SNAP_PRESENT===\nno\n"
        "===FLATPAK_SNAP_SUDO===\nok\n"
    )
    result = parse_readiness_output(raw)
    assert result["raspi_config_sudo_ok"] is False
    missing = missing_requirements(result)
    assert any("raspi-config" in item for item in missing)


def test_parse_readiness_output_raspi_config_absent_is_never_reported_missing():
    """A Debian/Ubuntu honeypot: raspi-config isn't installed at all (and
    never will be), so its missing sudo grant must not show up as a
    permanent, unfixable item in the readiness banner — same treatment
    `flatpak_snap_sudo_ok` already gets when neither is present."""
    raw = (
        "===NCURSES_TERM===\nok\n"
        "===APT_SUDO===\nok\n"
        "===SHUTDOWN_SUDO===\nok\n"
        "===DMIDECODE_SUDO===\nok\n"
        "===SYSTEMCTL_SUDO===\nok\n"
        "===RASPI_CONFIG_PRESENT===\nno\n"
        "===RASPI_CONFIG_SUDO===\nmissing\n"
        "===FLATPAK_SNAP_PRESENT===\nno\n"
        "===FLATPAK_SNAP_SUDO===\nok\n"
    )
    result = parse_readiness_output(raw)
    assert result["raspi_config_present"] is False
    assert result["raspi_config_sudo_ok"] is False
    missing = missing_requirements(result)
    assert not any("raspi-config" in item for item in missing)


def test_parse_readiness_output_missing_section_reads_as_not_ok():
    # A dropped connection partway through — everything after that point
    # should read as "not ok", never silently "fine".
    result = parse_readiness_output("===NCURSES_TERM===\nok\n")
    assert result["systemctl_sudo_ok"] is False
    assert result["raspi_config_present"] is False
