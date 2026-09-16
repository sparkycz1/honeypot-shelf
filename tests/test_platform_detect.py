"""`app.ssh.platform_detect` — parsing the OS-detection probe's output into
a `DetectedPlatform`, and rejecting anything outside the six supported
releases. See that module's own docstring for why `has_raspi_config` is a
live, separate probe rather than inferred from `ID`/codename."""

from __future__ import annotations

import pytest

from app.ssh.platform_detect import (
    SUPPORTED_RELEASES,
    UnsupportedPlatformError,
    build_detect_command,
    parse_detect_output,
)


def _raw(id_: str, codename: str, raspiconfig: str) -> str:
    return (
        f"===HONEYPOTSHELF_PLATFORM===\nID={id_}\nCODENAME={codename}\n"
        f"RASPICONFIG={raspiconfig}\n"
    )


@pytest.mark.parametrize(
    ("distro", "codename"),
    [
        ("debian", "bookworm"),
        ("debian", "trixie"),
        ("ubuntu", "noble"),
        ("ubuntu", "resolute"),
    ],
)
def test_every_supported_release_parses(distro, codename):
    platform = parse_detect_output(_raw(distro, codename, "no"))
    assert platform.distro == distro
    assert platform.codename == codename
    assert platform.label == SUPPORTED_RELEASES[(distro, codename)]
    assert platform.has_raspi_config is False


def test_raspberry_pi_os_reports_id_debian_but_is_distinguished_by_raspi_config():
    """Raspberry Pi OS (bookworm/trixie) reports ID=debian, identical to
    plain Debian, since bookworm — has_raspi_config is what actually
    tells them apart (see the module docstring), not ID/codename."""
    rpi = parse_detect_output(_raw("debian", "trixie", "yes"))
    plain_debian = parse_detect_output(_raw("debian", "trixie", "no"))
    assert rpi.distro == plain_debian.distro == "debian"
    assert rpi.codename == plain_debian.codename == "trixie"
    assert rpi.has_raspi_config is True
    assert plain_debian.has_raspi_config is False
    assert rpi.default_service_user == "pi"
    assert plain_debian.default_service_user == "debian"


def test_default_service_user_matches_each_ecosystems_own_convention():
    assert parse_detect_output(_raw("ubuntu", "noble", "no")).default_service_user == "ubuntu"
    assert parse_detect_output(_raw("debian", "bookworm", "no")).default_service_user == "debian"
    assert parse_detect_output(_raw("debian", "trixie", "yes")).default_service_user == "pi"


def test_unsupported_release_is_rejected():
    with pytest.raises(UnsupportedPlatformError):
        parse_detect_output(_raw("ubuntu", "jammy", "no"))  # 22.04 - not in the two newest


def test_unsupported_distro_is_rejected():
    with pytest.raises(UnsupportedPlatformError):
        parse_detect_output(_raw("fedora", "40", "no"))


def test_no_marker_at_all_is_rejected_not_silently_defaulted():
    """A dropped connection, or a shell so minimal the probe itself never
    ran - must surface as an error, never as some default platform."""
    with pytest.raises(UnsupportedPlatformError):
        parse_detect_output("")


def test_build_detect_command_is_read_only_shell_only():
    command = build_detect_command()
    assert "rm " not in command
    assert "sudo" not in command
    assert "raspi-config" in command
    assert "/etc/os-release" in command
