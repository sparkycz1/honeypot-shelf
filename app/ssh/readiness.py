"""Post-onboarding readiness check — did the app's own setup requirements
(`ncurses-term`, and this account's scoped sudo for apt/shutdown/
dmidecode/systemctl/raspi-config/flatpak+snap — see
`app.ssh.onboarding.build_onboarding_command`) actually take, or did
installing/granting one of them fail or get skipped
(no network at onboarding time, a hand-onboarded honeypot that predates one
of these requirements, ...)? Read-only: every check here is a plain
`dpkg -s`/`sudo -n ... --version`-style probe — nothing is installed or
changed by running this.

**A honeypot whose configured account already *is* root never needs any of
the sudo grants at all** — root doesn't need to `sudo` itself, and on many
hardened images root has no usable password for `sudo` to authenticate
with in the first place (a locked/no-password root account, common when
only key-based root login is allowed), so `sudo -n` would fail there even
though the real command it's gating (`apt-get`, `shutdown`, `dmidecode` —
see `app.ssh.updates`/`app.ssh.power`/`app.ssh.facts`) would work fine run
directly. Every sudo-gated probe here is therefore skipped (reported
`ok`) once `id -u` is 0, mirroring the same root-runs-it-directly
fallback those other modules' *real* commands use.
"""

from __future__ import annotations

import re
from typing import TypedDict

from app.db.models.honeypot import Honeypot
from app.ssh.client import open_connection

_SECTION_MARKERS = (
    "NCURSES_TERM",
    "APT_SUDO",
    "SHUTDOWN_SUDO",
    "DMIDECODE_SUDO",
    "SYSTEMCTL_SUDO",
    "RASPI_CONFIG_PRESENT",
    "RASPI_CONFIG_SUDO",
    "FLATPAK_SNAP_PRESENT",
    "FLATPAK_SNAP_SUDO",
)

READINESS_COMMAND = (
    'is_root=0; [ "$(id -u)" = "0" ] && is_root=1; '
    "echo ===NCURSES_TERM===; "
    "dpkg -s ncurses-term >/dev/null 2>&1 && echo ok || echo missing; "
    "echo ===APT_SUDO===; "
    '[ "$is_root" = 1 ] && echo ok || '
    "(sudo -n apt-get --version >/dev/null 2>&1 && echo ok || echo missing); "
    "echo ===SHUTDOWN_SUDO===; "
    '[ "$is_root" = 1 ] && echo ok || '
    "(sudo -n shutdown --help >/dev/null 2>&1 && echo ok || echo missing); "
    "echo ===DMIDECODE_SUDO===; "
    '[ "$is_root" = 1 ] && echo ok || '
    "(sudo -n dmidecode -t 17 >/dev/null 2>&1 && echo ok || echo missing); "
    "echo ===SYSTEMCTL_SUDO===; "
    '[ "$is_root" = 1 ] && echo ok || '
    "(sudo -n systemctl --version >/dev/null 2>&1 && echo ok || echo missing); "
    # Checked separately from the sudo grant below (same pattern as
    # FLATPAK_SNAP_PRESENT/_SUDO) — raspi-config genuinely doesn't exist
    # on Debian/Ubuntu (see app.ssh.platform_detect's module docstring),
    # so "missing sudo for it" would be a nonsensical, unfixable finding
    # on those; this is what lets `missing_requirements` skip it there
    # instead of reporting a permanent, unactionable item.
    "echo ===RASPI_CONFIG_PRESENT===; "
    "command -v raspi-config >/dev/null 2>&1 && echo yes || echo no; "
    "echo ===RASPI_CONFIG_SUDO===; "
    '[ "$is_root" = 1 ] && echo ok || '
    "(sudo -n raspi-config --version >/dev/null 2>&1 && echo ok || echo missing); "
    "echo ===FLATPAK_SNAP_PRESENT===; "
    "(command -v flatpak >/dev/null 2>&1 || command -v snap >/dev/null 2>&1) "
    "&& echo yes || echo no; "
    "echo ===FLATPAK_SNAP_SUDO===; "
    "ok=1; "
    'if [ "$is_root" != 1 ]; then '
    "if command -v flatpak >/dev/null 2>&1; then "
    "sudo -n flatpak --version >/dev/null 2>&1 || ok=0; fi; "
    "if command -v snap >/dev/null 2>&1; then "
    "sudo -n snap version >/dev/null 2>&1 || ok=0; fi; "
    "fi; "
    '[ "$ok" = 1 ] && echo ok || echo missing'
)


class ReadinessResult(TypedDict):
    ncurses_term_installed: bool
    apt_sudo_ok: bool
    shutdown_sudo_ok: bool
    dmidecode_sudo_ok: bool
    systemctl_sudo_ok: bool
    raspi_config_present: bool
    raspi_config_sudo_ok: bool
    flatpak_or_snap_present: bool
    flatpak_snap_sudo_ok: bool


def _split_sections(raw: str) -> dict[str, str]:
    pattern = "|".join(f"==={name}===" for name in _SECTION_MARKERS)
    parts = re.split(f"(?:{pattern})", raw)
    body = parts[1:]
    return dict(zip(_SECTION_MARKERS, (chunk.strip() for chunk in body), strict=False))


def parse_readiness_output(raw: str) -> ReadinessResult:
    """Parse `READINESS_COMMAND`'s output. Pure function, no I/O. A section
    that's missing or unrecognized reads as "not ok" — a dropped connection
    partway through should look like problems remain, never like
    everything's fine."""
    sections = _split_sections(raw)
    return ReadinessResult(
        ncurses_term_installed=sections.get("NCURSES_TERM") == "ok",
        apt_sudo_ok=sections.get("APT_SUDO") == "ok",
        shutdown_sudo_ok=sections.get("SHUTDOWN_SUDO") == "ok",
        dmidecode_sudo_ok=sections.get("DMIDECODE_SUDO") == "ok",
        systemctl_sudo_ok=sections.get("SYSTEMCTL_SUDO") == "ok",
        raspi_config_present=sections.get("RASPI_CONFIG_PRESENT") == "yes",
        raspi_config_sudo_ok=sections.get("RASPI_CONFIG_SUDO") == "ok",
        flatpak_or_snap_present=sections.get("FLATPAK_SNAP_PRESENT") == "yes",
        flatpak_snap_sudo_ok=sections.get("FLATPAK_SNAP_SUDO") == "ok",
    )


# (result key, human-readable description) — checked in this order so the
# banner's list reads roughly most-to-least impactful. raspi_config_sudo_ok
# is deliberately *not* here — see `missing_requirements` below for why it
# needs its own `raspi_config_present`-gated handling, the same pattern
# flatpak_snap_sudo_ok already gets.
_REQUIREMENT_LABELS: tuple[tuple[str, str], ...] = (
    ("apt_sudo_ok", "passwordless sudo for apt-get (needed for checking/running updates)"),
    ("shutdown_sudo_ok", "passwordless sudo for shutdown (needed for reboot/power actions)"),
    ("dmidecode_sudo_ok", "passwordless sudo for dmidecode (needed for the RAM speed fact)"),
    (
        "systemctl_sudo_ok",
        "passwordless sudo for systemctl (needed for the Honeypot Config tab's module editor)",
    ),
    ("ncurses_term_installed", "ncurses-term (needed for full-color terminal output)"),
)

# The one requirement above that's a package install rather than a sudo
# grant — and so the one a honeypot already connected as root can fix
# directly, no fresh credential needed, no sudoers file involved at all
# (see app.web.routes.honeypots.fix_readiness_directly_endpoint, the only
# caller). Every other requirement is a sudo grant that a root account
# never needs in the first place (see the module docstring), so
# `missing_requirements` never reports one for a root-connected honeypot —
# there is nothing else for that flow to fix.
DIRECT_FIX_COMMAND = (
    "apt-get update -q >/dev/null 2>&1; apt-get install -y ncurses-term >/dev/null 2>&1"
)


def missing_requirements(result: ReadinessResult) -> list[str]:
    """Human-readable descriptions of whatever `result` says isn't set up
    — empty means everything checked is in place. `flatpak_snap_sudo_ok`
    is only reported when flatpak or snap is actually present (no point
    telling an operator to fix sudo for a package manager the honeypot
    doesn't even have) — `raspi_config_sudo_ok` gets the identical
    treatment against `raspi_config_present`: raspi-config genuinely
    doesn't exist on Debian/Ubuntu, so "missing sudo for it" there would
    be a permanent, unfixable finding, not an actionable one."""
    missing = [label for key, label in _REQUIREMENT_LABELS if not result[key]]  # type: ignore[literal-required]
    if result["raspi_config_present"] and not result["raspi_config_sudo_ok"]:
        missing.append(
            "passwordless sudo for raspi-config (needed for the Honeypot Config tab's "
            "read-only-root toggle)"
        )
    if result["flatpak_or_snap_present"] and not result["flatpak_snap_sudo_ok"]:
        missing.append("passwordless sudo for flatpak/snap (needed for those updates)")
    return missing


async def check_honeypot_readiness(
    honeypot: Honeypot, secret: str | None, timeout_seconds: int
) -> ReadinessResult:
    """Connect to a honeypot and run every readiness probe. Requires a
    pinned host key."""
    async with await open_connection(honeypot, secret, timeout_seconds) as conn:
        result = await conn.run(READINESS_COMMAND, check=False, timeout=timeout_seconds)
    stdout = result.stdout or ""
    raw = stdout if isinstance(stdout, str) else stdout.decode()
    return parse_readiness_output(raw)
