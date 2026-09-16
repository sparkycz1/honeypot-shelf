"""Detects which of the OS/version combinations Initialize actually
supports a not-yet-provisioned device is running, before building or
running any provisioning script against it — see `app.ssh.initialize`'s
module docstring for how the result feeds into `build_initialize_command`.

**Distro + version** comes straight from `/etc/os-release`'s `ID`/
`VERSION_CODENAME` — reliable and universal across Debian, Ubuntu, and
Raspberry Pi OS alike. **Whether the device supports the read-only-root
toggle** (`app.ssh.readonly`) is a separate, independently-detected
signal (`command -v raspi-config`), deliberately *not* inferred from
`ID`/codename: Raspberry Pi OS has reported `ID=debian` — identical to
plain Debian — ever since bookworm (12); the two were only
distinguishable via `ID=raspbian` on the older bullseye and earlier. A
plain Debian box and a Raspberry Pi both running bookworm/trixie are
otherwise provisioned identically (same package names, same apt
mechanism) — the *only* behavioral fork this app makes between them is
whether `raspi-config` exists to toggle overlayfs at all, so that's
exactly the one thing actually probed for it, rather than trying (and
inevitably failing) to reconstruct "is this really a Raspberry Pi" from
distro labeling that no longer carries that information.
"""

from __future__ import annotations

from dataclasses import dataclass

_DETECT_MARKER = "===HONEYPOTSHELF_PLATFORM==="

# (ID, VERSION_CODENAME) -> human-readable label, for every combination
# Initialize actually supports — the two newest stable/LTS releases of
# each of the three OSes this app is built and tested against. `ID=debian`
# covers Raspberry Pi OS too (see the module docstring) - there is no
# separate "raspberry_pi_os" entry here; `DetectedPlatform.has_raspi_config`
# is what actually distinguishes it, not this table.
SUPPORTED_RELEASES: dict[tuple[str, str], str] = {
    ("debian", "bookworm"): "Debian 12 (bookworm)",
    ("debian", "trixie"): "Debian 13 (trixie)",
    ("ubuntu", "noble"): "Ubuntu 24.04 LTS (Noble Numbat)",
    ("ubuntu", "resolute"): "Ubuntu 26.04 LTS (Resolute Raccoon)",
}


class UnsupportedPlatformError(Exception):
    """The connected device isn't running one of `SUPPORTED_RELEASES` — or
    the probe itself failed to produce parseable output at all (a shell
    with no `/etc/os-release`, an unexpected connection drop, ...)."""


@dataclass(frozen=True)
class DetectedPlatform:
    distro: str  # os-release ID - "debian" or "ubuntu" (see SUPPORTED_RELEASES)
    codename: str  # os-release VERSION_CODENAME - e.g. "bookworm", "noble"
    label: str  # human-readable, e.g. "Debian 13 (trixie)"
    has_raspi_config: bool  # drives the read-only-root toggle - see module docstring

    # No `default_service_user` here any more — a previous version guessed
    # a fallback account name per ecosystem ("pi" for Raspberry Pi OS,
    # "debian"/"ubuntu" for the other two, matching each vendor's own
    # cloud-image convention). Confirmed live that this was wrong: a
    # plain, hand-installed Debian 13 VM (no cloud-init, no "debian" user
    # at all) failed Initialize outright with "chown: invalid user:
    # 'debian:debian'". `app.ssh.initialize.service_user_for` now falls
    # back to `nobody` unconditionally instead - guaranteed to exist on
    # every Debian-family system, not a guess.


def build_detect_command() -> str:
    """A tiny, read-only, no-sudo-needed probe — safe to run before any
    trust decision about the device has been made. Sourcing `/etc/
    os-release` directly (rather than grep/cut) is simpler and every
    target here is guaranteed to have one (systemd's own baseline
    requirement, which all six supported releases satisfy)."""
    return (
        ". /etc/os-release 2>/dev/null; "
        f'echo "{_DETECT_MARKER}"; '
        'echo "ID=$ID"; '
        'echo "CODENAME=$VERSION_CODENAME"; '
        "command -v raspi-config >/dev/null 2>&1 && echo RASPICONFIG=yes || echo RASPICONFIG=no"
    )


def parse_detect_output(raw: str) -> DetectedPlatform:
    marker_index = raw.find(_DETECT_MARKER)
    if marker_index == -1:
        raise UnsupportedPlatformError(
            "Could not determine the device's OS - the detection probe produced no output."
        )
    fields: dict[str, str] = {}
    for line in raw[marker_index + len(_DETECT_MARKER) :].splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        fields[key.strip()] = value.strip().strip('"')

    distro = fields.get("ID", "")
    codename = fields.get("CODENAME", "")
    label = SUPPORTED_RELEASES.get((distro, codename))
    if label is None:
        supported = ", ".join(sorted(SUPPORTED_RELEASES.values()))
        raise UnsupportedPlatformError(
            f"Unsupported OS: {distro or 'unknown'} {codename or ''}".strip()
            + f". Supported: {supported}."
        )
    return DetectedPlatform(
        distro=distro,
        codename=codename,
        label=label,
        has_raspi_config=fields.get("RASPICONFIG") == "yes",
    )
