"""Giving a honeypot a different MAC address — so that, on the network it
sits in, it looks like a printer, a camera or a switch from a particular
manufacturer rather than a Raspberry Pi.

**How**: one small systemd unit, `honeypotshelf-mac.service`, that runs
`ip link set dev <interface> address <mac>` once per boot, ordered before
`network-pre.target` — i.e. before NetworkManager, systemd-networkd,
ifupdown or dhcpcd touch the interface at all. All of them keep whatever
address the interface already has when they bring it up, so this works
the same on every release Initialize supports without knowing which of
them a given image uses. (A `.link` file would be the other obvious way,
but only the first matching `.link` file applies to an interface, so one
of our own would silently replace the distribution's naming policy.)

**When**: at the next boot, never live. Changing the address under a
running connection would cut this app's own SSH session, and the DHCP
server will usually hand a different address to a MAC it has not seen —
so the change is written now and takes effect with a reboot the operator
asks for, at a time they choose.

**Which interface**: the one the default route goes through when the
address is set — the interface the honeypot is seen on. Its name is
written into the unit.

**Undoing it**: removing the unit. The hardware address is never
overwritten anywhere, so the next boot simply comes up with it again.

A read-only root filesystem (`app.ssh.readonly`) would throw the unit
away at the next boot — exactly when it is meant to act — so setting or
clearing an address is refused while the overlay is active.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from app.db.models.honeypot import Honeypot
from app.ssh.exec import run_command

UNIT_NAME = "honeypotshelf-mac.service"
UNIT_PATH = f"/etc/systemd/system/{UNIT_NAME}"

_COMMAND_TIMEOUT_SECONDS = 30
# Exit statuses the scripts below use for a refusal with a known reason.
_NO_INTERFACE = 3
_READONLY_ROOT = 4

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_HEX_ONLY_RE = re.compile(r"^[0-9a-f]{12}$")

# The interface the default route uses (IPv4 first, then IPv6).
_DEFAULT_INTERFACE = (
    "$( { ip -o -4 route show default; ip -o -6 route show default; } 2>/dev/null "
    "| awk '{for (i = 1; i < NF; i++) if ($i == \"dev\") {print $(i + 1); exit}}')"
)


class MacAddressError(Exception):
    """Setting, clearing or reading the address did not work — the message
    is meant for the person who asked."""


class InvalidMacAddressError(ValueError):
    """Not something that can be an interface's own address."""


def normalize_mac(value: str) -> str:
    """`AA-BB-CC-DD-EE-FF`, `aabb.ccdd.eeff`, `aabbccddeeff` → the one form
    used everywhere here: lower case, colon separated. Raises
    `InvalidMacAddressError` for anything that is not six bytes, for the
    all-zero address, and for a multicast one (lowest bit of the first
    byte set — an interface cannot have it, and the kernel refuses it)."""
    compact = re.sub(r"[\s:.\-]", "", value.strip().lower())
    if not _HEX_ONLY_RE.match(compact):
        raise InvalidMacAddressError("A MAC address is six bytes, e.g. 00:1b:63:84:45:e6.")
    if compact == "0" * 12:
        raise InvalidMacAddressError("The all-zero MAC address cannot be used.")
    if int(compact[:2], 16) & 1:
        raise InvalidMacAddressError(
            "This is a multicast address (the first byte is odd); an interface cannot have it."
        )
    return ":".join(compact[i : i + 2] for i in range(0, 12, 2))


@dataclass(frozen=True)
class MacStatus:
    interface: str | None
    # What the interface has right now.
    current: str | None
    # What the unit will set at the next boot; None when there is no unit.
    configured: str | None
    readonly_root: bool

    @property
    def pending(self) -> bool:
        """Configured, but the interface still has another address — the
        reboot that applies it has not happened yet."""
        return self.configured is not None and self.configured != self.current


def build_status_command() -> str:
    """Read-only, needs no root: the default-route interface, its current
    address, the address our unit sets (if the unit exists), and whether
    root is an overlay."""
    return (
        f"iface={_DEFAULT_INTERFACE}; "
        'echo "IFACE=$iface"; '
        'echo "CURRENT=$(cat "/sys/class/net/$iface/address" 2>/dev/null)"; '
        f'echo "CONFIGURED=$(sed -n \'s/^# honeypotshelf-mac: //p\' {UNIT_PATH} 2>/dev/null)"; '
        'echo "ROOTFS=$(findmnt -n -o FSTYPE / 2>/dev/null)"'
    )


def parse_status(raw: str) -> MacStatus:
    values: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()

    def _mac(key: str) -> str | None:
        candidate = values.get(key, "").lower()
        return candidate if _MAC_RE.match(candidate) else None

    return MacStatus(
        interface=values.get("IFACE") or None,
        current=_mac("CURRENT"),
        configured=_mac("CONFIGURED"),
        readonly_root=values.get("ROOTFS") == "overlay",
    )


def unit_install_lines(mac: str) -> list[str]:
    """Shell lines, to be run as root, that write and enable the unit for
    the default-route interface. `mac` must already be normalized — it is
    the only caller-supplied value in the script. Shared by the Config
    tab (`build_set_command`) and Initialize
    (`app.ssh.initialize.build_initialize_command`)."""
    if not _MAC_RE.match(mac):
        raise InvalidMacAddressError("Not a normalized MAC address.")
    return [
        f"mac_iface={_DEFAULT_INTERFACE}",
        f'[ -n "$mac_iface" ] || {{ echo "No interface with a default route found."; '
        f"exit {_NO_INTERFACE}; }}",
        'mac_ip="$(command -v ip)"',
        f"cat > {UNIT_PATH} <<HONEYPOTSHELF_MAC_UNIT",
        "# Managed by Honeypot Shelf. Remove this unit to return to the hardware address.",
        f"# honeypotshelf-mac: {mac}",
        "[Unit]",
        "Description=Honeypot Shelf: MAC address of $mac_iface",
        "DefaultDependencies=no",
        "Wants=network-pre.target",
        "Before=network-pre.target",
        "",
        "[Service]",
        "Type=oneshot",
        "RemainAfterExit=yes",
        "TimeoutStartSec=30",
        # The interface may not exist yet this early in boot — wait for it
        # briefly rather than binding to its device unit, which would hold
        # the whole network back if the name ever changed. `\\$\\$`: a
        # literal `$$` in the unit file, which is how systemd spells a `$`
        # it must not expand itself.
        "ExecStart=/bin/sh -c 'n=0; while [ ! -e /sys/class/net/$mac_iface ] && "
        '[ \\$\\$n -lt 20 ]; do sleep 0.5; n=\\$\\$((n + 1)); done; '
        f"exec $mac_ip link set dev $mac_iface address {mac}'",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "HONEYPOTSHELF_MAC_UNIT",
        "systemctl daemon-reload",
        f"systemctl enable {UNIT_NAME}",
        'echo "IFACE=$mac_iface"',
    ]


_REFUSE_ON_READONLY_ROOT = (
    f'[ "$(findmnt -n -o FSTYPE / 2>/dev/null)" != overlay ] || exit {_READONLY_ROOT}'
)


def _as_root(script_lines: list[str]) -> str:
    """Same temp-file-then-`sudo` shape as
    `app.ssh.opencanary_config.build_write_command`: written to /tmp as
    the login user, run once under `sudo -n`, or directly when the
    connection is already root."""
    script_path = "/tmp/.honeypotshelf-mac.sh"  # noqa: S108 - written then removed below
    marker = "HONEYPOTSHELF_MAC_SCRIPT"
    body = "\n".join(["set -e", *script_lines]) + "\n"
    quoted = shlex.quote(script_path)
    return (
        f"cat > {quoted} <<'{marker}'\n{body}{marker}\n"
        f"if [ \"$(id -u)\" = 0 ]; then bash {quoted}; else sudo -n bash {quoted}; fi; "
        f"status=$?; rm -f {quoted}; exit $status"
    )


def build_set_command(mac: str) -> str:
    return _as_root([_REFUSE_ON_READONLY_ROOT, *unit_install_lines(mac)])


def build_reset_command() -> str:
    return _as_root(
        [
            _REFUSE_ON_READONLY_ROOT,
            f"systemctl disable {UNIT_NAME} 2>/dev/null || true",
            f"rm -f {UNIT_PATH}",
            "systemctl daemon-reload",
        ]
    )


def _explain(exit_status: int, output: str) -> str:
    if exit_status == _READONLY_ROOT:
        return (
            "The root filesystem is read-only, so the change would be gone at the next "
            "boot. Turn read-only root off, reboot, then set the MAC address."
        )
    if exit_status == _NO_INTERFACE:
        return "The honeypot has no interface with a default route to change."
    detail = output.strip().splitlines()[-1] if output.strip() else f"exit status {exit_status}"
    return f"The honeypot refused the change: {detail}"


async def read_mac_status(
    honeypot: Honeypot, secret: str | None, timeout_seconds: int
) -> MacStatus:
    result = await run_command(
        honeypot, secret, build_status_command(), timeout_seconds, _COMMAND_TIMEOUT_SECONDS
    )
    return parse_status(result.output)


async def set_mac_address(
    honeypot: Honeypot, secret: str | None, mac: str, timeout_seconds: int
) -> str | None:
    """Write the unit. Returns the interface it was written for."""
    result = await run_command(
        honeypot, secret, build_set_command(mac), timeout_seconds, _COMMAND_TIMEOUT_SECONDS
    )
    if result.exit_status != 0:
        raise MacAddressError(_explain(result.exit_status, result.output))
    return parse_status(result.output).interface


async def reset_mac_address(honeypot: Honeypot, secret: str | None, timeout_seconds: int) -> None:
    result = await run_command(
        honeypot, secret, build_reset_command(), timeout_seconds, _COMMAND_TIMEOUT_SECONDS
    )
    if result.exit_status != 0:
        raise MacAddressError(_explain(result.exit_status, result.output))
