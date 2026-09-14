"""Toggling a honeypot's root filesystem between read-only (overlay) and
writable — the Honeypot Config tab's one action.

**Why**: an SD card wears out from repeated writes; a honeypot that's
finished being provisioned has no real need to write to its own root
filesystem at all day to day (OpenCanary's own log goes to a tmpfs
ramdisk instead — see `app.ssh.initialize`'s `/mnt/tmpfs` setup, and the
Logs tab's "Honeypot logs" shortcut). Read-only root protects the card
from that wear and (as a side effect) makes an unclean power loss far
less likely to corrupt the filesystem — the two reasons this matters for
a device that's typically left running unattended for a long time.

**How**: Raspberry Pi OS's own built-in overlay filesystem support
(`raspi-config nonint do_overlayfs 0|1`) rather than hand-rolled `/etc/
fstab` editing — it's the officially supported, tested-by-the-vendor
mechanism for exactly this, and is trivially reversible (the same command,
the other way) where a mistake in a hand-written fstab entry can leave a
device unable to boot at all. **Takes effect on next reboot**, not
immediately — enabling/disabling only ever changes what root looks like
after the device restarts; the current boot keeps whatever it already
booted with. (Read the vendor's own `enable_overlayfs` shell function —
`sed -n '/^enable_overlayfs/,/^}/p' /usr/bin/raspi-config` on a real
device — before assuming anything else about the mechanism; it's not
obvious from the command name alone.)

**Compatible with everything Initialize's own log setup writes to
`/var/log` while enabled — verified against the vendor's actual
mechanism, not assumed.** `do_overlayfs` doesn't mount root plain
read-only; it installs the `overlayroot` package and adds
`overlayroot=tmpfs` to the kernel command line, which layers a **tmpfs**
(RAM) write layer on top of the real, read-only root at boot. Every write
anywhere under `/` — `/var/log/kern.log` and `/var/log/samba-audit.log`
(`app.ssh.initialize`'s portscan/smb module prep), journald's own
persistent `/var/log/journal` if present, this app's own SSH-pushed
files, anything — still succeeds exactly as before, into RAM; it's only
*discarded on the next reboot* rather than persisted to the SD card. That
discard-on-reboot is the entire point (protect the card from wear), and
it's fine for all of the above: OpenCanary's own alert history already
lives in Honeypot Shelf's own DB (pushed or SSH-polled, see
`app.services.honeypot_events`), never depends on anything under
`/var/log` surviving a reboot; `/mnt/tmpfs` (also `app.ssh.initialize`)
stays worth having independently of this toggle, for a honeypot that
never enables it at all, to spare the card from OpenCanary's own log
writes on every boot.

**Must be disabled before running system updates** (the Updates tab) —
`apt` can't write to a read-only root. The Config tab always shows
whichever of "enable"/"disable" makes sense for the currently *booted*
state (not the pending-until-reboot one), so it stays a one-click action
either direction.
"""

from __future__ import annotations

from typing import Literal

import asyncssh

from app.db.models.honeypot import Honeypot
from app.ssh.client import open_connection

_STATUS_TIMEOUT_SECONDS = 15
_TOGGLE_TIMEOUT_SECONDS = 30

ReadonlyState = Literal["enabled", "disabled"]


class ReadonlyToggleError(Exception):
    """`raspi-config nonint do_overlayfs` exited non-zero — e.g. it isn't
    installed (not Raspberry Pi OS) or the account has no usable sudo."""


def build_status_command() -> str:
    """`overlay` as the root filesystem's type is Raspberry Pi OS's own
    overlayfs in effect — i.e. currently booted read-only. Anything else
    (`ext4`, the common case) means a normal writable root, whether or not
    overlay has been toggled on for the *next* boot."""
    return "findmnt -n -o FSTYPE /"


def parse_status(raw: str) -> ReadonlyState:
    return "enabled" if raw.strip() == "overlay" else "disabled"


def build_toggle_command(*, enable: bool) -> str:
    """Same root-fallback shape `app.ssh.power`/`app.ssh.updates` use:
    `sudo -n` first, falling back to running it directly for an
    already-root connection."""
    flag = "0" if enable else "1"
    command = f"raspi-config nonint do_overlayfs {flag}"
    return f"(sudo -n {command} 2>/dev/null || {command})"


async def check_readonly_status(
    honeypot: Honeypot, secret: str | None, timeout_seconds: int = _STATUS_TIMEOUT_SECONDS
) -> ReadonlyState:
    async with await open_connection(honeypot, secret, timeout_seconds) as conn:
        result = await conn.run(
            build_status_command(), check=False, timeout=timeout_seconds, stderr=asyncssh.STDOUT
        )
    stdout = result.stdout or ""
    return parse_status(stdout if isinstance(stdout, str) else stdout.decode())


async def set_readonly(
    honeypot: Honeypot,
    secret: str | None,
    *,
    enable: bool,
    timeout_seconds: int = _TOGGLE_TIMEOUT_SECONDS,
) -> None:
    async with await open_connection(honeypot, secret, timeout_seconds) as conn:
        result = await conn.run(
            build_toggle_command(enable=enable),
            check=False,
            timeout=timeout_seconds,
            stderr=asyncssh.STDOUT,
        )
    if result.exit_status != 0:
        stdout = result.stdout or ""
        text = stdout if isinstance(stdout, str) else stdout.decode()
        raise ReadonlyToggleError(
            f"raspi-config exited {result.exit_status}: {text.strip() or '(no output)'}"
        )
