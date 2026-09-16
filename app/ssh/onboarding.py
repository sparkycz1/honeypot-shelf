"""Builds the shell script that prepares a fresh, not-yet-managed
Debian-family honeypot (Raspberry Pi OS, Debian, or Ubuntu — see
`app.ssh.platform_detect` for the six releases Initialize itself detects
and targets; this script doesn't need to tell them apart at all, see
below) for Honeypot Shelf, run directly over SSH (see
`app.tasks.jobs._run_honeypot_onboarding`, the only caller):

1. Create a dedicated `honeypotshelf` user (idempotent — `id -u` first).
2. Install this app's own SSH public key into that user's
   `authorized_keys` (idempotent — `grep -qxF` first, same convention as
   `app.tasks.jobs._push_pending_ssh_key`).
3. Grant it passwordless sudo, scoped to exactly what Honeypot Shelf needs
   (`apt-get`, `shutdown`, `dmidecode`, `systemctl`, `raspi-config` — the
   read-only-root toggle, granted unconditionally even though it only
   ever resolves to anything on a device that actually has raspi-config
   (Raspberry Pi OS) — a sudoers rule for a command that doesn't exist
   simply never matches, so this is harmless dead weight on Debian/Ubuntu,
   not a bug — and `bash /tmp/.honeypotshelf-*` — running this app's own
   generated scripts, e.g. the Honeypot Config tab's module editor
   restarting `opencanary` and toggling `smbd`/`nmbd` — and `flatpak`/
   `snap` if either is present) — see `build_sudoers_grant_command`'s own
   docstring for the full reasoning.
4. Best-effort install `ncurses-term`, so the web Terminal tab gets colors
   and box-drawing without a separate manual step. Its failure (no
   network, offline apt cache) must never fail onboarding itself — only
   steps 1-3 are load-bearing.

Deliberately **not** an actual `ansible-playbook` invocation: that would
need Ansible (and its own dependency tree) added to the worker image just
for this, for no behavioral difference over running the same handful of
idempotent shell commands through the SSH connection this app already has
everywhere else. (The team's own separate Ansible-based imaging/install
runbook, run once when a Pi is first provisioned, is complementary to
this, not replaced by it.)

Requires connecting as root (or an account that already behaves like
root) — that one-time credential is the whole point of onboarding a
honeypot that has nothing configured for Honeypot Shelf yet, so there is
deliberately no `sudo` escalation anywhere in this script to fall back on
if the connecting account isn't already root.
"""

from __future__ import annotations

import shlex

# The account Honeypot Shelf connects as afterwards.
ONBOARD_USERNAME = "honeypotshelf"

# Printed as the script's last line on success, so a caller can tell "ran
# to completion" apart from "produced some output but got cut off partway"
# without relying on exit status alone.
ONBOARD_SUCCESS_MARKER = "HONEYPOTSHELF_ONBOARD_OK"


def build_sudoers_grant_command(username: str) -> str:
    """The passwordless sudo grant `app.ssh.readiness` checks for
    (`apt-get`/`shutdown`/`dmidecode`/`systemctl`, plus `flatpak`/`snap` if
    either is present) — exactly what an operator would otherwise type by
    hand from the readiness banner's own hint — plus two more commands the
    readiness check doesn't probe directly but real features still need:
    `raspi-config` (the Honeypot Config tab's read-only-root toggle,
    `app.ssh.readonly.build_toggle_command`) and running this app's own
    generated scripts under `/tmp/.honeypotshelf-*` via `bash` (the OpenCanary
    module editor's "Apply" — `app.ssh.opencanary_config.
    build_write_command` writes `/tmp/.honeypotshelf-opencanary-apply.sh`,
    restarting `opencanary` and toggling `smbd`/`nmbd` to match, and
    `app.ssh.initialize` writes `/tmp/.honeypotshelf-initialize.sh` the same
    way, all in one script for exactly the same one-round-trip reasoning
    `app.ssh.updates.build_update_command` documents). Confirmed live that
    omitting either of these breaks that feature outright (`sudo: a
    password is required`, silently swallowed by the caller's own
    `2>/dev/null` fallback into a useless "exited 1: (no output)" — see
    `app.tasks.jobs._write_honeypot_opencanary_config`) — this grant
    exists specifically so neither ever needs a human sudo password typed
    in over the terminal tab instead.

    The `bash` grant is restricted to the `/tmp/.honeypotshelf-*` prefix (a
    sudoers command-argument glob, matched literally, not a shell glob)
    every script this app writes there uses — not a blanket "run any
    command as root" grant, even though in practice an account already
    this trusted (it holds the very credential Honeypot Shelf itself uses to
    manage this honeypot) getting broader access wouldn't meaningfully
    change what it could already do to the honeypot through the features
    above alone.

    Idempotent (each `cat >` overwrites its own file, never appending/
    duplicating) and self-validating (`visudo -cf` after every write — a
    syntax error here would otherwise silently break sudo for the whole
    system on next use, not just for this grant).

    Shared by `build_onboarding_command` (the dedicated `honeypotshelf` user,
    granted once during onboarding) and `app.ssh.initialize.
    build_initialize_command` (whichever account Initialize connects as,
    granted during initial provisioning — see that module for why this
    exists there too: without it, every freshly Initialized device used to
    show up in Honeypot Shelf already missing every one of these, exactly the
    gap `app.ssh.readiness`'s banner exists to catch).
    """
    user = shlex.quote(username)
    return (
        f"cat > /etc/sudoers.d/{user} <<'HONEYPOTSHELF_SUDOERS_APT'\n"
        f"{username} ALL=(root) NOPASSWD: /usr/bin/apt-get, /usr/sbin/shutdown, "
        "/usr/sbin/dmidecode, /usr/bin/systemctl, /usr/bin/raspi-config, "
        "/usr/bin/bash /tmp/.honeypotshelf-*\n"
        "HONEYPOTSHELF_SUDOERS_APT\n"
        f"chmod 440 /etc/sudoers.d/{user}; "
        f"visudo -cf /etc/sudoers.d/{user}; "
        "if command -v flatpak >/dev/null 2>&1 || command -v snap >/dev/null 2>&1; then "
        f"cat > /etc/sudoers.d/{user}-flatpak-snap <<'HONEYPOTSHELF_SUDOERS_FS'\n"
        f"{username} ALL=(root) NOPASSWD: /usr/bin/flatpak, /usr/bin/snap\n"
        "HONEYPOTSHELF_SUDOERS_FS\n"
        f"chmod 440 /etc/sudoers.d/{user}-flatpak-snap; "
        f"visudo -cf /etc/sudoers.d/{user}-flatpak-snap; "
        "fi"
    )


def build_onboarding_command(public_key: str) -> str:
    """Returns one `set -e` shell script — a single exec, not several round
    trips, same reasoning `app.ssh.updates.build_update_command` documents
    for bundling apt/flatpak/snap into one script. Safe to re-run (e.g.
    after a partial failure on an earlier attempt) without duplicating the
    `authorized_keys` line or fighting its own sudoers files.
    """
    quoted_key = shlex.quote(public_key.strip())
    user = ONBOARD_USERNAME
    return (
        "set -e; "
        f"id -u {user} >/dev/null 2>&1 || useradd -m -s /bin/bash {user}; "
        f'home="$(getent passwd {user} | cut -d: -f6)"; '
        f'install -d -m 700 -o {user} -g {user} "$home/.ssh"; '
        f'touch "$home/.ssh/authorized_keys"; '
        f'grep -qxF {quoted_key} "$home/.ssh/authorized_keys" 2>/dev/null || '
        f'echo {quoted_key} >> "$home/.ssh/authorized_keys"; '
        f'chmod 600 "$home/.ssh/authorized_keys"; '
        f'chown {user}:{user} "$home/.ssh/authorized_keys"; '
        f"{build_sudoers_grant_command(user)}; "
        "(apt-get update -q >/dev/null 2>&1 && "
        "apt-get install -y ncurses-term >/dev/null 2>&1) || true; "
        f"echo {ONBOARD_SUCCESS_MARKER}"
    )
