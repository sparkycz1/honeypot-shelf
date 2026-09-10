"""Builds the shell script that provisions a **brand new** Raspberry Pi OS
13 (Debian trixie) device into a working OpenCanary honeypot, run once over
SSH (see `app.web.routes.initialize_ws`, the only caller) — the
"Initialize" top-nav action (`app.web.routes.initialize`).

Adapted from the team's own Ansible playbook (packages, the venv +
OpenCanary/scapy/pcapy-ng install, the `opencanary.service` unit, locales,
timezone, the `vim`/`bash.bashrc` config, the base tool set) plus what the
playbook didn't cover that this app needed: setting the device's
hostname/`/etc/hosts` entry from the name given in the Initialize form,
installing + joining NetBird (repo + package + `netbird up`), generating
OpenCanary's own config (`opencanaryd --copyconfig`), and preparing the
two modules that need real host-OS setup beyond just flipping `enabled`
in that config — confirmed against OpenCanary's own wiki (only these two
need it; every other module is a self-contained listener):

- **portscan** — https://github.com/thinkst/opencanary/wiki/OpenCanary-Wiki#portscan-not-working-on-debian-12
  Debian 12+ dropped file-based kernel logging in favor of journald-only,
  and defaults to the nftables-backed `iptables` binary, neither of which
  the portscan module can read. Fixed by loading rsyslog's `imjournal`
  module (bridges journald back to a plain `/var/log/kern.log`) and
  switching the `iptables` alternative to `iptables-legacy`.
- **smb** — https://github.com/thinkst/opencanary/wiki/Opencanary-and-Samba
  Needs Samba itself configured with a `full_audit` VFS module that
  writes to syslog, which rsyslog then routes to a plain audit log file
  OpenCanary tails. Samba's own `smbd`/`nmbd` services are installed but
  left **disabled** — this is prep, not "go live"; nothing should be
  listening on the network until an operator deliberately enables both
  the systemd services and the `smb` module in the generated config.

Neither is force-enabled in the generated `opencanary.conf` — every
module still ships however `--copyconfig` defaults it (disabled), same as
every other module. The point of both is that flipping `"portscan.enabled"`/
`"smb.enabled"` to `true` afterward is *all* that's left to do — no
further host-side setup.

Deliberately **not** an actual `ansible-playbook` invocation, for the same
reason `app.ssh.onboarding` gives: one `set -e` shell script over the SSH
connection this app already has, no Ansible dependency added to the
worker image. Unlike onboarding (which only ever touches an
already-known, already-pinned `Honeypot` row), this targets a device that
isn't in HoneyHive's database at all yet — see
`app.web.routes.initialize` for how the connection itself is authenticated
and host-key-trusted for that case.

Also installed: `authorized_keys` (HoneyHive's own shared identity public
key, plus every current superadmin's personal key(s) from My account →
SSH public keys — see `app.web.routes.initialize_ws`'s caller) via
`app.ssh.authorized_keys.build_authorized_keys_append_command` — the same
idempotent, additive, home-dir-aware pattern `app.ssh.onboarding` and
`app.tasks.jobs.push_superadmin_ssh_keys` use, skipped entirely if the
caller passes none — and the exact scoped, passwordless sudo grant
(`app.ssh.onboarding.build_sudoers_grant_command`) `app.ssh.readiness`
checks for, so a freshly Initialized device never shows up in HoneyHive
already failing every one of those checks the way one used to before this
existed.

Second-to-last, sshd moves off the default port 22 to
`build_initialize_command`'s `new_ssh_port` argument (`NEW_SSH_PORT`,
22222, by default — an operator-editable field on the Initialize form,
see `app.web.routes.initialize`) via a drop-in under
`/etc/ssh/sshd_config.d/` — see `NEW_SSH_PORT`'s own comment for why this
step stays late, and why it can't lock an operator out. The device only
answers on the new port from then on; the operator must use it (not 22)
when adding the device as a `Honeypot` afterward.

The very last step reboots the device — a full clean boot rather than
trusting everything above is already in its final running state — and
`app.web.routes.initialize_ws` waits for it to come back up (polling the
new port, over the new port's own host-key fingerprint) before reporting
success, so "Initialize succeeded" actually means "the device rebooted
and came back," not just "the script ran to its last line."

Idempotent throughout (every step guards against "already done") — safe to
re-run Initialize against the same device after a partial failure. Each
step is preceded by an `echo` of `STEP_MARKER_PREFIX` + a human label —
`app.web.routes.initialize_ws` parses those lines out of the live output
stream to drive the "what's it doing right now" banner; everything else
on stdout/stderr is shown to the operator verbatim, live, as it's
produced.
"""

from __future__ import annotations

import shlex
from collections.abc import Sequence

from app.ssh.authorized_keys import build_authorized_keys_append_command
from app.ssh.logs import HONEYPOT_LOG_PATH
from app.ssh.onboarding import build_sudoers_grant_command

# Printed as the script's last line on success — same "did it actually run
# to completion" reasoning as app.ssh.onboarding.ONBOARD_SUCCESS_MARKER.
INITIALIZE_SUCCESS_MARKER = "HONEYHIVE_INITIALIZE_OK"

# A line `f"{STEP_MARKER_PREFIX}<label>"` on its own announces the start of
# one phase — parsed out of the live output stream, never shown as raw
# output itself. Distinctive enough that nothing legitimate a package
# manager/systemd/etc. prints could collide with it by accident.
STEP_MARKER_PREFIX = "##HH-STEP## "

# The default port sshd is moved to at the very end of a successful run —
# off the default 22, since that's the first thing an internet-wide
# scanner tries against a device that's about to spend its life
# pretending to be an unrelated set of fake services. Just the default:
# `build_initialize_command`'s `new_ssh_port` parameter (an editable field
# on the Initialize form, see `app.web.routes.initialize`) can override it
# per run. Applied last, after every other step has already succeeded,
# and gated on `sshd -t` passing first (see `build_initialize_command`) —
# a config an operator's own connection is still open on is never
# restarted into a state that could lock them out. The operator must use
# whichever port was actually used (not 22) when adding the device as a
# `Honeypot` afterward — `app.web.routes.initialize`'s docstring covers
# why that's a separate, manual step this function doesn't automate.
NEW_SSH_PORT = 22222

# apt's `full-upgrade` plus compiling pcapy-ng/scapy from source can
# genuinely take the better part of an hour on slower Pi models — this is
# the hard cap on one Initialize run's wall-clock duration in
# `app.web.routes.initialize_ws` (same reasoning/shape as
# `app.web.routes.terminal_ws.TERMINAL_SESSION_MAX_SECONDS`).
INITIALIZE_RUN_MAX_SECONDS = 60 * 60

# The post-reboot "did it actually come back" phase in
# `app.web.routes.initialize_ws`, run after the script above triggers the
# final reboot. `REBOOT_GRACE_SECONDS` is an unconditional wait before the
# first reconnect attempt — long enough that a real device has actually
# gone down by then, so an immediate successful probe can't be a stale
# leftover of the pre-reboot state; `REBOOT_POLL_INTERVAL_SECONDS` between
# each retry after that, for up to `REBOOT_WAIT_MAX_SECONDS` total —
# generous for a Raspberry Pi's real boot time (typically well under a
# minute) with real margin for a slower SD card or first-boot fsck.
REBOOT_GRACE_SECONDS = 15
REBOOT_POLL_INTERVAL_SECONDS = 5
REBOOT_WAIT_MAX_SECONDS = 240

# See app.ssh.readonly's module docstring for why this exists — a small
# ramdisk OpenCanary's log can still write to once root itself is
# read-only. Shared with app.ssh.logs.HONEYPOT_LOG_PATH (the actual log
# file lives at "<TMPFS_PATH>/opencanary.log").
TMPFS_PATH = "/mnt/tmpfs"
TMPFS_SIZE_MB = 512

# The account opencanaryd's systemd unit runs as (it drops to
# --uid=nobody --gid=nogroup itself once it has bound its listening
# ports — see the service unit below). Matches the source Ansible
# playbook's own hardcoded `User=pi`; used only when the operator
# connected as root, where there's no more specific account to prefer.
_DEFAULT_SERVICE_USER = "pi"

# python3-scapy is installed via apt (not pip) specifically so the venv
# can be built with --system-site-packages and see it — same reasoning
# the source playbook's `virtualenv_site_packages: yes` documents.
_APT_PACKAGES = [
    # --- OpenCanary's own runtime deps ---
    "python3-dev",
    "python3-pip",
    "python3-virtualenv",
    "python3-venv",
    "python3-scapy",
    "libssl-dev",
    "libpcap-dev",
    "samba",
    "rsyslog",
    "iptables",
    # --- General admin/runbook tool set (Debian >=12 package names) ---
    "tmux",
    "htop",
    "iftop",
    "atop",
    "rsync",
    "dstat",
    "mc",
    "telnet",
    "netcat-traditional",
    "tcpdump",
    "traceroute",
    "ethtool",
    "sysstat",
    "vim",
    "chrony",
    "net-tools",
    "sudo",
    "iperf3",
    # mlocate was dropped from the Debian archive as of trixie (13) —
    # plocate is its actively maintained, drop-in replacement (same
    # `locate`/`updatedb` commands). Verified against a real
    # `debian:trixie-slim` image: `apt-get install mlocate` fails with
    # "Unable to locate package", `plocate` installs cleanly.
    "plocate",
    "dnsutils",
    "bash-completion",
    "man",
    "apt-transport-https",
    "ngrep",
    "fping",
    "smartmontools",
    "pv",
    "hdparm",
    # --- Needed to add the NetBird apt repo below ---
    "curl",
    "gnupg",
    # --- Same requirement app.ssh.readiness checks for and
    # app.ssh.onboarding installs — full-color output (box-drawing,
    # 256-color) in the web Terminal tab. Installed here too so a freshly
    # Initialized device passes every readiness check out of the box,
    # never just the ones onboarding itself grants. ---
    "ncurses-term",
]

_LOCALES = ["en_US.UTF-8 UTF-8", "cs_CZ.UTF-8 UTF-8"]

_VIMRC = """\
runtime! debian.vim
let g:skip_defaults_vim = 1
syntax on
set background=dark
set mouse-=a
if has("autocmd")
  au BufReadPost * if line("'\\"") > 1 && line("'\\"") <= line("$") | exe "normal! g'\\"" | endif
endif
if has("autocmd")
  filetype plugin indent on
endif
if filereadable("/etc/vim/vimrc.local")
  source /etc/vim/vimrc.local
endif
set ruler
"""

_BASHRC = """\
[ -z "$PS1" ] && return
shopt -s checkwinsize
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi
PS1='${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ '
case "$TERM" in
xterm*|rxvt*|screen*)
    PROMPT_COMMAND='echo -ne "\\033]0;${USER}@${HOSTNAME}: ${PWD}\\007"'
    ;;
*)
    ;;
esac
if [ -x /usr/lib/command-not-found -o -x /usr/share/command-not-found/command-not-found ]; then
    function command_not_found_handle {
        if [ -x /usr/lib/command-not-found ]; then
           /usr/lib/command-not-found -- "$1"
           return $?
        elif [ -x /usr/share/command-not-found/command-not-found ]; then
           /usr/share/command-not-found/command-not-found -- "$1"
           return $?
        else
           printf "%s: command not found\\n" "$1" >&2
           return 127
        fi
    }
fi
alias ll='ls -alh --color=auto'
alias rm='rm -i'
alias mv='mv -i'
alias cp='cp -i'
"""

# vfs_object full_audit, routed to syslog facility local7 — rsyslog then
# files that to a plain log OpenCanary's `smb` module tails. See
# https://github.com/thinkst/opencanary/wiki/Opencanary-and-Samba.
# `netbios name` is capped at 15 chars and shouldn't contain spaces —
# truncated from the device name given in the Initialize form.
_SMB_SHARE_PATH = "/samba"


def _smb_conf(device_name: str) -> str:
    netbios_name = device_name[:15]
    return f"""\
[global]
   workgroup = WORKGROUP
   server string = NBDocs
   netbios name = {netbios_name}
   dns proxy = no
   log file = /var/log/samba/log.all
   log level = 0
   max log size = 100
   panic action = /usr/share/samba/panic-action %d
   server role = standalone
   passdb backend = tdbsam
   obey pam restrictions = yes
   unix password sync = no
   map to guest = bad user
   usershare allow guests = yes
   load printers = no
   vfs object = full_audit
   full_audit:prefix = %U|%I|%i|%m|%S|%L|%R|%a|%T|%D
   full_audit:success = flistxattr
   full_audit:failure = none
   full_audit:facility = local7
   full_audit:priority = notice
[documents]
   comment = Office documents
   path = {_SMB_SHARE_PATH}
   guest ok = yes
   read only = yes
   browseable = yes
"""


def _opencanary_service_unit(service_user: str) -> str:
    return f"""\
[Unit]
Description=OpenCanary honeypot
After=syslog.target
After=network.target

[Service]
User={service_user}
Restart=always
Environment=VIRTUAL_ENV=/opt/myenv
Environment=PATH=$VIRTUAL_ENV/bin:/usr/bin:$PATH
WorkingDirectory=/opt/myenv/bin
ExecStart=/opt/myenv/bin/opencanaryd --start --uid=nobody --gid=nogroup

[Install]
WantedBy=multi-user.target
"""


def service_user_for(ssh_username: str) -> str:
    """The account opencanaryd's unit runs as: the SSH login account
    itself when it's a real, non-root user (the common case — a device
    imaged with a normal account, e.g. via RPi Imager), or the source
    playbook's own `pi` default when connecting as root, since root
    itself already isn't the right account to run a network-facing
    daemon as."""
    return ssh_username if ssh_username != "root" else _DEFAULT_SERVICE_USER


def _heredoc(path: str, content: str, marker: str) -> str:
    return f"cat > {path} <<'{marker}'\n{content}{marker}\n"


def _step(label: str) -> str:
    return f"echo {shlex.quote(STEP_MARKER_PREFIX + label)}"


def build_initialize_command(
    *,
    device_name: str,
    service_user: str,
    vpn_provider: str = "none",
    netbird_setup_key: str | None = None,
    netbird_management_url: str | None = None,
    wireguard_config: str | None = None,
    new_ssh_port: int = NEW_SSH_PORT,
    ssh_username: str = "",
    authorized_keys: Sequence[str] = (),
) -> str:
    """Returns one `set -e` shell script provisioning a fresh device end to
    end: base packages, timezone/locale, a full `apt` upgrade, the
    OpenCanary venv + systemd service, hostname/`/etc/hosts`, `vim`/bash
    config, one of NetBird/WireGuard/nothing per `vpn_provider` (see
    `app.web.routes.initialize`'s VPN field — this is the honeypot's own
    connection, not HoneyHive's own; see wiki/Architecture.md's "VPN
    connectivity" section for how the two relate), OpenCanary's own config
    (`--copyconfig`), and the portscan/Samba host-side prep described in
    the module docstring above.
    """
    name = shlex.quote(device_name.strip())
    apt_packages = " ".join(shlex.quote(p) for p in dict.fromkeys(_APT_PACKAGES))
    locale_lines = "\\n".join(_LOCALES)

    lines: list[str] = ["set -e"]

    lines.append("export DEBIAN_FRONTEND=noninteractive")

    # --- Hostname + /etc/hosts, from the "device name" field ---
    lines.append(_step("Setting hostname"))
    lines.append(f"hostnamectl set-hostname {name}")
    lines.append(
        f'grep -q "^127.0.1.1[[:space:]]" /etc/hosts && '
        f'sed -i "s/^127.0.1.1[[:space:]].*/127.0.1.1\\t{device_name.strip()}/" /etc/hosts || '
        f'echo -e "127.0.1.1\\t{device_name.strip()}" >> /etc/hosts'
    )

    # --- Base + admin-tool packages, one apt run ---
    lines.append(_step("Installing packages"))
    lines.append("apt-get update -y")
    lines.append(f"apt-get install -y {apt_packages}")

    # --- OpenCanary venv (system-site-packages, so apt's python3-scapy is
    # visible inside it — see module docstring) ---
    lines.append(_step("Setting up the OpenCanary venv"))
    lines.append("if [ ! -d /opt/myenv ]; then virtualenv --system-site-packages /opt/myenv; fi")
    lines.append("/opt/myenv/bin/pip install --upgrade pip")
    lines.append("/opt/myenv/bin/pip install opencanary scapy pcapy-ng")

    # --- opencanary.service ---
    lines.append(_step("Installing the opencanary.service unit"))
    lines.append(
        _heredoc(
            "/etc/systemd/system/opencanary.service",
            _opencanary_service_unit(service_user),
            "HONEYHIVE_OPENCANARY_UNIT",
        ).rstrip()
    )
    lines.append("systemctl daemon-reload")
    lines.append("systemctl enable opencanary")

    # --- Locale ---
    lines.append(_step("Configuring locale"))
    lines.append(
        'grep -qxF "en_US.UTF-8 UTF-8" /etc/locale.gen || '
        f'printf "{locale_lines}\\n" >> /etc/locale.gen'
    )
    lines.append("locale-gen")

    # --- Time ---
    lines.append(_step("Setting timezone"))
    lines.append("timedatectl set-timezone Europe/Prague")
    lines.append("timedatectl set-ntp true")
    lines.append("systemctl restart systemd-timedated.service || true")

    # --- Full upgrade ---
    lines.append(_step("Upgrading the system (apt full-upgrade)"))
    lines.append("apt-get update -y")
    lines.append("apt-get -y full-upgrade")

    # --- vim: default editor + config (best-effort — a minimal image
    # without vim.basic shouldn't fail the whole run over this) ---
    lines.append(_step("Configuring vim and bash"))
    lines.append(
        "(command -v update-alternatives >/dev/null 2>&1 && "
        "[ -x /usr/bin/vim.basic ] && "
        "update-alternatives --set editor /usr/bin/vim.basic) || true"
    )
    lines.append(_heredoc("/etc/vim/vimrc", _VIMRC, "HONEYHIVE_VIMRC").rstrip())
    lines.append(_heredoc("/etc/bash.bashrc", _BASHRC, "HONEYHIVE_BASHRC").rstrip())

    # --- VPN: at most one of NetBird or WireGuard, per `vpn_provider` —
    # this is the honeypot's *own* connection (mirrors, but is independent
    # of, HoneyHive's own VPN choice in Settings -> VPN). "none" (the
    # default) skips this whole section — neither package is installed
    # unless actually selected. ---
    if vpn_provider == "netbird":
        lines.append(_step("Installing NetBird"))
        lines.append(
            "curl -sSL https://pkgs.netbird.io/debian/public.key | "
            # --yes: without it, gpg silently prompts "overwrite existing
            # file?" on a re-run against a device that already has this
            # keyring from an earlier attempt — and since this runs over a
            # plain SSH exec with no pty, gpg can't read that prompt from
            # /dev/tty at all, failing with "cannot open '/dev/tty'"
            # (exit 2) instead. Confirmed live: this crashed a real re-run
            # exactly this way. `--batch` suppresses every other
            # interactive behavior gpg might otherwise fall back to.
            "gpg --batch --yes --dearmor -o /usr/share/keyrings/netbird-archive-keyring.gpg"
        )
        lines.append(
            "echo 'deb [signed-by=/usr/share/keyrings/netbird-archive-keyring.gpg] "
            "https://pkgs.netbird.io/debian stable main' > /etc/apt/sources.list.d/netbird.list"
        )
        lines.append("apt-get update -y")
        lines.append("apt-get install -y netbird")
        if netbird_setup_key:
            lines.append(_step("Joining the NetBird network"))
            key = shlex.quote(netbird_setup_key.strip())
            up_cmd = f"netbird up --setup-key {key}"
            if netbird_management_url:
                up_cmd += f" --management-url {shlex.quote(netbird_management_url.strip())}"
            lines.append(up_cmd)
    elif vpn_provider == "wireguard" and wireguard_config:
        # HoneyHive doesn't generate WireGuard keys or run its own server
        # (see wiki/Architecture.md) — this is the exact peer config an
        # operator already has from wherever they run their WireGuard
        # server, brought up verbatim, the same as Settings -> VPN does
        # for HoneyHive's own side.
        lines.append(_step("Installing WireGuard"))
        lines.append("apt-get install -y wireguard-tools")
        lines.append(_step("Joining the WireGuard network"))
        lines.append(
            _heredoc(
                "/etc/wireguard/wg0.conf", wireguard_config.strip() + "\n", "HONEYHIVE_WG_CONF"
            )
        )
        lines.append("chmod 600 /etc/wireguard/wg0.conf")
        lines.append("systemctl enable wg-quick@wg0")
        lines.append("wg-quick up wg0 || (wg-quick down wg0 || true; wg-quick up wg0)")

    # --- /mnt/tmpfs: a small ramdisk OpenCanary's own log writes to
    # instead of the SD card (see app.ssh.readonly's module docstring —
    # the Honeypot Config tab's read-only-root toggle assumes this exists
    # so there's still somewhere for OpenCanary to write once root itself
    # is read-only). Idempotent: adding the fstab line twice would mount
    # it twice, so this checks first. ---
    lines.append(_step(f"Setting up the {TMPFS_SIZE_MB}MB tmpfs at {TMPFS_PATH}"))
    lines.append(f"mkdir -p {TMPFS_PATH}")
    lines.append(
        f"grep -q '{TMPFS_PATH} ' /etc/fstab || "
        f"echo 'tmpfs {TMPFS_PATH} tmpfs defaults,noatime,size={TMPFS_SIZE_MB}M 0 0' >> /etc/fstab"
    )
    lines.append(f"mountpoint -q {TMPFS_PATH} || mount {TMPFS_PATH}")

    # --- OpenCanary's own config (JSON) — generated once, never
    # overwritten on a re-run (an operator may have already hand-edited
    # it: which modules are enabled, ports, etc.) ---
    lines.append(_step("Generating the OpenCanary config"))
    lines.append(
        "[ -f /etc/opencanaryd/opencanary.conf ] || "
        "(. /opt/myenv/bin/activate && /opt/myenv/bin/opencanaryd --copyconfig)"
    )

    # --- portscan: rsyslog imjournal + legacy iptables — see module
    # docstring. Safe to re-run: every step here is its own idempotent
    # guard. ---
    lines.append(_step("Preparing the portscan module (rsyslog + legacy iptables)"))
    lines.append(
        'grep -q \'module(load="imjournal")\' /etc/rsyslog.conf || '
        '{ echo \'module(load="imjournal")\' > /etc/rsyslog.conf.new; '
        "cat /etc/rsyslog.conf >> /etc/rsyslog.conf.new; "
        "mv /etc/rsyslog.conf.new /etc/rsyslog.conf; }"
    )
    lines.append(
        "grep -rq 'kern\\.\\*.*kern\\.log' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null || "
        "printf 'kern.*\\t\\t\\t\\t\\t-/var/log/kern.log\\n' >> /etc/rsyslog.conf"
    )
    lines.append(
        "! update-alternatives --list iptables 2>/dev/null | grep -q iptables-legacy || "
        "update-alternatives --set iptables /usr/sbin/iptables-legacy"
    )
    # rsyslog's own default $FileCreateMode/$FileOwner/$FileGroup (0640
    # root:adm — see /etc/rsyslog.conf) would otherwise make a freshly
    # created kern.log unreadable by opencanaryd's unprivileged
    # `nobody:nogroup` (not a member of `adm`) once the portscan module
    # is enabled and tries to tail it — rsyslogd only sets those
    # permissions when it *creates* a file, so pre-creating it here,
    # world-readable, before rsyslog is ever restarted (below) sticks.
    lines.append("touch /var/log/kern.log")
    lines.append("chmod 644 /var/log/kern.log")

    # --- smb: Samba config + full_audit -> syslog -> plain log file, but
    # the systemd services themselves stay disabled — see module
    # docstring. ---
    lines.append(_step("Preparing Samba (service left disabled)"))
    lines.append(f"mkdir -p {_SMB_SHARE_PATH}")
    lines.append(f"chown {shlex.quote(service_user)}:{shlex.quote(service_user)} {_SMB_SHARE_PATH}")
    lines.append(f"chmod 755 {_SMB_SHARE_PATH}")
    lines.append(f"touch {_SMB_SHARE_PATH}/testing.txt")
    lines.append(
        _heredoc(
            "/etc/samba/smb.conf", _smb_conf(device_name.strip()), "HONEYHIVE_SMB_CONF"
        ).rstrip()
    )
    lines.append(
        "grep -q 'local7.*samba-audit.log' /etc/rsyslog.conf || "
        "echo 'local7.*        /var/log/samba-audit.log' >> /etc/rsyslog.conf"
    )
    lines.append("touch /var/log/samba-audit.log")
    # No dedicated `syslog` system user to chown this to (as of Debian
    # trixie's rsyslog package, its postinst no longer creates one —
    # confirmed against a real debian:trixie-slim install; the systemd
    # unit runs rsyslogd as root via CAP_* capabilities instead, same
    # reasoning modern systemd services widely moved to). `chmod 644`
    # (root-owned, world-readable) is all this actually needs: rsyslogd
    # itself runs as root regardless of file ownership, and
    # opencanaryd's `smb` module — which tails this file as the
    # unprivileged `nobody:nogroup` its systemd unit drops to — only
    # needs read access, which the world-readable bit already grants.
    lines.append("chmod 644 /var/log/samba-audit.log")
    lines.append("systemctl restart rsyslog || true")
    lines.append("systemctl disable --now smbd || true")
    lines.append("systemctl disable --now nmbd || true")

    # --- Point the just-generated config at the paths prepared above, in
    # one pass (all keys live in the same JSON file) — doesn't enable any
    # module; that's a deliberate separate, manual step. The file logger's
    # own path is best-effort (wrapped so a future OpenCanary version with
    # a differently-shaped default config doesn't fail the whole run over
    # this one, purely cosmetic, adjustment). ---
    lines.append(_step("Pointing the config at the prepared portscan/Samba/log paths"))
    lines.append(
        "python3 - <<'HONEYHIVE_INITIALIZE_CFG'\n"
        "import json\n"
        'path = "/etc/opencanaryd/opencanary.conf"\n'
        "with open(path) as f:\n"
        "    cfg = json.load(f)\n"
        'cfg["portscan.iptables_path"] = "/usr/sbin/iptables"\n'
        'cfg["smb.auditfile"] = "/var/log/samba-audit.log"\n'
        "try:\n"
        f'    cfg["logger"]["kwargs"]["handlers"]["file"]["filename"] = "{HONEYPOT_LOG_PATH}"\n'
        "except (KeyError, TypeError):\n"
        "    pass\n"
        "with open(path, \"w\") as f:\n"
        "    json.dump(cfg, f, indent=4)\n"
        "HONEYHIVE_INITIALIZE_CFG"
    )

    # --- Install every given authorized_keys entry (HoneyHive's own
    # shared identity key, plus every current superadmin's personal
    # key(s) — see app.web.routes.initialize_ws's caller) onto the
    # account Initialize connected as, so both can reach the device
    # directly afterward without needing the one-time password/key this
    # run itself used. Skipped entirely if the caller passed none (e.g.
    # no superadmin has a personal key configured yet, or the identity
    # key was somehow unavailable) — never fails the run either way, this
    # is convenience, not something later steps depend on. Idempotent and
    # strictly additive — see app.ssh.authorized_keys's module docstring
    # for why a key added by hand is never at risk from this. ---
    if ssh_username and authorized_keys:
        lines.append(_step("Installing SSH keys (HoneyHive + superadmins)"))
        lines.append(build_authorized_keys_append_command(ssh_username, list(authorized_keys)))

    # --- Grant the same scoped, passwordless sudo app.ssh.onboarding
    # grants its own dedicated `honeyhive` user — apt-get/shutdown/
    # dmidecode/systemctl(+flatpak/snap) — to the account Initialize
    # connected as. Without this, a freshly Initialized device used to
    # show up in HoneyHive already failing every one of
    # app.ssh.readiness's checks (and, in turn, things that quietly
    # depend on the same sudo, like the Honeypot Config tab's "Apply"
    # button) until an operator separately ran "Run initial setup" or the
    # readiness banner's own "Fix it" flow — this closes that gap at
    # Initialize time instead. Root never needs sudo granted to itself
    # (see app.ssh.readiness's module docstring for the same reasoning),
    # so this is skipped entirely for a root connection. ---
    if ssh_username and ssh_username != "root":
        lines.append(_step("Granting passwordless sudo (apt/shutdown/dmidecode/systemctl)"))
        lines.append(build_sudoers_grant_command(ssh_username))

    # --- Move sshd off the default port, last of all — everything else
    # above must already have succeeded (this app's own connection is what
    # ran all of it, over the *old* port, and stays open regardless of
    # what the listening port config now says). A drop-in file under
    # sshd_config.d/ (Debian's own default sshd_config Include's that
    # directory before its own commented-out "#Port 22") rather than
    # editing sshd_config directly — simpler to make idempotent (just
    # overwrite the file) and leaves the distro-maintained file untouched.
    # `sshd -t` validates the merged config *before* restarting; `set -e`
    # means a bad config aborts here without ever restarting the running
    # daemon, so this can never lock an operator out mid-run. ---
    lines.append(_step(f"Moving SSH to port {new_ssh_port}"))
    lines.append("mkdir -p /etc/ssh/sshd_config.d")
    lines.append(
        f"echo 'Port {new_ssh_port}' > /etc/ssh/sshd_config.d/honeyhive-ssh-port.conf"
    )
    lines.append("sshd -t")
    lines.append("systemctl restart ssh")
    lines.append(
        f'echo "SSH now listens on port {new_ssh_port} — use that port (not 22) when '
        f'adding this device as a honeypot in HoneyHive."'
    )

    lines.append(f"echo {INITIALIZE_SUCCESS_MARKER}")

    # --- Reboot, last of all — a full clean boot (fresh kernel state,
    # every systemd unit started the normal way, including opencanary)
    # rather than trusting everything this script just did to already be
    # in its final running state. Backgrounded, disowned, and delayed by a
    # couple of seconds so the `exec` channel this whole script runs over
    # gets to return its exit status (and the success marker above) first
    # — `app.web.routes.initialize_ws` waits for exactly that before
    # moving on to its own "wait for the device to come back" phase,
    # which is what actually confirms the reboot completed; this step
    # only ever *triggers* it. ---
    lines.append(_step("Rebooting"))
    lines.append("(sleep 2; reboot) >/dev/null 2>&1 & disown")

    return "\n".join(lines) + "\n"


def wrap_for_sudo(script: str, *, ssh_username: str, sudo_password: str | None) -> str:
    """Wraps the whole script in one `sudo` invocation when the SSH login
    account isn't already root — see `app.web.routes.initialize`'s own
    docstring for why this wraps the *entire* script once rather than
    prefixing every individual privileged line.

    - Connecting as `root` needs no sudo at all — the script runs as-is.
    - Otherwise, with a password on hand (password-auth was chosen):
      `sudo -S` reads it from stdin.
    - Otherwise (the shared-key path — no password known to this app):
      `sudo -n`, which only succeeds if the account already has
      passwordless sudo — the Raspberry Pi OS default for its initial
      user. A device without that needs either password auth chosen
      instead, or NOPASSWD sudo granted to the account by hand first.

    The script is first written to a temp file (as the unprivileged login
    user — `/tmp` is always writable) and *then* run under `sudo bash
    <file>`, rather than piping/heredoc'ing it directly into `sudo` — a
    heredoc attached to the same command as a piped password would fight
    the pipe for the same stdin, and the script's own content (the
    `.bashrc` heredoc within it) contains single quotes that would break
    a `sudo bash -c '...'` single-quoted wrapping instead.
    """
    if ssh_username == "root":
        return script
    marker = "HONEYHIVE_INITIALIZE_SCRIPT"
    script_path = "/tmp/.honeyhive-initialize.sh"  # noqa: S108 - always written then removed below
    write_script = f"cat > {script_path} <<'{marker}'\n{script}{marker}\n"
    if sudo_password:
        quoted_password = shlex.quote(sudo_password)
        run = f"echo {quoted_password} | sudo -S -p '' bash {script_path}"
    else:
        run = f"sudo -n bash {script_path}"
    return f"{write_script}{run}; status=$?; rm -f {script_path}; exit $status"
