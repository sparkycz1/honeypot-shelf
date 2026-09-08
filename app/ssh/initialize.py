"""Builds the shell script that provisions a **brand new** Raspberry Pi OS
13 (Debian trixie) device into a working OpenCanary honeypot, run once over
SSH (see `app.tasks.jobs._run_honeypot_initialize`, the only caller) —
the "Initialize" top-nav action (`app.web.routes.initialize`).

Adapted from the team's own Ansible playbook (packages, the venv +
OpenCanary/scapy/pcapy-ng install, the `opencanary.service` unit, locales,
timezone, the `vim`/`bash.bashrc` config, the base tool set) plus two
things the playbook didn't cover that this app needed: setting the
device's hostname/`/etc/hosts` entry from the name given in the Initialize
form, and installing + joining NetBird (repo + package + `netbird up`).

Deliberately **not** an actual `ansible-playbook` invocation, for the same
reason `app.ssh.onboarding` gives: one `set -e` shell script over the SSH
connection this app already has, no Ansible dependency added to the
worker image. Unlike onboarding (which only ever touches an
already-known, already-pinned `Honeypot` row), this targets a device that
isn't in HoneyHive's database at all yet — see
`app.web.routes.initialize` for how the connection itself is authenticated
and host-key-trusted for that case.

Idempotent throughout (every step guards against "already done") — safe to
re-run Initialize against the same device after a partial failure.
"""

from __future__ import annotations

import shlex

# Printed as the script's last line on success — same "did it actually run
# to completion" reasoning as app.ssh.onboarding.ONBOARD_SUCCESS_MARKER.
INITIALIZE_SUCCESS_MARKER = "HONEYHIVE_INITIALIZE_OK"

# apt's `full-upgrade` plus compiling pcapy-ng/scapy from source can
# genuinely take the better part of an hour on slower Pi models — give
# this a lot more headroom than any other SSH-connecting job in this app.
# Shared between app.tasks.jobs (the Celery task's own time_limit) and
# app.web.routes.initialize (how long the request handler waits on it).
INITIALIZE_RUN_TIMEOUT_EXTRA_SECONDS = 45 * 60

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
    "mlocate",
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


def build_initialize_command(
    *,
    device_name: str,
    service_user: str,
    netbird_setup_key: str | None,
    netbird_management_url: str | None,
) -> str:
    """Returns one `set -e` shell script provisioning a fresh device end to
    end: base packages, timezone/locale, a full `apt` upgrade, the
    OpenCanary venv + systemd service, hostname/`/etc/hosts`, `vim`/bash
    config, and (if a setup key was given) NetBird.
    """
    name = shlex.quote(device_name.strip())
    apt_packages = " ".join(shlex.quote(p) for p in dict.fromkeys(_APT_PACKAGES))
    locale_lines = "\\n".join(_LOCALES)

    lines: list[str] = ["set -e"]

    lines.append("export DEBIAN_FRONTEND=noninteractive")

    # --- Hostname + /etc/hosts, from the "device name" field ---
    lines.append(f"hostnamectl set-hostname {name}")
    lines.append(
        f'grep -q "^127.0.1.1[[:space:]]" /etc/hosts && '
        f'sed -i "s/^127.0.1.1[[:space:]].*/127.0.1.1\\t{device_name.strip()}/" /etc/hosts || '
        f'echo -e "127.0.1.1\\t{device_name.strip()}" >> /etc/hosts'
    )

    # --- Base + admin-tool packages, one apt run ---
    lines.append("apt-get update -y")
    lines.append(f"apt-get install -y {apt_packages}")

    # --- OpenCanary venv (system-site-packages, so apt's python3-scapy is
    # visible inside it — see module docstring) ---
    lines.append("if [ ! -d /opt/myenv ]; then virtualenv --system-site-packages /opt/myenv; fi")
    lines.append("/opt/myenv/bin/pip install --upgrade pip")
    lines.append("/opt/myenv/bin/pip install opencanary scapy pcapy-ng")

    # --- opencanary.service ---
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
    lines.append(
        'grep -qxF "en_US.UTF-8 UTF-8" /etc/locale.gen || '
        f'printf "{locale_lines}\\n" >> /etc/locale.gen'
    )
    lines.append("locale-gen")

    # --- Time ---
    lines.append("timedatectl set-timezone Europe/Prague")
    lines.append("timedatectl set-ntp true")
    lines.append("systemctl restart systemd-timedated.service || true")

    # --- Full upgrade ---
    lines.append("apt-get update -y")
    lines.append("apt-get -y full-upgrade")

    # --- vim: default editor + config (best-effort — a minimal image
    # without vim.basic shouldn't fail the whole run over this) ---
    lines.append(
        "(command -v update-alternatives >/dev/null 2>&1 && "
        "[ -x /usr/bin/vim.basic ] && "
        "update-alternatives --set editor /usr/bin/vim.basic) || true"
    )
    lines.append(_heredoc("/etc/vim/vimrc", _VIMRC, "HONEYHIVE_VIMRC").rstrip())

    # --- bash.bashrc ---
    lines.append(_heredoc("/etc/bash.bashrc", _BASHRC, "HONEYHIVE_BASHRC").rstrip())

    # --- NetBird: add the repo, install, and (if a setup key was given)
    # join the network. Installing without joining is also a valid
    # outcome — `netbird up` only runs when a key is present. ---
    lines.append(
        "curl -sSL https://pkgs.netbird.io/debian/public.key | "
        "gpg --dearmor -o /usr/share/keyrings/netbird-archive-keyring.gpg"
    )
    lines.append(
        "echo 'deb [signed-by=/usr/share/keyrings/netbird-archive-keyring.gpg] "
        "https://pkgs.netbird.io/debian stable main' > /etc/apt/sources.list.d/netbird.list"
    )
    lines.append("apt-get update -y")
    lines.append("apt-get install -y netbird")
    if netbird_setup_key:
        key = shlex.quote(netbird_setup_key.strip())
        up_cmd = f"netbird up --setup-key {key}"
        if netbird_management_url:
            up_cmd += f" --management-url {shlex.quote(netbird_management_url.strip())}"
        lines.append(up_cmd)

    lines.append(f"echo {INITIALIZE_SUCCESS_MARKER}")

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
