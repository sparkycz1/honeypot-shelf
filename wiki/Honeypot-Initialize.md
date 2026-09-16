# 🌱 Initialize

*A blank device walks in a plain OS install and walks out a convincing liar.*

**Initialize** (top nav, visible to anyone with write access —
company-scoped `READ_WRITE` or superadmin) provisions a **brand new**
device into a working OpenCanary honeypot over SSH, in one run: base +
admin-tool packages, a Python venv with OpenCanary/scapy/pcapy-ng, the
`opencanary.service` systemd unit, locale (English + Czech, matching this
app's own two) and timezone (Europe/Prague), a full `apt` upgrade, the
team's `vim`/`bash.bashrc` config, hostname/`/etc/hosts`, at most one of
[NetBird](https://netbird.io) or [WireGuard](https://www.wireguard.com)
(see [Architecture](Architecture.md)'s "VPN connectivity" section for how
this relates to Honeypot Shelf's own, independent VPN choice in Settings
→ VPN), generating OpenCanary's config (`opencanaryd --copyconfig`), and
host-side prep for the two modules that need it beyond `enabled: true`
(see "Modules prepared, not enabled" below — confirmed against
[OpenCanary's own wiki](https://github.com/thinkst/opencanary/wiki)).
Adapted from the team's own Ansible playbook — see `app.ssh.initialize`'s
module docstring for why this runs as one shell script instead of a real
`ansible-playbook` invocation.

**Six supported OS releases, auto-detected — nothing to pick on the
form.** The two newest releases of each of Raspberry Pi OS, Debian, and
Ubuntu (LTS, Desktop or Server — indistinguishable over plain SSH) — see
`app.ssh.platform_detect.SUPPORTED_RELEASES` for the exact list. Right
after connecting, a quick read-only probe (`/etc/os-release` plus
`command -v raspi-config`) decides which; an unsupported OS is refused
before any change is made, with a clear error naming what's supported.
Only one thing actually differs by platform — where OpenCanary's own log
lives (a tmpfs ramdisk on a device with raspi-config, to spare an SD
card the write wear the read-only-root toggle exists for — see
[Honeypot Management](Honeypot-Management.md)'s own Config-tab section —
or a plain persistent path otherwise, since Debian/Ubuntu typically
aren't running off an SD card at all). Every other step is identical
across all six.

**Run history**: `/initialize/history` keeps the last 50 runs (device,
outcome, who ran it, full output) — the run page's own live output is
otherwise gone the moment its tab closes.

**You see it happen, live**: the run page opens a WebSocket
(`app.web.routes.initialize_ws`) on load — a banner tracks the current
phase ("Installing packages", "Upgrading the system", ...) while the
script's output streams in line by line, the same feel as the interactive
SSH terminal. A run can take up to an hour on a slow Pi (`apt
full-upgrade` and compiling `pcapy-ng` are the long parts) — the socket
stays open the whole time.

**A separate, earlier step from onboarding a `Honeypot` already in
Honeypot Shelf** ([Architecture.md](Architecture.md)'s onboarding
paragraph, the "Run initial setup" button on a honeypot's Settings tab):
Initialize targets a device with no row in Honeypot Shelf yet — no pinned
host key, nothing to onboard. Once it succeeds, add the device the normal
way ([Installation](Installation.md)/`/honeypots/new`), which discovers
and pins its host key the usual, non-TOFU way, then (optionally) run its
own "Run initial setup" to hand SSH management over to Honeypot Shelf's
shared `honeypotshelf` identity.

## Fields

| Field | Notes |
|---|---|
| IP address | The device's current IP — no DNS lookup, no discovery. |
| Device name | Set as hostname and `/etc/hosts` entry. Must be a valid hostname (letters/digits/hyphens). |
| User | `root`, or any other account already reachable over SSH. Anything other than `root` runs the whole script via `sudo`. |
| SSH port | Defaults to 22 — used for *this run only*, to reach the device as it is right now. |
| New SSH port | Defaults to **22222**. As the last step, on success, sshd moves to this port (see "SSH moves to a new port on success" below) — use it, not the port above, when adding the device afterward. Editable per run — e.g. set it equal to "SSH port" to leave a device's port unchanged on a re-run. |
| Authentication | Honeypot Shelf's shared identity key (assumed already authorized — e.g. preseeded via RPi Imager; see Settings for the public key) or a one-time password. Neither the password nor any VPN field below is ever stored — used for this one run only. |
| VPN | None (default), NetBird, or WireGuard — the device's own connection, independent of Honeypot Shelf's own VPN choice in Settings → VPN (see [Architecture](Architecture.md)). Picking one reveals its own fields; picking neither installs neither package. |
| NetBird setup key | Optional (VPN = NetBird). NetBird installs either way; a setup key also joins the device to your network right away (`netbird up --setup-key ...`). Get one from your NetBird management console. |
| NetBird management URL | Optional (VPN = NetBird). Blank = NetBird Cloud; set only for a self-hosted management server. |
| WireGuard config | Required (VPN = WireGuard). The device's own peer config — the same `.conf` your WireGuard server (or its UI) hands any client. Written to `/etc/wireguard/wg0.conf`, brought up with `wg-quick up wg0` and `systemctl enable wg-quick@wg0` (survives a reboot). |

## Host-key trust is deliberately trust-on-first-use here

Every other SSH connection this app makes uses **strict pinned host-key
verification** — no blind trust on first use (see `app.ssh.client`'s
module docstring). Initialize is a narrow exception: the device isn't in
Honeypot Shelf yet, so there's no prior fingerprint to compare against.
The fingerprint is shown back after the run to note down and verify
independently if wanted — nothing about it is stored. The normal "Add
honeypot" flow that follows uses the real discover-then-confirm flow, not
this one.

## Honeypot Shelf's and every superadmin's SSH keys are installed

Second-to-last (right before the port change below), Initialize installs
Honeypot Shelf's own shared identity public key, plus every current
superadmin's personal SSH public key(s) (My account → SSH public keys —
see [Honeypot Management](Honeypot-Management.md#superadmin-personal-ssh-keys)), onto
the account it connected as — so both Honeypot Shelf and every superadmin
can reach the freshly provisioned device directly afterward, without the
one-time password/key this run used (useful especially when
"Password" was the authentication method, since that password is never
stored once the run ends). Skipped harmlessly if there's nothing to
install; safe to re-run — every key is added idempotently, never removing
or overwriting one already there, by hand or otherwise.

## Passwordless sudo is granted up front

Alongside the SSH keys above, Initialize grants the connecting account
the exact scoped, passwordless sudo `app.ssh.readiness`'s "missing
requirements" banner otherwise asks an operator to fix by hand: `apt-get`
(checking/running updates), `shutdown` (reboot/power actions), `dmidecode`
(the RAM speed fact), `systemctl` (the Honeypot Config tab's module
editor) — plus `flatpak`/`snap` if present. Skipped for a `root`
connection. Same grant `app.ssh.onboarding` gives its own dedicated
`honeypotshelf` user — a freshly Initialized device no longer shows up
already failing every readiness check.

## The device reboots, and Initialize waits for it to come back

The last step reboots the device — a full clean boot, not trusting
everything the script just did is already in its final running state.
Initialize polls the device's new SSH port (same trust-on-first-use
host-key probe, never a real login) until it answers again, for up to a
few minutes, before reporting success — so "Initialize succeeded" means
the device actually came back up. A *different* host key across the
reboot is reported as a problem, never silently accepted (see
[Architecture](Architecture.md) for the full timing). If it never comes
back within the wait window (a slow SD card, a first-boot fsck), the run
is reported failed with that explanation — check the device by hand.

## SSH moves to a new port on success

The last step moves sshd off port 22 to the "New SSH port" field
(**22222** by default, `app.ssh.initialize.NEW_SSH_PORT`), via a drop-in
file (`/etc/ssh/sshd_config.d/honeypotshelf-ssh-port.conf`) rather than
editing the distro's own `sshd_config` — idempotent, leaves the
maintained file untouched. It's last for a reason: every earlier step has
already fully succeeded over the *original* connection by the time this
runs — restarting sshd doesn't drop that already-open session, only new
connections see the new port. `sshd -t` validates the merged config
first; the whole script is `set -e`, so a config problem aborts *before*
sshd restarts — this can never lock an operator out mid-run.

**Use the new port, not 22, when adding the device as a honeypot**
afterward (`/honeypots/new`'s "Port" field) — the form and run page both
call this out. A re-run against a device already moved to the new port
still works: it connects on whichever port you give it and re-applies the
drop-in file, a no-op.

## Non-root sudo

Connecting as `root` needs no sudo. Otherwise:

- With a password: supplied to `sudo -S`.
- With the shared key: `sudo -n`, which only works if the account already
  has passwordless sudo — Raspberry Pi OS's own default for its initial
  user, not Debian's or Ubuntu's. Otherwise use password auth, or grant
  NOPASSWD sudo by hand first.

## Where OpenCanary's own log lives

Before generating the config, Initialize decides this per the detected
platform (see above): on a device with raspi-config, a 512&nbsp;MB tmpfs
at `/mnt/tmpfs` (an `/etc/fstab` entry + mounting it, idempotent) — what
the [Honeypot Config tab](Architecture.md)'s read-only-root toggle
assumes exists, so OpenCanary still has somewhere to write once `/` is
read-only, sparing the SD card that same write. On Debian/Ubuntu instead
— no read-only-root toggle offered at all, see
[Honeypot Management](Honeypot-Management.md) — a plain persistent path,
`/var/log/opencanary/opencanary.log`, which survives a reboot (a feature
there, not something to work around). Either way, Initialize repoints
OpenCanary's file logger at whichever path it set up, and the honeypot's
own `opencanary_log_path` column (kept in sync by every facts refresh,
not just at Initialize — see `app.ssh.facts`) is what the Logs tab's
"Honeypot logs" shortcut and the Activity tab's poll actually read.

## Modules prepared, not enabled

`opencanaryd --copyconfig` generates `/etc/opencanaryd/opencanary.conf`
(skipped if it already exists — a re-run never clobbers a hand-edited
config). Every module ships **disabled** by default; Initialize never
flips `"<module>.enabled"` to `true`. What it does do, for the two
modules that need real host-OS setup beyond that (every other module is a
self-contained listener, nothing further to prepare):

- **portscan** — Debian 12+ (and Ubuntu, same systemd/journald and
  nftables-backed-`iptables` defaults) dropped file-based kernel logging
  for journald-only; neither works with the module as shipped. Fixed by
  loading rsyslog's
  `imjournal` module (bridges journald back to `/var/log/kern.log`) and
  switching the `iptables` alternative to `iptables-legacy` — see
  [OpenCanary's wiki](https://github.com/thinkst/opencanary/wiki/OpenCanary-Wiki#portscan-not-working-on-debian-12).
- **smb** — Samba is installed and configured with a `full_audit` VFS
  module (`/etc/samba/smb.conf`) logging file access to syslog facility
  `local7`, which rsyslog routes to `/var/log/samba-audit.log` OpenCanary
  tails — see
  [OpenCanary's wiki](https://github.com/thinkst/opencanary/wiki/Opencanary-and-Samba).
  **`smbd`/`nmbd` are left disabled** — prepared, not live; nothing
  listens until an operator deliberately enables both services and the
  `smb` module.

Both modules' config keys (`portscan.iptables_path`, `smb.auditfile`) are
already pointed at the right paths — enabling either module afterward
needs no Terminal-tab edit: once the device is a `Honeypot`, its Config
tab has a full module editor (every module, not just these two — see
[Architecture](Architecture.md)) that ticks `"<module>.enabled"`,
restarts `opencanary`, and (for Samba) starts `smbd`/`nmbd`.

## What it doesn't do

- **Doesn't create a `Honeypot` row.** Add the device separately
  afterward — once its host key is pinned, events start arriving with no
  further setup (see [Honeypot Management](Honeypot-Management.md#-how-events-arrive-an-ssh-poll-nothing-pushed)).
- **Doesn't enable any OpenCanary module** — see "Modules prepared, not
  enabled" above and the Config tab's module editor.
