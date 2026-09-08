# 🌱 Initialize

The **Initialize** page (top nav, visible to anyone with write access —
company-scoped `READ_WRITE` or superadmin) provisions a **brand new**
Raspberry Pi OS 13 (Debian trixie) device into a working OpenCanary
honeypot over SSH, in one run: base + admin-tool packages, a Python venv
with OpenCanary/scapy/pcapy-ng, the `opencanary.service` systemd unit,
locale (English + Czech, matching this app's own two) and timezone
(Europe/Prague), a full `apt` upgrade, the team's `vim`/`bash.bashrc`
config, the device's hostname/`/etc/hosts` entry, at most one of
[NetBird](https://netbird.io) or [WireGuard](https://www.wireguard.com)
(per the VPN field below — see [Architecture](Architecture.md)'s "VPN
connectivity" section for how this relates to HoneyHive's own,
independent VPN choice in Settings → VPN), generating OpenCanary's own config
(`opencanaryd --copyconfig`), and — confirmed against
[OpenCanary's own wiki](https://github.com/thinkst/opencanary/wiki) as the
only two modules that need it — the host-side setup **portscan** and
**smb** each need beyond just flipping `enabled` in that config (see
"Modules prepared, not enabled" below). Adapted from the team's own
Ansible playbook — see `app.ssh.initialize`'s module docstring for exactly
what changed and why this runs as one shell script instead of a real
`ansible-playbook` invocation (same reasoning as the "Run initial setup"
onboarding step below).

**Run history**: `/initialize/history` keeps the last 50 runs (device,
outcome, who ran it, and its full output) — the WebSocket output above is
otherwise gone the moment the run page is closed, so this is what to check
after a failed provisioning without having had to keep that tab open.

**You see it happen, live**: the run page opens a WebSocket
(`app.web.routes.initialize_ws`) the moment it loads — a banner at the top
tracks which phase is currently running ("Installing packages", "Upgrading
the system", ...), and the script's actual output streams into the panel
below it line by line as it's produced, the same "watch it happen" feel as
the interactive SSH terminal. A run can take up to an hour on a slow Pi
(the `apt full-upgrade` and compiling `pcapy-ng` are the long parts) — the
socket stays open the whole time.

**This is a separate, earlier step from onboarding a `Honeypot` already
in HoneyHive** ([Architecture.md](Architecture.md)'s onboarding
paragraph, the "Run initial setup" button on a honeypot's Settings tab):
Initialize targets a device that isn't in HoneyHive's database at all
yet — there's no honeypot row, no pinned host key, nothing to onboard.
Once it succeeds, add the device the normal way
([Installation](Installation.md)/`/honeypots/new`), which discovers and
pins its host key the usual, non-TOFU way, then (optionally) run its own
"Run initial setup" to hand SSH management over to HoneyHive's shared
`honeyhive` identity.

## Fields

| Field | Notes |
|---|---|
| IP address | The device's current IP — no DNS lookup, no discovery. |
| Device name | Set as the device's hostname and `/etc/hosts` entry. Must be a valid hostname (letters/digits/hyphens). |
| User | `root`, or any other account already reachable over SSH. Anything other than `root` runs the whole script via `sudo`. |
| SSH port | Defaults to 22. |
| Authentication | HoneyHive's own shared identity key (assumed already authorized on the device — e.g. preseeded via RPi Imager; see Settings for the public key) or a one-time password. Neither the password nor any of the VPN fields below is ever stored — all of them are used for this one run only. |
| VPN | None (default), NetBird, or WireGuard — the device's own connection, independent of HoneyHive's own VPN choice in Settings → VPN (see [Architecture](Architecture.md)). Picking one reveals its own fields below; picking neither installs neither package. |
| NetBird setup key | Optional (shown when VPN = NetBird). NetBird installs either way; a setup key also joins the device to your network right away (`netbird up --setup-key ...`). Get one from your NetBird management console. |
| NetBird management URL | Optional (shown when VPN = NetBird). Blank = NetBird Cloud (the public management service); set this only for a self-hosted management server. |
| WireGuard config | Required when VPN = WireGuard. The device's own peer config — the same `.conf` your WireGuard server admin (or its own UI) already hands out for any client. Written to `/etc/wireguard/wg0.conf` and brought up with `wg-quick up wg0` (and `systemctl enable wg-quick@wg0`, so it survives a reboot). |

## Host-key trust is deliberately trust-on-first-use here

Every other SSH connection this app makes uses **strict pinned host-key
verification** — no blind trust on first use (see `app.ssh.client`'s
module docstring). Initialize is a narrow, explicit exception: since the
device isn't in HoneyHive at all yet, there is no prior fingerprint to
compare the one it presents against. The fingerprint is shown back after
the run so an operator can note it down and verify it independently if
they want to; nothing about it is stored anywhere. The normal "Add
honeypot" flow that follows uses the real discover-then-confirm flow, not
this one.

## Non-root sudo

Connecting as `root` needs no sudo. Otherwise:

- With a password (password auth chosen): supplied to `sudo -S`.
- With the shared key (no password known to this app): `sudo -n`, which
  only works if the account already has passwordless sudo — the
  Raspberry Pi OS default for its initial user. A device without that
  needs either password auth instead, or NOPASSWD sudo granted by hand
  first.

## A tmpfs ramdisk for OpenCanary's own log

Before generating the config, Initialize sets up a 512&nbsp;MB tmpfs at
`/mnt/tmpfs` (an `/etc/fstab` entry + mounting it immediately — idempotent,
safe on a re-run) and best-effort repoints OpenCanary's file logger at
`/mnt/tmpfs/opencanary.log`. This is what the [Honeypot Config
tab](Architecture.md)'s read-only-root toggle assumes exists — once `/` is
read-only, OpenCanary still needs somewhere to write its own log, and a
ramdisk both works and, as a bonus, is one less thing writing to the SD
card. The Logs tab's "Honeypot logs" shortcut points at this same path.

## Modules prepared, not enabled

`opencanaryd --copyconfig` generates `/etc/opencanaryd/opencanary.conf`
(skipped if it already exists — a re-run never clobbers a hand-edited
config). Every module ships however `--copyconfig` defaults it —
**disabled** — same as any other module; Initialize never flips
`"<module>.enabled"` to `true` for you. What it does do, for the two
modules that need real host-OS setup beyond that (confirmed against
OpenCanary's own wiki — every other module is a self-contained listener,
nothing further to prepare):

- **portscan** — Debian 12+ dropped file-based kernel logging in favor of
  journald-only, and defaults to the nftables-backed `iptables` binary;
  neither works with the portscan module as shipped. Fixed by loading
  rsyslog's `imjournal` module (bridges journald back to a plain
  `/var/log/kern.log`) and switching the `iptables` alternative to
  `iptables-legacy` — see
  [OpenCanary's wiki](https://github.com/thinkst/opencanary/wiki/OpenCanary-Wiki#portscan-not-working-on-debian-12).
- **smb** — Samba itself is installed and configured with a `full_audit`
  VFS module (`/etc/samba/smb.conf`) that logs file access to syslog
  facility `local7`, which rsyslog then routes to a plain
  `/var/log/samba-audit.log` OpenCanary tails — see
  [OpenCanary's wiki](https://github.com/thinkst/opencanary/wiki/Opencanary-and-Samba).
  **Samba's own `smbd`/`nmbd` systemd services are left disabled** —
  prepared, not live; nothing listens on the network from this until an
  operator deliberately enables both those services and the `smb` module.

Both modules' relevant config keys (`portscan.iptables_path`,
`smb.auditfile`) are already pointed at the right paths — enabling either
module afterward is all that's left to do, and doesn't need the Terminal
tab or a manual `opencanary.conf` edit: once the device is added as a
`Honeypot`, its own Config tab has a full module editor (every module,
not just these two — see [Architecture](Architecture.md)) that ticks
`"<module>.enabled"`, restarts `opencanary`, and (for Samba) starts
`smbd`/`nmbd` for you.

## What it doesn't do

- **Doesn't create a `Honeypot` row.** Standalone tool — add the device
  separately afterward.
- **Doesn't enable any OpenCanary module** — see "Modules prepared, not
  enabled" above and the Honeypot Config tab's module editor
  ([Architecture](Architecture.md)) for actually turning one on.
- **Doesn't wire up event forwarding** — see
  [Honeypot Onboarding](Honeypot-Onboarding.md) for `POST
  /api/ingest/{honeypot_id}/events`, which needs the `Honeypot` row this
  page deliberately doesn't create.
