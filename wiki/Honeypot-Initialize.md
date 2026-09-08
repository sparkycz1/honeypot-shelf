# 🌱 Initialize

The **Initialize** page (top nav, visible to anyone with write access —
company-scoped `READ_WRITE` or superadmin) provisions a **brand new**
Raspberry Pi OS 13 (Debian trixie) device into a working OpenCanary
honeypot over SSH, in one run: base + admin-tool packages, a Python venv
with OpenCanary/scapy/pcapy-ng, the `opencanary.service` systemd unit,
locale (English + Czech, matching this app's own two) and timezone
(Europe/Prague), a full `apt` upgrade, the team's `vim`/`bash.bashrc`
config, the device's hostname/`/etc/hosts` entry, and
[NetBird](https://netbird.io) (repo + package, and joining your network if
a setup key is given). Adapted from the team's own Ansible playbook — see
`app.ssh.initialize`'s module docstring for exactly what changed and why
this runs as one shell script instead of a real `ansible-playbook`
invocation (same reasoning as the "Run initial setup" onboarding step
below).

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
| Authentication | HoneyHive's own shared identity key (assumed already authorized on the device — e.g. preseeded via RPi Imager; see Settings for the public key) or a one-time password. Neither the password nor the NetBird setup key below is ever stored — both are used for this one run only. |
| NetBird setup key | Optional. NetBird installs either way; a setup key also joins the device to your network right away (`netbird up --setup-key ...`). Get one from your NetBird management console. The management server URL (blank = NetBird Cloud) is configured once, globally, on Settings → Integrations. |

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

## What it doesn't do

- **Doesn't create a `Honeypot` row.** Standalone tool — add the device
  separately afterward.
- **Doesn't configure OpenCanary's own modules/config** (`/opt/myenv`'s
  `opencanary.conf`) — every module ships disabled by default; that's a
  manual step (or your own separate config-management step) after
  Initialize finishes.
- **Doesn't wire up event forwarding** — see
  [Honeypot Onboarding](Honeypot-Onboarding.md) for `POST
  /api/ingest/{honeypot_id}/events`, which needs the `Honeypot` row this
  page deliberately doesn't create.
