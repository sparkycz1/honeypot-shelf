# 🍯 Honeypot Management

*SSH in, ask nicely, never trust a first handshake.*

Everything here is ported from debcontrol's own machine-management layer
close to unchanged — a `Honeypot` is managed exactly like a debcontrol
`Machine` (facts, packages, monitoring, updates, terminal, logs,
scheduling). This page covers what's genuinely different: how a
honeypot gets provisioned, reached, and how its own OpenCanary events
get in.

## 🌱 Provisioning a brand-new device

[Initialize](Honeypot-Initialize.md) is the one write path that SSHes
into a device **with no `Honeypot` row at all** — everything else in
`app/ssh/*` requires one first. With no prior host-key fingerprint to
check, trust here is deliberately trust-on-first-use — the one
exception to the pinned-verification policy `app.ssh.client` enforces
everywhere else.

Runs live in the web process, not Celery (a run can take up to an hour
and the operator needs to *watch* it). Its second-to-last step installs
this app's own shared identity key plus every superadmin's personal
key(s) into the connected account — idempotently, additively — so both
the app and every superadmin can reach the device directly afterward.

### Superadmin personal SSH keys

`User.ssh_public_keys` (My account) lets a superadmin paste their own
key(s) for logging into a honeypot directly — superadmin-only by
design, since granting host-level SSH into the whole fleet is a
superadmin-tier capability, not something company scoping should ever
widen. Two things read it: **Initialize** (installs every current
superadmin's key on a fresh device) and **"Push to every honeypot"**
(does the same for the existing fleet). Both, and Settings' own
SSH-identity push, share one command builder — **strictly additive**:
every key is checked before being appended, so a key added by hand is
never overwritten or duplicated.

## 🔌 VPN connectivity: NetBird or WireGuard

**The problem**: SSH-management-plane features need `web`/`worker` to
open a plain TCP connection to a honeypot — impossible if it sits
behind a NAT with no forwarded port, a common shape for a honeypot
specifically. Two fixes, **mutually exclusive**, picked in
**Settings → VPN**: `web`/`worker` join a virtual network as a peer,
the honeypot joins the same one (via Initialize), and a plain SSH
connect to its tunnel address just works.

| | NetBird | WireGuard |
|---|---|---|
| **Solves NAT on both ends?** | Yes — NetBird's own relay/coordination server does the hole-punching | **No** — needs a WireGuard server the operator already runs |
| **What this app enters** | A setup key + management URL + an optional hostname (so this peer shows up in NetBird's dashboard as something recognizable, not the container's bare Docker hostname — only takes effect on that peer's *first* registration; renaming later needs removing it from the dashboard first, then reconnecting) | A complete peer `.conf`, same as any other client gets |
| **"Log"** | The NetBird daemon's own log, tailed | Thinner — `wg-quick`'s own output plus `wg show` |

Both run inside an optional privileged `vpn` sidecar
(`docker-compose.vpn.yml`); `web`/`worker` borrow its network namespace
rather than gaining privilege of their own. `AppSettings.vpn_provider`
is set only by whichever `connect()` last succeeded, never edited
directly — connecting one best-effort disconnects the other. This is a
**different** NetBird connection from the one on the Initialize form —
that one joins the honeypot being provisioned; this one joins this
app's own containers.

## 🔒 Honeypot Config: read-only root + the OpenCanary module editor

Two independent live-SSH sections, neither persisted in this app's own
DB — the honeypot's own state is the only copy of the truth.

**Read-only root filesystem** — only offered for a honeypot with
`supports_readonly_root` set (live-detected on every facts refresh via
`command -v raspi-config`, see `app.ssh.platform_detect`'s module
docstring for why that — not the OS/distro itself — is the actual
gate). Protects the SD card from write wear via Raspberry Pi OS's own
overlay filesystem — takes effect on next reboot, not immediately (the
Config tab says so explicitly). Not literal read-only: every write still
succeeds at runtime, just discarded on reboot. Debian/Ubuntu never show
this section at all, and get no substitute for it — those releases
typically aren't running off an SD card, so the whole reason this toggle
exists doesn't apply. OpenCanary's log just goes to a plain persistent
path instead there (see [Initialize](Honeypot-Initialize.md)'s own
"Where OpenCanary's own log lives" section).

**The OpenCanary module editor** is a category-by-category form over
every OpenCanary module (FTP, HTTP(S), SSH, Telnet, databases, RDP,
VNC, SIP, SNMP, NTP, TFTP, Git, LLMNR, a TCP banner listener, portscan,
Samba). Saving re-reads the live config, merges the form in, writes it
back, restarts `opencanary`. No module is ever force-enabled by
Initialize or this editor's own defaults. Every successful save also
tags the honeypot with its now-enabled modules — a manually-added tag
survives every future save.

## 🍯 The data model

- **`Company`** — a tenant. One row per customer.
- **`Honeypot`** — one deployed OpenCanary instance, attached to any
  number of companies via a plain link table, including zero (visible
  to a superadmin only). Identity + last-seen bookkeeping only; this
  app never connects to it proactively.
- **`HoneypotEvent`** — one row per OpenCanary alert, close to
  OpenCanary's own JSON, with the common filter fields promoted to real
  columns. Scope is derived by joining through the honeypot's companies
  at query time, since a honeypot can belong to several.
- **`CompanySnapshot`** — one row per company per day, backing the
  Dashboard's trend sparkline.

A company's own page can *attach* an already-existing honeypot or
*grant* an already-existing user access, additively — never detaching
either from wherever else they already are. Deleting a `Company` only
ever removes *links*, never the honeypot or user account itself.

## 📡 How events arrive: an SSH poll, nothing pushed

```mermaid
sequenceDiagram
    participant Beat as beat (scheduler)
    participant Worker as worker (Celery)
    participant Pi as Honeypot (Raspberry Pi OS/Debian/Ubuntu)
    participant DB as PostgreSQL

    Beat->>Worker: every opencanary_log_poll_interval_seconds
    Worker->>Pi: SSH: tail opencanary.log since last byte offset
    Pi-->>Worker: new alert lines (if any)
    Worker->>DB: store each as HoneypotEvent
    Worker->>DB: last_seen_at = now (proof OpenCanary answered at all)
```

OpenCanary has no built-in "POST to a URL" — it only logs locally. Every
`AppSettings.opencanary_log_poll_interval_seconds` (Settings → Checks &
retention, default 120), this app connects over SSH and reads whatever's
new in that log, incrementally by byte offset — no setup needed on the
honeypot side beyond a pinned host key. Backs the **Activity** tab.

**"Online"/"offline"** is `last_seen_at` vs.
`HONEYPOT_OFFLINE_AFTER_SECONDS`, deliberately separate from
`is_reachable`/`last_ping_at` (a plain SSH-plane ping — see the note on
[Home](Home.md)). A poll bumps `last_seen_at` on **any** successful
contact with the log, not only when it found a real alert, so a quiet
but healthy honeypot doesn't sit "offline" forever for lack of attacker
traffic. The Monitoring tab's **"OpenCanary service"** panel is a third
signal — `systemctl is-active opencanary`, piggybacked on the same
round trip the CPU/RAM sample already makes.

## Three syslog targets, deliberately never mixed

- **Global** (`app.audit_syslog`, Settings → Integrations) — every
  `AuditLogEntry`. Never a honeypot alert. See [Audit Log](Audit-Log.md).
- **Per-company** — one target per `Company`, that company's own
  Integrations tab. An alert from a honeypot shared across companies
  goes to **every** one of its companies' own targets. Never an audit
  entry.
- **Fleet-wide** — "All honeypots" → Integrations, not backed by any
  `Company` row. Every honeypot's alerts, **in addition to** the
  per-company target if both are set.

Split by company because this is multi-tenant — company A's SOC
shouldn't see company B's traffic. All three share one transport
(UDP/TCP/TCP-over-TLS) and one convention: the RFC 5424 MSG part is
always a compact JSON object, never `key="value"` text. All
best-effort — a delivery failure is logged and swallowed.

**Wazuh users**: `wazuh/honeypotshelf_decoders.xml` decodes this JSON
and `wazuh/honeypotshelf_rules.xml` (repo root) ships one rule per
OpenCanary module (rule ids `107000`-`107099`), plus a brute-force
correlation rule for repeated SSH login attempts against the same
honeypot from the same source IP — see
[Audit Log](Audit-Log.md#forwarding-to-your-own-siem) for the same
ruleset's audit-side coverage.

## Settings → Checks & retention: database-backed, not `.env`

Every background-check timeout/interval and every retention policy
lives on `AppSettings` (Settings → **Checks & retention**), not `.env`
— a change applies without a restart for the timeouts/concurrency cap
(read fresh from the database on every call), but the four sweep
*intervals* (reachability/facts/monitoring/OpenCanary-log-poll) still
only take effect on the next `worker`/`beat` restart, since a Celery
`beat_schedule` entry's `schedule` is a plain value computed once at
import time. Ported from an identical debcontrol change.

## 🗺️ GeoIP and the Map page

Resolves a `HoneypotEvent`'s (or an `AuditLogEntry`'s) source IP to a
country/city/lat-long, **once, at write time** — not re-derived later, so
a row's location stays historically accurate even after the database
itself is updated. Deliberately only ever for a **public** IP:
`ipaddress.ip_address(...).is_global` gates every lookup (`app.services.
geoip`), since a company's own LAN-facing traffic or a login through an
internal proxy has no real-world location to show, and would otherwise
just waste a lookup MaxMind's database has no record for anyway.

**Needs a database this app never bundles** (redistributing MaxMind's
GeoLite2 data isn't allowed under their license) — Settings → **GeoIP**
takes a primary and backup download URL instead (both stored encrypted,
same convention as every other secret in Settings, since a MaxMind
"permalink" embeds your license key), tried in that order, never
load-balanced. Not MaxMind-specific: any URL serving a compatible
`.mmdb` — gzipped or not, raw or inside a `.tar.gz` — works, detected
from the bytes themselves (`app.services.geoip._extract_mmdb`). A
"Download now" button runs the same Celery task the periodic refresh
(`AppSettings.geoip_refresh_interval_hours`, default weekly — MaxMind
itself only updates GeoLite2 a couple of times a week) uses, so the two
paths can never disagree on what "downloading" means. The downloaded
bytes live in their own singleton table (`GeoipDatabase`), not on
`AppSettings` itself — that row is read on essentially every request, so
a multi-megabyte blob there would be a cost paid by every caller, not
just GeoIP lookups.

**The reader is cached in-process**, revalidated against `GeoipDatabase.
updated_at` at most once an hour — the overwhelming majority of calls
(every audit log write, every ingested honeypot event) cost one
in-memory check, not a database round trip, at the price of a freshly
downloaded database taking up to an hour to be picked up by an
already-running `web`/`worker` process.

**The Map page** (company-scoped exactly like the Dashboard) plots
every located event on a real (if label-free) world coastline — traced
once, offline, from Natural Earth's public-domain land outline, not a
full political map with borders/place names (see
`app.services.geoip_display.WORLD_LAND_PATH`). Pannable/zoomable —
wheel, drag, pinch, or the +/−/reset buttons
(`app/web/static/js/map-zoom.js`) — since a screenful of dots at world
scale hides exactly the regional clustering a company with a lot of
traffic from one area most wants to see. A top-countries table (flag
emoji + name + count) sits below it either way. The audit log shows the same
resolved country next to each entry's IP, deliberately **excluded**
from the hash chain (`AuditLogEntry.entry_hash`) — it's a display
enrichment, not part of the tamper-evident record of what actually
happened.

## Small but worth knowing

- **Alert type labels are localized** for the two template-rendering
  call sites — the REST API, exports, and both syslog forwarders keep
  the plain English label on purpose, since a machine-consumed response
  shouldn't vary by session.
- **Live updates over WebSocket**: a page opens one WebSocket and turns
  each `{"kind": "..."}` push into a DOM event, so its htmx panel
  refreshes within about a second instead of waiting out its poll
  interval — the poll stays only as a fallback for a missed/dropped
  push. Every message carries a `kind` only, never actual data, so the
  socket is a doorbell, not a feed: whatever it triggers is still
  fetched (and permission/scope-checked) exactly like its periodic poll
  already was. Four independent scopes share this mechanism
  (`app/services/live_updates.py`, `app/web/routes/live_ws.py`,
  `app/web/static/js/live-updates.js`):
  - **Per-honeypot** — Overview, Monitoring, Activity, Updates. The
    Monitoring and Activity tabs also have a "Refresh now" button.
  - **Fleet-wide** — the Dashboard and the Map page, refreshed the
    moment any honeypot's reachability or activity changes anywhere in
    view.
  - **Admin-wide** — the Audit log and the Companies list, refreshed
    the moment a new audit entry is written (which covers company/user
    create-edit-delete too, since those are always audit-logged).
    Superadmin-only, matching those pages.
  - **Per-user** — a user's own Notification history, refreshed the
    moment a send attempt (real or test) is logged for them.

  Deliberately **not** wired up on pages built around an in-progress
  form or a bulk-selection checkbox list (the Honeypots list, Users
  list, Scheduling) — an unannounced full-table swap mid-selection or
  mid-edit would silently discard whatever the operator was doing.
  Those keep their existing polling fallback only.
- **Update rollback**: every real update run captures a package-version
  snapshot right before upgrading. "Roll back this update" diffs a
  fresh snapshot against that stored one and re-installs, pinned by
  exact version, only whatever actually changed since.
