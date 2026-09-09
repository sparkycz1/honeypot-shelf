# 🐝 HoneyHive

Management and monitoring for a fleet of
[OpenCanary](https://github.com/thinkst/opencanary) honeypots (Raspberry
Pis deployed at customer sites), across **multiple companies**, each with
their own scoped users. Every page requires a login; access is controlled
per company (see [Architecture](Architecture.md#authentication--rbac)),
with accounts authenticating locally, against LDAP, or via OIDC SSO. Login
is two steps — username, then a passkey (signs straight in, no password
needed) or a password (plus TOTP and/or a passkey as a second factor, if
either is set up). A honeypot is managed exactly like a
machine in debcontrol (a sister project managing Debian machines over
SSH, which this project's tech stack, layout, auth system, and entire SSH
management layer were ported from) — terminal, facts, packages, updates,
power, scheduling — plus this project's own addition: honeypots push
OpenCanary events in, and the Dashboard sums them per company. See
[CLAUDE.md](../CLAUDE.md) for the full "what was reused vs. what's
different" story.

## 📑 Wiki contents

See [README](README.md) for the full page list. Start with
[Installation](Installation.md) to run it, or
[Architecture](Architecture.md) to understand how it's built.

## ✅ Current state

Built and verified end-to-end (real Postgres, migrated, exercised through
the actual app, not just unit tests): the full auth stack; company-scoped
RBAC; event ingestion and the Dashboard; full Honeypot management
(create/edit/delete, host-key discovery/trust, the SSH terminal, Logs
(journal, a clickable file browser, and a shortcut to OpenCanary's own
log), facts/packages/services refresh, system updates with live output,
power actions, an Activity tab reading whatever's new in OpenCanary's own
log over SSH (no forwarder setup needed — an aggregated by-alert-type
trend chart plus a recent-alerts list, see
[Architecture](Architecture.md)), and a Honeypot Config tab toggling the
read-only root filesystem for SD card longevity plus a full
category-by-category editor for every OpenCanary module (FTP/HTTP(S)/SSH/
Telnet/databases/RDP/VNC/SIP/SNMP/NTP/TFTP/Git/LLMNR/a generic TCP
banner/portscan/Samba));
[Initialize](Honeypot-Initialize.md) — provisioning a brand new
Raspberry Pi into a working honeypot (packages, OpenCanary, NetBird) over
SSH before it's ever added to HoneyHive, with a persisted run history for
debugging a failed provisioning after the fact; Company management (each
company's own page shows just its users and its honeypots, each with a
link to add another) and fleet-wide/"All honeypots" bulk actions;
Scheduling, including a per-schedule run history and one-click retry for a
failed firing; a per-honeypot ingest token (rotate/revoke from that
honeypot's Settings tab), alternative to the shared `INGEST_TOKEN`;
NetBird or WireGuard connectivity for HoneyHive's own SSH management
plane (Settings → VPN, an optional `docker-compose.vpn.yml` sidecar — see
[Architecture](Architecture.md)) for a honeypot that's only reachable over
one of those; the REST API mirroring all of the above; Users and Settings
(LDAP/OIDC/syslog forwarding, SSH key rotation, retention policies); full
**English and
Czech i18n** across every page, not just the site chrome. A 177-test
suite covers the RBAC/scoping-sensitive paths; `ruff check .` and `mypy
app alembic tests` are both fully clean. See [CLAUDE.md](../CLAUDE.md)'s
"Current state" section for what's left (mainly: no CI workflow file).

### Product decisions (settled)

- **Who can create a company/honeypot/user?** Superadmin only. A company
  user (`READ` or `READ_WRITE`) never creates a company or another user —
  only global admins do. A `READ_WRITE` user *does* manage the honeypots
  already in their own company (create/edit/delete, terminal, updates,
  power — everything `/honeypots` offers, already scoped to that company).
  Companies/Users/Settings/Audit stay superadmin-only end to end (nav,
  web routes, and REST API).
- **What does `READ_WRITE` mean on a honeypot?** More than HoneyHive-side
  metadata — it includes reaching into the honeypot itself: an interactive
  terminal, and everything debcontrol's `Machine` management already
  covers (facts, packages, system updates, power, running an ad-hoc
  command via Scheduling's `run_command` action). See
  [Architecture](Architecture.md) for exactly what that covers today, and
  what's still web-UI-only by design (SSH key rotation, LDAP/OIDC config).
- **Alerting**: out of scope for v1 — this is a management/overview tool,
  not a notification system. (`AppSettings.syslog_*` forwarding to a SIEM
  such as Wazuh, copied from debcontrol, still exists as an escape hatch
  for anyone who wants alerting via their own tooling instead.)
- **Audit log / Settings visibility**: superadmin-only.

### Still-open questions

- **Event retention & volume.** `EVENT_RETENTION_DAYS` defaults to 180 —
  right for the expected event volume per honeypot?
- **A map/geo view, CSV export of events, per-event-type dashboards** —
  none of these exist yet; worth asking which (if any) matter for v1.
