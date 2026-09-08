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
(create/edit/delete, host-key discovery/trust, the SSH terminal, Logs,
facts/packages/services refresh, system updates with live output, power
actions); [Initialize](Honeypot-Initialize.md) — provisioning a brand new
Raspberry Pi into a working honeypot (packages, OpenCanary, NetBird) over
SSH before it's ever added to HoneyHive; Company management and
fleet-wide/"All honeypots" bulk actions; Scheduling; the REST API
mirroring all of the above; Users and Settings (LDAP/OIDC/syslog
forwarding, SSH key rotation, retention policies). An 80-test suite
covers the RBAC/scoping-sensitive paths. See [CLAUDE.md](../CLAUDE.md)'s
"Current state" section for exact gaps (mainly: i18n coverage is still
just the site chrome, and a lint/mypy cleanup pass hasn't happened yet).

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
- **Per-honeypot ingest tokens.** The model (`Honeypot.ingest_token_hash`)
  and the shared `INGEST_TOKEN` fallback both exist, but nothing in the UI
  generates/rotates a per-honeypot token yet.
- **What exactly does "host configuration" cover beyond the SSH terminal
  already ported?** Network/IP settings specifically, OpenCanary's own
  YAML config with a service restart, or is the terminal itself (already
  built) considered sufficient for that?
- **A map/geo view, CSV export of events, per-event-type dashboards** —
  none of these exist yet; worth asking which (if any) matter for v1.
- **i18n**: worth investing in full Czech coverage beyond the site chrome
  before going live, or is English-only acceptable for now?
