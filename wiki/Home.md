# 🐝 HoneyHive

Management and monitoring overview for a fleet of
[OpenCanary](https://github.com/thinkst/opencanary) honeypots (Raspberry
Pis deployed at customer sites), across **multiple companies**, each with
their own scoped users. Every page requires a login; access is controlled
per company (see [Architecture](Architecture.md#authentication--rbac)),
with accounts authenticating locally, against LDAP, or via OIDC SSO, with
optional TOTP/passkey two-factor.

This project reuses debcontrol's (a sister project managing Debian
machines over SSH) technology stack, project layout, and entire auth
system — see [CLAUDE.md](../CLAUDE.md) for what was reused verbatim and
what's different here (no roles/groups — a flat per-company
read/read-write model). **Monitoring (event ingestion, dashboard) and
remote management (SSH terminal, host config/IP changes) are both in
scope** — see "SSH-based remote management" below; this scaffold only has
the monitoring half built so far.

## 📑 Wiki contents

See [README](README.md) for the full page list. Start with
[Installation](Installation.md) to run it, or
[Architecture](Architecture.md) to understand how it's built.

## 🚧 Current state — this is a fresh scaffold, not a finished app

What's real today: the domain model (companies, users, honeypots, events),
the full auth stack, company-scoped access, event ingestion, the
Dashboard, and read-only Honeypots/Companies/Users/Audit/Settings pages.
**Not built yet**: create/edit/delete forms, the REST API, an initial
Alembic migration, tests. See [CLAUDE.md](../CLAUDE.md)'s "Current state"
section for the exact list.

### Product decisions (settled)

- **Who can create a company/honeypot/user?** Superadmin only. A company
  user (`READ` or `READ_WRITE`) never creates these — only global admins
  do. Matches the current nav (Users/Companies/Settings/Audit are all
  superadmin-gated).
- **What does `READ_WRITE` mean on a honeypot?** More than HoneyHive-side
  metadata — it includes **reaching into the honeypot itself**: an
  interactive terminal, host configuration changes, IP/network settings.
  This is a much bigger feature than the current scaffold has — see
  "SSH-based remote management" below.
- **Alerting**: out of scope for v1 — this is a dashboard/overview tool,
  not a notification system. (The existing `AppSettings.syslog_*`
  forwarding-to-Wazuh path, copied from debcontrol, still exists as an
  escape hatch for anyone who wants alerting via their SIEM instead.)
- **Audit log / Settings visibility**: superadmin-only, staying as-is.

### SSH-based remote management — the next major piece to build

`READ_WRITE` on a honeypot needs to behave like debcontrol's
`machine.manage` + `action.terminal`, scoped to the honeypots in a user's
own company: an interactive browser SSH terminal, and the ability to push
host configuration (network/IP settings, presumably OpenCanary's own
config too — confirm exact scope before building) to the Raspberry Pi.
This scaffold deliberately shipped **without** any SSH client code (see
CLAUDE.md's original "deliberately not reused" list) — that assumption no
longer holds and needs walking back:

- Re-add `asyncssh` as a dependency, and an SSH identity mechanism
  (`app/ssh/`, `SSHIdentity` model) — debcontrol's own implementation
  (host-key pinning, one shared keypair, rotation) is the reference to
  port from, adapted so a honeypot's SSH credential is scoped to its
  `Company` like everything else here.
- A `terminal_ws.py`-equivalent WebSocket route, gated by `READ_WRITE` +
  `ensure_company_access` instead of a `Permission` — WebSockets bypass
  `app.auth.middleware` entirely (Starlette doesn't run HTTP middleware
  for `scope["type"] == "websocket"`), so this route re-implements the
  session-cookie + access check itself, exactly like debcontrol's does.
- Host key pinning matters *more* here than in debcontrol, not less — a
  honeypot is an intentionally-exposed, high-risk box; never connect
  without an explicitly confirmed fingerprint.
- Decide, before building, exactly what "host configuration" covers
  (network/IP only? OpenCanary's own YAML config, restarting the service
  after? both?) and whether it's the same one shared SSH identity per
  Company (like debcontrol's fleet-wide one) or genuinely per-honeypot.

### Still-open questions

- **Event retention & volume.** `EVENT_RETENTION_DAYS` defaults to 180 —
  right for the expected event volume per honeypot?
- **Per-honeypot ingest tokens.** The model (`Honeypot.ingest_token_hash`)
  and the shared `INGEST_TOKEN` fallback both exist, but nothing in the UI
  generates/rotates a per-honeypot token yet.
- **A map/geo view, CSV export of events, per-event-type dashboards** —
  none of these exist yet; worth asking which (if any) matter for v1.
