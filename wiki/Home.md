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
read/read-write model; no SSH machine management; honeypots push events in
rather than being polled).

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

### Open product questions

These were still unanswered when this scaffold was written — check with
whoever's driving the product before building the corresponding feature,
or check recent commits/issues in case they've since been settled:

- **Who can register a new honeypot / create a company / create a user?**
  Superadmin-only (simplest, matches this scaffold's current nav — Users/
  Companies/Settings/Audit are all superadmin-gated), or can a company's
  own `READ_WRITE` user manage their own company's honeypots/users too?
- **What does "write access" mean for a honeypot?** Renaming/relocating/
  adding notes and deleting it in HoneyHive only (this app never reaches
  back into a honeypot), or does it eventually include pushing OpenCanary
  config changes to the Pi (which would need a very different, SSH-based
  mechanism this project deliberately doesn't have today)?
- **Should the audit log / Settings ever be visible to a non-superadmin?**
  Currently both are superadmin-only, mirroring debcontrol's "audit is a
  security control over the whole deployment, no partial view" stance —
  but debcontrol only had one tenant; a company here might reasonably want
  its own audit trail.
- **Alerting.** Nothing pages/emails/webhooks anyone today — is that in
  scope (per-event-type or per-honeypot-offline notifications), and via
  what channel (email, the existing syslog-forwarding-to-Wazuh path,
  something else)?
- **Event retention & volume.** `EVENT_RETENTION_DAYS` defaults to 180 —
  is that right for the expected event volume per honeypot, and does
  anything need events kept longer (compliance, a customer-facing
  report)?
- **Per-honeypot ingest tokens.** The model (`Honeypot.ingest_token_hash`)
  and the shared `INGEST_TOKEN` fallback both exist, but nothing in the UI
  generates/rotates a per-honeypot token yet — worth building before many
  honeypots share one bearer token in practice?
- **A map/geo view, CSV export of events, per-event-type dashboards** —
  none of these exist yet; worth asking which (if any) matter for v1.
