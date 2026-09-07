# 🏗️ Architecture

## 🧱 Stack

| Layer | Choice | Notes |
|---|---|---|
| Language | Python 3.14 | |
| Web framework | FastAPI | async, OpenAPI schema for free |
| Templates / UI | Jinja2 + [htmx](https://htmx.org) (vendored locally) | no SPA build, no CDN |
| Database | PostgreSQL 18 | via `asyncpg` + SQLAlchemy 2.0 (async) |
| Migrations | Alembic | async engine |
| Task queue / broker | Redis | broker + result backend for [Celery](https://docs.celeryq.dev/); also backs the login rate limiter |
| Background tasks | Celery + Celery Beat | one `worker` process, exactly one `beat` scheduler — three daily housekeeping jobs, no per-honeypot fan-out (see below) |
| Auth: passwords | [`argon2-cffi`](https://github.com/hynek/argon2-cffi) | argon2id hashing for local accounts |
| Auth: LDAP | [`ldap3`](https://github.com/cannatag/ldap3) | pure Python |
| Auth: OIDC | [`Authlib`](https://authlib.org/) | discovery, authorization-code flow, ID token validation |
| Auth: TOTP | [`pyotp`](https://github.com/pyauth/pyotp) + [`qrcode`](https://github.com/lincolnloop/python-qrcode) | RFC 6238 two-factor codes |
| Auth: WebAuthn/passkeys | [`webauthn`](https://github.com/duo-labs/py_webauthn) | registration/authentication ceremony verification |
| Reverse proxy (optional) | [Caddy](https://caddyproxy.com/) | automatic HTTPS, TLS 1.3 only, HTTP/3 |
| Packaging / lockfile | [`uv`](https://docs.astral.sh/uv/) | `uv.lock` is committed |
| Containers | Docker (multi-stage build) + Docker Compose | |

This entire stack — and most of the code implementing the auth row — is
carried over from [debcontrol](https://github.com/sparkycz1/debcontrol),
a sister project for the same team. See [CLAUDE.md](../CLAUDE.md) for what
was and wasn't reused.

```mermaid
flowchart LR
    Honeypot[["OpenCanary honeypot<br/>(a Raspberry Pi)"]]
    Browser["Browser<br/>htmx, no SPA build"]
    Web["web<br/>FastAPI"]
    DB[("PostgreSQL")]
    Redis[("Redis<br/>broker + result backend")]
    Worker["worker<br/>Celery"]
    Beat["beat<br/>Celery Beat scheduler"]

    Honeypot -->|"POST /api/ingest/&lt;id&gt;/events<br/>(bearer token)"| Web
    Browser <-->|HTTP| Web
    Web <--> DB
    Beat -->|"daily housekeeping"| Redis
    Redis --> Worker
    Worker <--> DB
```

**The data flow is inverted from debcontrol's**: debcontrol's `web`
process reaches out over SSH to managed machines. HoneyHive never reaches
into a honeypot at all — a honeypot's own forwarder pushes events in (see
[Honeypot Onboarding](Honeypot-Onboarding.md)). There is no SSH client
dependency in this codebase.

## 📂 Project structure

```
app/
  audit.py      the single audit-log write path (hash chaining, verification) — from debcontrol, unchanged
  auth/         login (local/LDAP/OIDC), sessions, TOTP, WebAuthn, per-user API tokens,
                company scoping (app/auth/scope.py) — see "Authentication & RBAC" below
  core/         config (pydantic-settings), logging, encryption, CSRF, editable app settings
  db/           SQLAlchemy models + async session
  schemas/      Pydantic schemas for forms
  services/     logic shared between routes (e.g. honeypot online/offline status)
  tasks/        Celery app (beat schedule, fork-safety hook) + the three daily job bodies
  web/          FastAPI routers, Jinja2 templates, static files
alembic/        DB migrations
wiki/           this documentation
```

## Authentication & RBAC

Login/session/TOTP/WebAuthn/LDAP/OIDC/rate-limiting/API-token machinery is
**copied from debcontrol nearly unchanged** — see that project's
`wiki/Architecture.md` for the exhaustive version of all of this (session
rows vs. signed cookies, brute-force lockout, per-IP rate limiting, TOTP
recovery codes, the WebAuthn ceremony, OIDC's own Starlette session, the
bootstrapping script). What's genuinely different is the authorization
model layered on top:

### No accounts are ever auto-created

Same as debcontrol: every `User` row is created inside HoneyHive first
(`scripts/create_admin.py` for the very first superadmin, the Users page
after that) — never by LDAP or OIDC. `auth_provider` only decides *how* an
existing account proves who it is.

### RBAC: company + access level, not roles

An admin does **not** define custom roles here. Every user is either:

- **A superadmin** (`User.is_superadmin = True`) — `company_id` and
  `access_level` are both `NULL`. Sees and manages everything, every
  company.
- **A company user** — `company_id` (required) points at exactly one
  `Company`; `access_level` is `READ` or `READ_WRITE`. `READ_WRITE` always
  implies everything `READ` grants; there is no third tier, and no way to
  grant access to more than one company short of being a superadmin.

Enforced at two independent layers, same separation of concerns debcontrol
used for permissions vs. machine-group scoping:

- **`app.auth.dependencies.require_write`** — is this user allowed to
  write *at all* (superadmin, or `READ_WRITE` on their own company)? Gates
  a route the way debcontrol's `require_permission(Permission.X)` did.
- **`app.auth.scope.ensure_company_access(user, company_id, write=...)`**
  / **`visible_company_id(user)`** — *which* company's data may this user
  touch? A superadmin passes for every company id; anyone else only for
  their own. **Out-of-scope reads 404, never 403** — a 403 would itself
  confirm the company/honeypot exists, which a user outside it shouldn't
  learn for free (same reasoning debcontrol's machine-group scoping
  documents).

There is no per-honeypot grant, no multi-company non-superadmin user, and
no custom-role editor — see `app/db/models/user.py`'s module docstring for
why this is deliberately much flatter than debcontrol's `Role`/
`Permission` matrix, and [Home.md](Home.md)'s open questions for what's
still unsettled about who's allowed to do what.

### Sessions, TOTP, WebAuthn, API tokens, OIDC, rate limiting

All unchanged in mechanism from debcontrol — `UserSession` rows (not
signed cookies), the same `SESSION_IDLE_TIMEOUT`/`SESSION_ABSOLUTE_MAX`,
self-service TOTP enrollment with recovery codes, WebAuthn/passkey
registration, per-user API tokens (prefixed `hhpat_` here, not `dcpat_`)
that authorize whatever the owning user's company + access level currently
permit, and the same per-IP login rate limiter. One deliberate
simplification: **there is no per-role mandatory TOTP enforcement** (no
`Role.require_totp` — there are no roles). TOTP/passkeys are purely
self-service today; a future "require 2FA for every user" toggle would
need to live on `AppSettings` instead, checked in
`app.auth.middleware`.

## 🍯 Honeypot data model

- **`Company`** — a tenant. One row per customer.
- **`Honeypot`** — one deployed OpenCanary instance (one Raspberry Pi),
  belonging to exactly one `Company`. Identity + last-seen bookkeeping
  only; HoneyHive never connects to it.
- **`HoneypotEvent`** — one row per OpenCanary alert, close to OpenCanary's
  own JSON shape (`raw`), with `event_type`/`occurred_at`/`src_ip`/
  `src_port`/`dst_port` promoted to real columns for the common
  list/filter/dashboard queries. Denormalizes `company_id` onto the event
  itself so every scoped query avoids a join through `Honeypot`.
- **`CompanySnapshot`** — one row per company per day, written by a daily
  Celery Beat job, backing the Dashboard's trend sparkline — mirrors
  debcontrol's `FleetSnapshot` one-to-one.

### How events actually arrive

OpenCanary itself has no built-in "POST to a URL" output — it only writes
to a local log/its own handlers. `POST
/api/ingest/{honeypot_id}/events` (`app/web/routes/ingest.py`) is what a
small forwarder on the Pi calls, authenticated with either the shared
`INGEST_TOKEN` (bootstrap, same shape as debcontrol's `INFORM_TOKEN`) or a
per-honeypot token (`Honeypot.ingest_token_hash` — model exists, no UI to
generate one yet). See [Honeypot Onboarding](Honeypot-Onboarding.md).

"Online"/"offline" (`app/services/honeypot_status.py`) is purely derived
from `Honeypot.last_seen_at` vs. `HONEYPOT_OFFLINE_AFTER_SECONDS` — no
separate reachability check exists (there's nothing to reach).

## 🔒 Security model

CSRF, CSP (strict, no inline scripts/styles, no CDN — htmx and Swagger UI
vendored locally), security headers, secrets-at-rest encryption
(`ENCRYPTION_KEY`, Fernet — used for LDAP/OIDC secrets and, once built,
per-honeypot ingest tokens), and the hash-chained audit log are all
unchanged from debcontrol. See that project's `wiki/Architecture.md`
"Security model" section for the exhaustive version.

**Deliberately out of scope** (unlike debcontrol): no SSH access to
anything, no remote command execution, no AI assistant, no user-definable
roles.
