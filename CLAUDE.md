# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

HoneyHive: a FastAPI + htmx web app for **monitoring a fleet of
[OpenCanary](https://github.com/thinkst/opencanary) honeypots** (Raspberry
Pis deployed at customer sites) across **multiple companies**, with
per-company RBAC. Server-rendered Jinja2 + htmx, not a SPA. Python 3.14,
SQLAlchemy 2.0 async + PostgreSQL, Celery + Redis for daily housekeeping
jobs, deployed via Docker Compose only.

**This project is derived from a sister project, [debcontrol](https://github.com/sparkycz1/debcontrol)**
(a Debian fleet-management app for the same team) — deliberately reused:
the tech stack, reverse-proxy setup, project layout, and the *entire* auth
system (local/LDAP/OIDC login, sessions, TOTP, WebAuthn/passkeys, per-user
API tokens, audit log, CSRF/CSP/security headers). Deliberately **not**
reused: debcontrol's `Role`/`Permission` matrix (replaced by a much flatter
model — see below), its machine-group scoping (replaced by `Company`
scoping), scheduling, and the AI assistant.

**SSH-based remote management IS in scope, not yet built.** `READ_WRITE`
on a `Honeypot` is meant to include an interactive terminal and host
configuration/IP changes — i.e. this project needs debcontrol's SSH client
layer (`app/ssh/`, `SSHIdentity`, host-key pinning, `terminal_ws.py`)
ported in and scoped per company, not just the monitoring/ingest half this
scaffold currently has. See
[wiki/Home.md](wiki/Home.md#ssh-based-remote-management--the-next-major-piece-to-build)
before starting that work. When in doubt about *why* something is built a
certain way and it isn't explained below, the debcontrol repo/wiki is
probably the reference this copied from.

## RBAC: the one thing that's genuinely different from debcontrol

**No roles, no groups.** Every user either:

- is a **superadmin** (`User.is_superadmin`) — sees and manages every
  company, every honeypot, Users, Companies, Settings, and the Audit log;
  or
- belongs to **exactly one `Company`** (`User.company_id`, required) with
  exactly one **`AccessLevel`** (`User.access_level`): `READ` or
  `READ_WRITE`. Nothing in between, no per-honeypot grants.

See [`app/db/models/user.py`](app/db/models/user.py)'s module docstring for
the full reasoning and the DB `CheckConstraint` enforcing this shape, and
[`app/auth/scope.py`](app/auth/scope.py) for how a request gets checked
against it (`app.auth.dependencies.require_write` for "can this user write
at all", `app.auth.scope.ensure_company_access`/`visible_company_id` for
"which company"). **Out-of-scope reads 404, never 403** — same reasoning
debcontrol's machine-group scoping used (a 403 would itself leak that the
company/honeypot exists).

## Commands

```bash
uv sync                          # install deps into .venv (needed for tests/lint/mypy)
uv run pytest                    # full suite — no real Postgres/Redis/Celery broker touched
uv run pytest tests/test_x.py    # one file
uv run ruff check .               # lint
uv run mypy app alembic tests    # type check (strict for app/ and alembic/)
uv run alembic revision --autogenerate -m "..."   # after changing a model — READ the generated file
uv run alembic upgrade head
uv run alembic heads             # must show exactly one head before committing a migration
```

There is no supported way to run the app itself outside Docker:
`docker compose up -d --build`. See [wiki/Installation.md](wiki/Installation.md).

**Before committing**, run the same gate debcontrol's history consistently
uses: `ruff check .`, `mypy app alembic tests`, `pytest`, `alembic heads`
(single head) — all clean.

**Every round of changes** bumps `APP_VERSION` in `app/core/version.py`
**and** `version` in `pyproject.toml` together (patch for a small fix,
minor for a feature/infrastructure change, major only if explicitly
asked) — then run `uv lock` and commit the updated `uv.lock` in the same
commit.

## Current state of this repo — read before assuming a page exists

This repo is a **freshly scaffolded start**, not a feature-complete app.
Done and real: the domain models (`Company`, `User`, `Honeypot`,
`HoneypotEvent`, `CompanySnapshot`), the full auth stack (login/logout,
sessions, TOTP, WebAuthn, LDAP, OIDC, API tokens, rate limiting, CSRF,
audit log), company scoping, the event-ingest endpoint
(`POST /api/ingest/{honeypot_id}/events`), the Dashboard, and read-only
Honeypots/Companies/Users/Audit/Settings pages. **Not yet built**: create/
edit/delete forms for honeypots, companies, and users; the SSH-based
terminal/host-config management `READ_WRITE` is meant to grant (see
above — this is the single biggest missing piece, not a minor gap); the
REST API (`/api/v1/...`); an initial Alembic migration (no DB has been
migrated against these models yet — generate one with `alembic revision
--autogenerate` against a real Postgres before first deploy); a test
suite; i18n coverage beyond the site chrome.

Settled product decisions (see [wiki/Home.md](wiki/Home.md) for the full
list): only a superadmin creates companies/honeypots/users — a company's
own `READ_WRITE` user never does; the audit log and Settings stay
superadmin-only; no alerting in v1 (dashboard/overview only).

## Architecture, beyond what one file shows

- **Monitoring today is one-way and agentless; remote management (SSH) is
  planned but not built** (see above). Right now HoneyHive never SSHes
  into a honeypot and has no live agent polling it — a
  honeypot's own forwarder (see
  [wiki/Honeypot-Onboarding.md](wiki/Honeypot-Onboarding.md)) pushes
  OpenCanary's JSON events to `POST /api/ingest/{honeypot_id}/events`;
  HoneyHive only ever reads that stream. "Online"/"offline" status
  (`app/services/honeypot_status.py`) is purely derived from how recently
  an event arrived, compared against `HONEYPOT_OFFLINE_AFTER_SECONDS` —
  there's no separate reachability check.
- **The async/sync seam** and **fork safety** (Celery workers rebuild the
  DB engine after forking) are copied verbatim from debcontrol — see
  [`app/tasks/celery_app.py`](app/tasks/celery_app.py)'s module docstring.
  Unlike debcontrol, there's no per-machine fan-out needing this: Celery
  here only runs three daily housekeeping jobs
  ([`app/tasks/jobs.py`](app/tasks/jobs.py)) — purge old events, purge old
  audit log entries, and roll up yesterday's per-company counts into
  `CompanySnapshot` for the Dashboard trend chart. Event ingestion itself
  is a plain synchronous DB write on the web process, not queued.
- **CSP is strict — no inline scripts or styles, no CDN.** Same as
  debcontrol: htmx and Swagger UI are vendored under `app/web/static/`.
  New CSS reads colors through `--color-*` custom properties in
  `style.css`.
- **Audit logging** (`app.audit.log_event`) is unchanged from debcontrol —
  hash-chained, called once per human-initiated mutation, action codes
  `lowercase.dot.separated` (e.g. `honeypot.create`,
  `user.access_level.update`).
- **Dashboard scoping**: every user sees the *sum* across their own
  company's honeypots/events (per the product brief — "every user sees
  the total across all their honeypots"); a superadmin additionally sees a
  per-company breakdown. See
  [`app/web/routes/dashboard.py`](app/web/routes/dashboard.py).
- **UI strings go through `t()`**, backed by `app/i18n/` (English + Czech
  today) — same mechanism as debcontrol, copied as-is. Coverage today is
  just the site chrome; extend it the same way debcontrol's wiki
  documents (add the key to **every** `app/i18n/locales/*.json` file, not
  just one).

## Checklist for every change

1. **Company scoping.** Any new read/write path touching a honeypot,
   event, or company must go through
   `app.auth.scope.ensure_company_access`/`visible_company_id` — never
   trust a `company_id`/`honeypot_id` from the client without checking it
   against the current user first.
2. **Wiki parity.** Update the relevant `wiki/*.md` page(s) in the same
   change — `wiki/Home.md`'s feature table, `wiki/Architecture.md` for
   *why*/how it works.
3. **i18n parity.** Any new or changed user-facing string goes through
   `t(request, "...")` and gets a key in `app/i18n/locales/en.json` *and*
   `cs.json`.
4. **Upgrade safety.** Once this app has a real deployment with data, a
   new column must be nullable or have a safe server default, and a
   renamed/removed route or config key must not break someone silently.
5. **Security.** CSRF on every mutating web route, `require_write` +
   company scoping on both the web and (once built) API side, secrets only
   ever `encrypt_secret`/stored hashed, no new inline script/style (CSP).
6. **Current, not legacy, tech.** Match what's already here (Python 3.14,
   SQLAlchemy 2.0 async, Pydantic v2, FastAPI, htmx 2.x).
7. **Tag and release.** Once `APP_VERSION`/`pyproject.toml` are bumped and
   the change is committed and pushed, tag it (`git tag vX.Y.Z` + `git push
   --tags`) and cut a GitHub release (`gh release create vX.Y.Z`).

None of this means doing every possible thing for every tiny change — it
means actually checking each of these against what you just did, and
either handling it or explicitly deciding (and saying) it doesn't apply
this time.
