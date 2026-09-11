# CLAUDE.md

Guidance for Claude Code when working in this repo.

## What this is

Honeypot Shelf: FastAPI + htmx, **manages and monitors a fleet of
[OpenCanary](https://github.com/thinkst/opencanary) honeypots** (Raspberry
Pis at customer sites) across **multiple companies**, with per-company
RBAC. Server-rendered Jinja2 + htmx, no SPA. Python 3.14, SQLAlchemy 2.0
async + PostgreSQL, Celery + Redis, Docker Compose only.

**Derived from a sister project, [debcontrol](https://github.com/sparkycz1/debcontrol)**
(Debian fleet management, same team) — reused near-verbatim: the stack,
reverse-proxy setup, project layout, the *entire* auth system (local/LDAP/
OIDC, sessions, TOTP, WebAuthn/passkeys, API tokens, audit log, CSRF/CSP/
headers), and the **entire SSH management layer** (`app/ssh/`, host-key
pinning, the browser terminal, facts/packages/services/monitoring/update
sweeps, power actions, Scheduling, the REST API) — a `Honeypot` is managed
exactly like debcontrol's `Machine`. **Not** reused: debcontrol's
`Role`/`Permission` matrix (see RBAC below), its machine-group scoping
(replaced by `Company` scoping), and its AI assistant. When something
isn't explained here, debcontrol's repo/wiki is probably the reference
this was ported from.

**Genuinely new here**: OpenCanary event ingestion — an SSH poll of each
honeypot's own log, no forwarder/push endpoint (`app/db/models/
honeypot_event.py`, `app.services.honeypot_events`) — and the
company-scoped Dashboard on top of it — see
[wiki/Architecture.md](wiki/Architecture.md).

## RBAC: the one thing genuinely different from debcontrol

**No roles, no groups — but not single-company either.** Every user
either:

- is a **superadmin** (`User.is_superadmin`) — sees/manages every company,
  every honeypot, Users, Companies, Settings, the Audit log; no
  memberships at all; or
- holds zero or more `CompanyMembership` rows
  (`app/db/models/company_membership.py`), each naming one `Company` and
  one **`AccessLevel`** (`READ`/`READ_WRITE`), independent per company —
  the same person can be `READ_WRITE` at one company and `READ`-only at
  another. `READ_WRITE` on a company covers everything for *that*
  company — no separate "terminal permission" the way debcontrol's
  `action.terminal` was its own grant.

**`Honeypot` is many-to-many with `Company` too** (`honeypot_companies`,
a plain link table) — a honeypot can belong to any number of companies,
including zero (superadmin-visible only). A company's own page can
*attach* an already-existing honeypot/grant an already-existing user
access, additively, alongside creating a brand-new one — see
[`app/web/routes/companies.py`](app/web/routes/companies.py)'s
`attach_existing_honeypot`/`attach_existing_user` (and their `detach_*`
counterparts). Deleting a `Company` only ever removes those links now,
never the honeypot or user account itself.

See [`app/db/models/user.py`](app/db/models/user.py)'s docstring for the
full reasoning, and [`app/auth/scope.py`](app/auth/scope.py) for
enforcement (`require_write` = "can write at all, on any company",
`ensure_company_access`/`visible_company_ids`/`has_company_access`/
`can_write_company` = "which company/companies"). **Out-of-scope reads
404, never 403** — a 403 would itself leak that the company/honeypot
exists. Companies, Users, Settings, and the Audit log are
**superadmin-only** end to end — see [wiki/Home.md](wiki/Home.md).

## Commands

```bash
uv sync                          # install deps into .venv (needed for tests/lint/mypy)
uv run pytest                    # full suite — no real Postgres/Redis/Celery broker touched
uv run pytest tests/test_x.py    # one file
uv run ruff check .              # lint
uv run mypy app alembic tests    # type check (strict for app/ and alembic/)
uv run alembic revision --autogenerate -m "..."   # after changing a model — READ the generated file
uv run alembic upgrade head
uv run alembic heads             # must show exactly one head before committing a migration
```

No supported way to run the app outside Docker: `docker compose up -d
--build`. See [wiki/Installation.md](wiki/Installation.md).

**Before committing**, run the gate: `ruff check .`, `mypy app alembic
tests`, `pytest`, `alembic heads` (single head) — all clean. CI
(`.github/workflows/ci.yml`) runs the exact same gate plus `pip-audit` on
every push/PR.

**Every round of changes** bumps `APP_VERSION` (`app/core/version.py`)
**and** `version` in `pyproject.toml` together (patch for a fix, minor for
a feature, major only if explicitly asked) — then `uv lock` and commit
`uv.lock` in the same commit.

## Current state

Everything in [wiki/Home.md](wiki/Home.md)'s highlights table is real and
verified end-to-end against real Postgres, not just "imports without
error": the full domain model and auth stack, company scoping, event
ingestion, the Dashboard, full Honeypot CRUD (terminal, facts/packages/
services, updates with rollback, power, the read-only-root + OpenCanary
module-editor Config tab), Company CRUD, Scheduling, the REST API,
Initialize (provisions a bare Pi into a working honeypot over SSH — see
[wiki/Honeypot-Initialize.md](wiki/Honeypot-Initialize.md)), VPN
connectivity (NetBird/WireGuard, see
[wiki/Architecture.md](wiki/Architecture.md)), complete English+Czech
i18n, and CI. Check `uv run pytest` for the current test count rather
than trusting a number in prose. Settled product decisions (only a
superadmin creates companies/honeypots/users, no alerting in v1, audit
log/Settings superadmin-only, ...) live in
[wiki/Home.md](wiki/Home.md) — don't relitigate those without asking.

Periodically synced against upstream debcontrol for fixes that apply to
both (proxy-header support, FIPS-aligned crypto defaults, backup/restore
scripts, ...) — check that project's release history when in doubt why
something here works a certain way.

### Lessons worth remembering (not obvious from the code alone)

- **A "the mechanical port was verified end-to-end" claim covers what was
  *tested* at the time, not a guarantee nothing was missed.** Real bugs
  have slipped through this exact way more than once (a debcontrol
  leftover CSS class, a whole client-side asset never actually copied
  over, a Celery beat schedule silently missing 11 of its 14 entries since
  the first commit) — re-check a claim like this against the files on
  disk before trusting it, don't just trust the prose.
- **Any SSH-provisioning code (Initialize, onboarding, key pushes) must
  stay strictly additive.** `grep -qxF`-check before appending to
  `authorized_keys`/sudoers — never remove or overwrite something already
  there by hand. Use `getent passwd` for a home directory, never `~` —
  scripts often run wrapped under one `sudo`, where `~` resolves to the
  escalated account's home, not the target's.
  See [wiki/Architecture.md#superadmin-personal-ssh-keys](wiki/Architecture.md#superadmin-personal-ssh-keys).
- **A `POST` used as a testing/debugging tool without a pty (e.g. `gpg
  --dearmor`) can silently prompt on `/dev/tty` and fail with a cryptic
  error instead of just doing the thing** — prefer `--batch --yes`-style
  non-interactive flags over trusting a tool won't ever prompt.
- **`READ` vs `READ_WRITE` gating is per-route, not per-page** — a page
  can look gated in the nav while an underlying route has no
  `require_write` at all. When adding a tab/page, check the route itself,
  not just whether a nav link is hidden.
- **FIPS-aligned crypto is a deliberate, ongoing constraint** (AES-256-GCM
  at rest, SHA-256 signed tickets, a restricted SSH KEX/cipher/MAC set) —
  see [wiki/Architecture.md#fips-alignment](wiki/Architecture.md#fips-alignment).
  The one intentional exception is Argon2id for password hashing (not
  FIPS-approved, kept anyway — meaningfully more GPU/ASIC-resistant than
  PBKDF2). Don't "fix" that without asking.

## Architecture, beyond what one file shows

- **Two independent "is this honeypot alive" signals coexist — don't
  conflate them.** `Honeypot.is_reachable`/`last_ping_at` is the
  SSH-management-plane check (a periodic unauthenticated TCP connect).
  `Honeypot.last_seen_at`/`last_seen_ip` is when it last pushed an
  OpenCanary *event* (see `app.services.honeypot_status.is_online`/
  `status_of`) — a honeypot can be SSH-reachable with OpenCanary down, or
  vice versa. The Dashboard's "online" count uses the event signal; the
  SSH-facts-derived counts (`needs_updates`, etc.) use the other.
  `CompanySnapshot` (the Dashboard trend chart's daily rollup) stores
  both.
- **Every timestamp comparison in Python (not SQL) must normalize
  naive-vs-aware first** — SQLite (what tests run against) drops tzinfo on
  round-trip; real Postgres columns never do. Reuse
  `app.services.honeypot_status.as_aware_utc`/`is_online` (or the
  identical pattern in `User.is_locked_out`/`app.audit._normalized_timestamp`)
  for any new Python-side datetime comparison — a bare `a >= b` that works
  against SQLite in a hand-run test can still `TypeError` against real
  Postgres, and `pytest` won't catch it unless a test actually exercises
  it (see `tests/test_dashboard.py`).
- **Every `ScheduledTask` belongs to exactly one company**
  (`owner_company_id`) — `ALL_HONEYPOTS` means "every honeypot in this
  schedule's own company," not the whole fleet. `app.scheduling.targets.
  task_within_scope` (read, `write=False`) vs. `target_within_scope(...,
  write=True)` (create/edit) are genuinely distinct — mixing them up
  silently makes schedules invisible to `READ`-only users.
- **The async/sync seam** and **fork safety** (Celery workers rebuild the
  DB engine after forking) are copied verbatim from debcontrol — see
  [`app/tasks/celery_app.py`](app/tasks/celery_app.py)'s docstring.
- **CSP is strict — no inline scripts or styles, no CDN.** htmx, Swagger
  UI, and OS-badge SVGs are vendored under `app/web/static/`. New CSS
  reads colors through `--color-*` custom properties in `style.css`.
- **Audit logging** (`app.audit.log_event`) is hash-chained, called once
  per human-initiated mutation, action codes `lowercase.dot.separated`
  (e.g. `honeypot.create`, `user.access_level.update`).
- **UI strings go through `t()`**, backed by `app/i18n/` (English + Czech)
  — coverage is complete, including tab-navigation labels built in Python.
  Extend it by adding the key to **every** `app/i18n/locales/*.json` file,
  not just one. **A Jinja macro that calls `t(request, ...)` — directly,
  or via `{% include %}` inside its own body — needs `request` as an
  explicit parameter**: macros don't inherit the calling template's
  context by default, so omitting it fails at render time with
  `UndefinedError: 'request' is undefined` (not a syntax error — a plain
  parse check won't catch it).

## Checklist for every change

1. **Company scoping.** Any new read/write path touching a honeypot,
   event, company, or scheduled task must go through
   `app.auth.scope`/`app.scheduling.targets` — never trust a
   `company_id`/`honeypot_id` from the client without checking it against
   the current user, and never reuse a `write=True` scope check for a
   read-only listing.
2. **Wiki parity.** Update the relevant `wiki/*.md` page(s) in the same
   change — `wiki/Home.md`'s highlights table, `wiki/Architecture.md` for
   *why*/how it works.
3. **i18n parity.** Any new/changed user-facing string goes through
   `t(request, "...")` and gets a key in `app/i18n/locales/en.json` *and*
   `cs.json`.
4. **Upgrade safety.** Real Alembic migration, deployed with real data —
   a new column must be nullable or have a safe server default, and a
   renamed/removed route or config key must not break someone silently.
5. **Security.** CSRF on every mutating web route, `require_write` +
   company scoping on both web and API sides, secrets only ever
   `encrypt_secret`/stored hashed, no new inline script/style (CSP).
6. **Current, not legacy, tech.** Match what's already here (Python 3.14,
   SQLAlchemy 2.0 async, Pydantic v2, FastAPI, htmx 2.x).
7. **Test it.** Add/extend a test in `tests/` — the suite runs against
   in-memory SQLite (see `tests/conftest.py`), fast, no real Postgres/
   Redis needed. Run the whole gate before considering the change done.
8. **Tag and release.** Once `APP_VERSION`/`pyproject.toml` are bumped and
   the change is committed and pushed, tag it (`git tag vX.Y.Z` + `git
   push --tags`) and cut a GitHub release (`gh release create vX.Y.Z`).

None of this means doing every possible thing for every tiny change — it
means actually checking each of these against what you just did, and
either handling it or explicitly deciding (and saying) it doesn't apply
this time.
