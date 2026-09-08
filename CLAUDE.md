# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

HoneyHive: a FastAPI + htmx web app for **managing and monitoring a fleet
of [OpenCanary](https://github.com/thinkst/opencanary) honeypots**
(Raspberry Pis deployed at customer sites) across **multiple companies**,
with per-company RBAC. Server-rendered Jinja2 + htmx, not a SPA. Python
3.14, SQLAlchemy 2.0 async + PostgreSQL, Celery + Redis for background
work, deployed via Docker Compose only.

**This project is derived from a sister project, [debcontrol](https://github.com/sparkycz1/debcontrol)**
(a Debian fleet-management app for the same team) — reused near-verbatim:
the tech stack, reverse-proxy setup, project layout, the *entire* auth
system (local/LDAP/OIDC login, sessions, TOTP, WebAuthn/passkeys, per-user
API tokens, audit log, CSRF/CSP/security headers), and the **entire SSH
management layer** (`app/ssh/`, host-key pinning, the interactive browser
terminal, facts/packages/services/monitoring/update sweeps, power actions,
Scheduling, the REST API) — a `Honeypot` is managed exactly like
debcontrol's `Machine`. Deliberately **not** reused: debcontrol's
`Role`/`Permission` matrix (replaced by a much flatter model — see below),
its machine-group scoping (replaced by `Company` scoping), and the AI
assistant. When in doubt about *why* something is built a certain way and
it isn't explained below, the debcontrol repo/wiki is probably the
reference this copied from.

**This project also adds its own thing debcontrol has no equivalent of**:
OpenCanary event ingestion (`POST /api/ingest/{honeypot_id}/events`,
`app/db/models/honeypot_event.py`) and the company-scoped Dashboard built
on top of it — see "Architecture" below.

## RBAC: the one thing that's genuinely different from debcontrol

**No roles, no groups.** Every user either:

- is a **superadmin** (`User.is_superadmin`) — sees and manages every
  company, every honeypot, Users, Companies, Settings, and the Audit log;
  or
- belongs to **exactly one `Company`** (`User.company_id`, required) with
  exactly one **`AccessLevel`** (`User.access_level`): `READ` or
  `READ_WRITE`. Nothing in between, no per-honeypot grants. `READ_WRITE`
  covers everything a company user can do — terminal, facts, updates,
  power, scheduling — there is no separate "terminal permission" the way
  debcontrol's `action.terminal` was its own grant.

See [`app/db/models/user.py`](app/db/models/user.py)'s module docstring for
the full reasoning and the DB `CheckConstraint` enforcing this shape, and
[`app/auth/scope.py`](app/auth/scope.py) for how a request gets checked
against it (`app.auth.dependencies.require_write` for "can this user write
at all", `app.auth.scope.ensure_company_access`/`visible_company_id`/
`has_company_access` for "which company"). **Out-of-scope reads 404, never
403** — same reasoning debcontrol's machine-group scoping used (a 403
would itself leak that the company/honeypot exists). Companies, Users,
Settings, and the Audit log are **superadmin-only** end to end (web and
REST API) — see [wiki/Home.md](wiki/Home.md) for that product decision.

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

There is no supported way to run the app itself outside Docker:
`docker compose up -d --build`. See [wiki/Installation.md](wiki/Installation.md).

**Before committing**, run the same gate debcontrol's history consistently
uses: `ruff check .`, `mypy app alembic tests`, `pytest`, `alembic heads`
(single head) — all clean. (At the time of the last verified pass: 101/101
`pytest`, `ruff check .` and `mypy app alembic tests` both fully clean —
see "Current state" below for what that cleanup pass found and fixed.)

**Every round of changes** bumps `APP_VERSION` in `app/core/version.py`
**and** `version` in `pyproject.toml` together (patch for a small fix,
minor for a feature/infrastructure change, major only if explicitly
asked) — then run `uv lock` and commit the updated `uv.lock` in the same
commit.

## Current state of this repo

Real and verified end-to-end (built, migrated against real Postgres,
exercised through the actual HTTP stack — not just "imports without
error"): the full domain model, the entire auth stack (including
two-step, GitHub/Google-style login — username first, then a passkey or
password), company scoping, event ingestion, the Dashboard, full Honeypot
CRUD (create/edit/delete, host-key discovery/trust, facts/packages/
services refresh, the SSH terminal, the Logs tab — journal, a clickable
`ls`-based file browser, and a one-click shortcut to OpenCanary's own
log — system updates with live output, power actions, and a Honeypot
Status tab toggling the read-only root filesystem Raspberry Pi OS's own
overlay support provides, protecting the SD card from write wear — see
`app.ssh.readonly`), Company CRUD and bulk actions ("All honeypots"),
Scheduling (cron-driven actions, company-scoped via
`ScheduledTask.owner_company_id`), the REST API mirroring all of the above
(`/api/v1/...`), Users/Settings (LDAP/OIDC/syslog-forwarding config, SSH
key rotation, retention policies), Initialize (`app.ssh.initialize` +
`app.web.routes.initialize_ws`, `/initialize` — provisions a brand new
Raspberry Pi OS 13 device into a working OpenCanary honeypot over SSH,
before it's ever added to HoneyHive: packages, the OpenCanary venv/
service, locale/timezone, hostname, NetBird, generating OpenCanary's own
config, and the portscan/Samba modules' host-side prep, all streamed live
to the browser over a WebSocket — see
[wiki/Honeypot-Initialize.md](wiki/Honeypot-Initialize.md)), and an
initial Alembic migration. A 101-test suite covers auth, company
scoping, ingest, the dashboard, honeypot/company/schedule CRUD, `pg_enum`,
i18n, config, Initialize's script builder, and the proxy-headers/
CSP-safety regression guards below.

Periodically synced against upstream debcontrol for fixes/features that
apply here too (see that project's own release history) — most recently
`X-Forwarded-Proto`/`-For` reverse-proxy support
(`app.core.proxy_headers`), the two-step login above, the honeypot list
folding tag search into its main search box, and a CSP-safety regression
test (`tests/test_no_inline_event_handlers.py`) that also caught two
HoneyHive-specific inline `onchange` handlers on the Users new/edit forms
(silently dead under this app's CSP — fixed via `data-toggle-hidden` +
`static/js/toggle-hidden.js`). Also caught and fixed during this pass: the
interactive SSH terminal's own client-side assets (`static/js/terminal.js`,
vendored xterm.js + its fit addon, `static/css/xterm.css`) had never
actually been copied over during the original port despite the terminal
page referencing them — the feature 404'd on every asset it needed. Take
this as a reminder that "the mechanical port was verified end-to-end"
claims from earlier in this file cover what was *tested* at the time, not
a guarantee nothing was missed — re-check a claim like this against the
actual files on disk before trusting it, the same way this bug was found.

**Known gaps, not yet done**: i18n coverage is still just the site
chrome plus the auth/footer/toolbar/Initialize strings touched so far
(most of the ported pages' strings are still plain English, same "not yet
translated" state debcontrol itself is in for many pages); no CI workflow
file exists (deliberately out of scope — this repo relies on the local
gate below instead). `ruff check .` and `mypy app alembic tests` are both
now fully clean (as of the Initialize change): the ~95 line-length
warnings left over from the mechanical port were wrapped by hand, and the
first-ever `mypy --strict` run surfaced 16 pre-existing errors — mostly
`X | None` used where a non-`None` type was expected (a pydantic schema
field left `Optional` because a route resolves it, not because it can
actually be `None` by the time it's used — fixed with a narrowing
`assert` plus a comment at each call site) — and one real bug:
`app/web/routes/honeypots.py`'s package-search endpoint called
`honeypots_visible_to()` as if it were an async DB query (`await
honeypots_visible_to(db, current_user)`) when it's actually a plain sync
function returning a `Select` to compose further, taking only `user` —
every search with a non-empty query raised a `TypeError`, uncaught by any
existing test. `tests/` needed a `tests/__init__.py` (resolves
`tests/conftest.py: Source file found twice under different module
names`) plus a `[[tool.mypy.overrides]]` disabling four separate
strict-mode flags for `tests.*` (only `disallow_untyped_defs` was
disabled before; incomplete annotations, untyped calls, and `Any`
returns — all normal in test fixtures — were still erroring). None of
this blocks using the app.

Settled product decisions (see [wiki/Home.md](wiki/Home.md) for the full
list): only a superadmin creates companies/honeypots/users — a company's
own `READ_WRITE` user manages honeypots *within* their own company (via
`/honeypots`, already scoped) but never creates a company or another
user; the audit log and Settings stay superadmin-only; no alerting in v1
(dashboard/overview only); `READ_WRITE` includes the SSH terminal and host
config, not just HoneyHive-side metadata.

## Architecture, beyond what one file shows

- **Two independent "is this honeypot alive" signals coexist — don't
  conflate them.** `Honeypot.is_reachable`/`last_ping_at` is the
  SSH-management-plane check (identical to debcontrol's `Machine`, a
  periodic unauthenticated TCP connect). `Honeypot.last_seen_at`/
  `last_seen_ip` is when this honeypot last pushed an OpenCanary *event*
  to `POST /api/ingest/{id}/events` (see
  `app.services.honeypot_status.is_online`/`status_of`) — a honeypot can
  be SSH-reachable with OpenCanary itself down, or vice versa. The
  Dashboard's "online" count uses the event signal; the SSH-facts-derived
  counts (`needs_updates`, etc., `app.services.company_stats`) use the
  other. `CompanySnapshot` (the Dashboard trend chart's daily rollup)
  stores both.
- **Every timestamp comparison in Python (not SQL) must normalize
  naive-vs-aware first** — SQLite (what tests run against) drops tzinfo on
  round-trip; real Postgres columns (`DateTime(timezone=True)`, see
  `app.db.base.Base.type_annotation_map`) never do. This bit the Dashboard
  once already (fixed via `app.services.honeypot_status.as_aware_utc`/
  `is_online`) — reuse that helper (or the identical pattern in
  `User.is_locked_out`/`app.audit._normalized_timestamp`) for any new
  Python-side datetime comparison; a bare `a >= b` that works against
  SQLite in a hand-run test can still `TypeError` there and won't be
  caught by `pytest` unless a test actually exercises it (see
  `tests/test_dashboard.py`).
- **Every `ScheduledTask` belongs to exactly one company**
  (`owner_company_id`) — unlike debcontrol, where "All machines" meant the
  whole (single-tenant) fleet, `ALL_HONEYPOTS` here means "every honeypot
  in this schedule's own company." `app.scheduling.targets.
  task_within_scope` (read, `write=False`) vs. `target_within_scope(...,
  write=True)` (create/edit) — mixing these up silently makes schedules
  invisible to `READ`-only users, which is exactly the bug the current
  code was fixed for; if you touch scheduling scoping, keep read and write
  paths distinct.
- **The async/sync seam** and **fork safety** (Celery workers rebuild the
  DB engine after forking) are copied verbatim from debcontrol — see
  [`app/tasks/celery_app.py`](app/tasks/celery_app.py)'s module docstring.
- **CSP is strict — no inline scripts or styles, no CDN.** Same as
  debcontrol: htmx, Swagger UI, and the OS-badge SVGs are vendored under
  `app/web/static/`. New CSS reads colors through `--color-*` custom
  properties in `style.css`.
- **Audit logging** (`app.audit.log_event`) is unchanged from debcontrol —
  hash-chained, called once per human-initiated mutation, action codes
  `lowercase.dot.separated` (e.g. `honeypot.create`,
  `user.access_level.update`, `company.honeypot.add`).
- **UI strings go through `t()`**, backed by `app/i18n/` (English + Czech
  today) — same mechanism as debcontrol, copied as-is. Coverage today is
  just the site chrome; extend it the same way debcontrol's wiki
  documents (add the key to **every** `app/i18n/locales/*.json` file, not
  just one).

## Checklist for every change

1. **Company scoping.** Any new read/write path touching a honeypot,
   event, company, or scheduled task must go through
   `app.auth.scope`/`app.scheduling.targets` — never trust a
   `company_id`/`honeypot_id` from the client without checking it against
   the current user first, and never reuse a `write=True` scope check for
   a read-only listing (see "Architecture" above).
2. **Wiki parity.** Update the relevant `wiki/*.md` page(s) in the same
   change — `wiki/Home.md`'s feature table, `wiki/Architecture.md` for
   *why*/how it works.
3. **i18n parity.** Any new or changed user-facing string goes through
   `t(request, "...")` and gets a key in `app/i18n/locales/en.json` *and*
   `cs.json`.
4. **Upgrade safety.** This app has a real Alembic migration and is meant
   to be deployed with real data — a new column must be nullable or have a
   safe server default, and a renamed/removed route or config key must not
   break someone silently.
5. **Security.** CSRF on every mutating web route, `require_write` +
   company scoping on both the web and API side, secrets only ever
   `encrypt_secret`/stored hashed, no new inline script/style (CSP).
6. **Current, not legacy, tech.** Match what's already here (Python 3.14,
   SQLAlchemy 2.0 async, Pydantic v2, FastAPI, htmx 2.x).
7. **Test it.** Add/extend a test in `tests/` for the change — the suite
   runs against in-memory SQLite (see `tests/conftest.py`), so it's fast
   and needs no real Postgres/Redis. Run the whole gate (`ruff check .`,
   `mypy app alembic tests`, `pytest`, `alembic heads`) before considering
   the change done.
8. **Tag and release.** Once `APP_VERSION`/`pyproject.toml` are bumped and
   the change is committed and pushed, tag it (`git tag vX.Y.Z` + `git push
   --tags`) and cut a GitHub release (`gh release create vX.Y.Z`).

None of this means doing every possible thing for every tiny change — it
means actually checking each of these against what you just did, and
either handling it or explicitly deciding (and saying) it doesn't apply
this time.
