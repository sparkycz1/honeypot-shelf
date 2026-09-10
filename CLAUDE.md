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
(single head) — all clean. (At the time of the last verified pass: 120/120
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
Config tab: the read-only root filesystem toggle (Raspberry Pi OS's own
overlay support, protecting the SD card from write wear — see
`app.ssh.readonly`) plus a full category-by-category editor for every
OpenCanary module (`app.ssh.opencanary_config` — FTP/HTTP(S)/SSH/Telnet/
MySQL/MSSQL/MongoDB/Redis/RDP/VNC/SIP/SNMP/NTP/TFTP/Git/LLMNR/a generic
TCP banner listener/portscan/Samba, one dataclass-described module per
category driving both the form and the save-time merge, neither section
ever persisted in this app's own DB), Company CRUD and bulk actions
("All honeypots"),
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
initial Alembic migration. A 194-test suite (grown well past this
paragraph's own original count — check `uv run pytest` for the current
number rather than trusting a number in prose) covers auth, company
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

**i18n is now complete, English and Czech, across the whole app** — every
template's user-facing text goes through `t(request, "...")`, including
tab navigation labels that were previously hardcoded in Python
(`_honeypot_tabs`/`_company_tabs`/`settings._tabs`, now translated
functions rather than static lists). 710+ new keys were added in one pass
(app/i18n/locales/{en,cs}.json, now ~790 keys total). Two real bugs
surfaced along the way, both fixed: (1) `partials/_packages_summary.html`
and `_services_summary.html`'s `render(...)` macros called `t(request,
...)` inside an `{% include %}` without `request` ever being passed into
the macro — Jinja macros don't inherit the calling template's context by
default, so this crashed with `UndefinedError: 'request' is undefined`
the moment either macro was actually rendered (caught by
`tests/test_readonly.py`, not by the translating pass's own Jinja
syntax-only parse check); now `request` is an explicit first parameter,
threaded through every call site. (2) The same "macro needs `request`
passed explicitly" issue existed in `macros/charts.html`'s three chart
macros — fixed with an optional `request=none` parameter and an
English-literal fallback for the one caller (`honeypots/monitoring.html`)
that doesn't pass it. **Known gaps, not yet done**: no CI workflow file
exists (deliberately out of scope — this repo relies on the local gate
below instead). `ruff check .` and `mypy app alembic tests` are both
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

**VPN connectivity for HoneyHive itself** (Settings → VPN, `app.services.
netbird`/`wireguard`) — distinct from a honeypot's own, independent VPN
choice on the Initialize form — lets `web`/`worker` reach a honeypot
that's only addressable over NetBird or WireGuard (e.g. behind a NAT with
no forwarded SSH port), via an optional privileged `vpn` sidecar
container (`docker-compose.vpn.yml`) that `web`/`worker` share the
network namespace of (`network_mode: "service:vpn"`) rather than gaining
any elevated privilege themselves. The two providers are mutually
exclusive (`AppSettings.vpn_provider`, set automatically by whichever
`connect()` last succeeded) — WireGuard needed its own small
`app.services.vpn_control_server` (run inside the sidecar) since plain
`wireguard-tools`, unlike NetBird, has no daemon+CLI split of its own for
`web` to talk to. See [wiki/Architecture.md](wiki/Architecture.md)'s "VPN
connectivity: NetBird or WireGuard" section for the full design.

**The Honeypot Activity tab** (`app.ssh.canary_activity`,
`app.services.canary_activity_history`/`opencanary_logtypes`) reads
whatever's new in OpenCanary's own log over SSH every
`OPENCANARY_LOG_POLL_INTERVAL_SECONDS` (default 120, per-honeypot
overridable) — no forwarder setup needed on the honeypot side, unlike the
push-based ingest endpoint. Both paths write the same `HoneypotEvent`
table (`source` distinguishes them) — see
[wiki/Architecture.md](wiki/Architecture.md)'s "How events actually
arrive" section. Building this surfaced a serious pre-existing bug, fixed
in the same change: `app/tasks/celery_app.py`'s `beat_schedule` only ever
had 3 of the ~14 periodic entries it should have (no periodic
reachability/facts/packages/services/readiness/update-check/monitoring
sweep, no honeypot Scheduling ever firing on its own cron, no purge of
`HoneypotEvent`/monitoring-sample/update-run history) since this
project's first commit — and `app.scheduling.jobs` wasn't in Celery's
`include=[...]` list at all, so a standalone `worker`/`beat` process
never even registered `run_scheduled_task`, the task an operator's "Run
now" button enqueues. Invisible to `pytest` because
`tests/conftest.py` monkeypatches `Task.apply_async` itself for the whole
suite — see `tests/test_beat_schedule.py`, the regression guard added
alongside the fix, and `app.tasks.celery_app`'s own comments for the full
story. Confirmed fixed live: `docker compose logs beat` now shows
`Scheduler: Sending due task ...` for entries that never fired before,
and the worker's task list at startup includes every
`app.scheduling.jobs.*` task.

Since built on top of that: `GET /api/v1/events` (+ `/export`, CSV/JSON) —
`app/web/routes/api_v1_events.py` — a company-scoped REST API over
`HoneypotEvent`, and a per-honeypot `GET /honeypots/{id}/status/export`
(session-authenticated, same download-link pattern as the audit log's
export) for the Activity tab's own CSV/JSON button. Both existed only as
documentation before (`auth/account.html`'s API-tokens hint has referenced
`GET /api/v1/events` since that page was written) — a real, previously
undetected gap between what the app claimed and what it did. The
Dashboard also got a fleet-wide (or, company-scoped, that company's own)
"activity by alert type" section, reusing
`canary_activity_history.build_activity_history` across every honeypot in
scope instead of one. Scheduling gained two debugging actions — "force
OpenCanary log poll now"/"force monitoring sample now"
(`app.services.honeypot_actions.trigger_canary_log_poll`/
`trigger_monitoring_sample`) — for forcing either sweep on demand instead
of waiting out its own interval.

Also fixed in the same pass: `auth/account.html` ("My account") was
almost entirely hardcoded English — the Password/2FA/Passkeys/Sessions/
API-tokens sections and several `data-confirm` prompts never went through
`t()` at all, despite this file and the wiki claiming complete i18n
coverage. Same gap, smaller scope, in `settings/_vpn.html`,
`companies/detail.html`, and `honeypots/list.html`/`edit.html`'s
`data-confirm`/`aria-label` attributes. All fixed — see
`tests/test_account_i18n.py` for the regression guard (asserts the Czech
locale actually renders Czech text on `/account`, not an English
fallback).

**Settings → VPN used to take ~10 seconds to open.** `netbird status`
(and every other `netbird` CLI call) doesn't fail fast when the sidecar
isn't running — its own gRPC client retries with backoff for about 10s
before giving up with "context deadline exceeded", regardless of this
app's own `netbird_command_timeout_seconds` (an outer ceiling on top of
that, not a replacement for it). `app.services.netbird._run` now checks
the daemon socket file exists first (`os.path.exists`, same fast check
`app.services.wireguard` already had for its own control socket) — fails
in microseconds instead. The VPN tab's NetBird/WireGuard status calls are
also now fetched concurrently (`asyncio.gather`) rather than sequentially.
WireGuard also gained its own connection log (`app.services.
vpn_control_server` now writes to `WIREGUARD_LOG_PATH`, a new shared
volume in `docker-compose.vpn.yml` — plain `wireguard-tools` keeps no log
of its own, unlike NetBird's client) and all three buttons (Connect/
Restart/Disconnect) for both providers now render as one row (the
"Connect" button submits its section's config form by `form="..."` id from
outside it, rather than living inside a separate form from Restart/
Disconnect).

**Users list**: the "API access" column header used to render an entire
sentence (reusing the edit-form field's own label+hint text) — a
dedicated short `users.list.api_access` key fixes it. Also gained
checkbox multi-select (bulk delete, bulk assign-to-company/access-level —
`POST /users/bulk/delete`/`/bulk/assign-company`, both declared *before*
`/{user_id}/...` in the router, same reasoning `app/web/routes/
honeypots.py`'s own `/bulk/...` routes are). Fixed alongside: `bulk-
select.js`'s "select all" checkbox used to hardcode toggling checkboxes
named `machine_ids` — a debcontrol leftover — so "select all" silently
did nothing on the Honeypots list (whose checkboxes are `honeypot_ids`);
the script now reads the checkbox name to toggle from `data-select-
all="..."` itself, fixing both pages.

**`scripts/setup.py`** now asks whether to add the VPN sidecar
(`docker-compose.vpn.yml`), same shape as its existing Caddy question —
no provider/setup-key/config asked there, all of that stays a Settings →
VPN, post-deploy step. `scripts/upgrade.sh`'s existing Caddy-detection
technique (a running container's own Compose service label, not an `.env`
flag) is reused for VPN detection too, in `upgrade.sh` itself and in
`scripts/setup.py`'s existing-`.env` re-run path. Two new scripts,
`scripts/stop.sh`/`start.sh`, stop/start the whole stack (`docker compose
stop`/`start` — nothing removed) with the same auto-detection, so there's
one command regardless of which overlay file(s) a given deployment
actually runs.

**Ported from debcontrol's own recent releases** (that project is synced
here periodically for fixes/features that apply to both — see its release
history): `scripts/backup.sh`/`restore.sh` for full disaster-recovery
backups — a live `pg_dump` plus `.env` (holding `ENCRYPTION_KEY`, without
which every stored secret is unrecoverable ciphertext), with automatic
retention pruning; unlike debcontrol, there's no separate shared SSH
identity volume to back up here, since a honeypot's own credential
already lives in the database. "Roll back this update"
(`HoneypotUpdateRun.package_snapshot`/`rollback_of_run_id`,
`app.ssh.updates.capture_package_snapshot`/`build_rollback_command`/
`run_rollback`, `app.tasks.jobs._rollback_honeypot_update`) — every real
update run now snapshots installed dpkg versions just before the upgrade
step; rolling back diffs a fresh snapshot against that stored one and
re-installs, pinned to exact `package=version`, only whatever actually
changed since (never a blind full replay), as a brand new run in the same
history rather than an edit to the original. Both the web UI (update-run
detail page) and the REST API (`POST /honeypots/{id}/updates/{run_id}/
rollback`) expose it, gated by the same write access as running an update
in the first place. FIPS-aligned crypto defaults
(`app.core.security`/`app.auth.sessions`/`app.ssh.client`) — secrets at
rest moved from Fernet (AES-128) to **AES-256-GCM**, with
`decrypt_secret` still transparently reading the legacy format forever
and `scripts/reencrypt_secrets.py` available to proactively upgrade every
remaining one; the pending-TOTP/WebAuthn `itsdangerous` tickets now sign
with `digest_method=hashlib.sha256` instead of the library's own
HMAC-SHA1 default; every honeypot SSH connection now restricts key
exchange/encryption/MAC negotiation to a FIPS-approved subset (NIST-curve
ECDH or ≥2048-bit DH with SHA-2, AES-GCM/CTR, HMAC-SHA-2), deliberately
left unrestricted only for the unauthenticated host-key-fingerprint probe
and the accepted server host-key algorithm itself (this app pins by exact
fingerprint, not algorithm). Argon2id password hashing was deliberately
**not** swapped for FIPS-approved PBKDF2 — a documented trade-off, not a
gap, since Argon2id is meaningfully more GPU/ASIC-resistant. See
[wiki/Architecture.md](wiki/Architecture.md)'s "FIPS alignment" and
"Rolling back a honeypot update" sections for the full reasoning, and
[wiki/Installation.md](wiki/Installation.md) for the backup/restore and
`reencrypt_secrets.py` usage. New migration `c8d9e0f1a2b3` (two nullable
columns on `honeypot_update_runs` — safe on an existing deployment, no
data backfill). Alongside this: `uv`/dependency versions synced to
current (`uv` 0.12.7 → 0.12.12 in the Dockerfile, `uv lock` re-run against
latest compatible releases) — `python:3.14.7-slim`, `postgres:18.6`, and
`redis:8.10.1` were already current, nothing to bump there.

**Initialize package/port fixes**: `app.ssh.initialize._APT_PACKAGES` was
installing `mlocate` — dropped from the Debian archive as of trixie (13,
what Raspberry Pi OS 13 is based on), so `apt-get install mlocate` failed
outright on every run; swapped for `plocate`, its actively maintained
drop-in replacement. Verified the entire package list against a real
`debian:trixie-slim` container (`apt-get install --dry-run`), not just
`apt-cache show` (which reports success for virtual/transitional package
names with no installable candidate at all, e.g. `man` → `man-db` — a
false-positive trap worth remembering if re-checking this list later).
Also, `build_initialize_command`'s very last step now moves the freshly
provisioned device's own sshd from port 22 to `NEW_SSH_PORT` (22222) via
an `/etc/ssh/sshd_config.d/` drop-in — `sshd -t` validates the config
before ever restarting the daemon (and `set -e` aborts before that
restart on a failure), so this can't lock an operator out mid-run; see
`app.ssh.initialize`'s module docstring and
[wiki/Honeypot-Initialize.md](wiki/Honeypot-Initialize.md)'s new "SSH
moves to a new port on success" section for the full reasoning. Both the
Initialize form and the run page now call out the new port explicitly.

**Found live on real hardware, same round**: `chown syslog:adm
/var/log/samba-audit.log` (the smb-module prep step) crashed the whole
run with `chown: invalid user: 'syslog'` — Debian trixie's `rsyslog`
package no longer creates that dedicated system user in its postinst
(confirmed against a real `debian:trixie-slim` install: `getent passwd
syslog` finds nothing after a plain `apt-get install rsyslog`; modern
rsyslogd instead runs as root via systemd `CAP_*` capabilities). Fixed by
dropping the chown and relying on a plain `chmod 644` — rsyslogd (root)
can write regardless of file ownership, and opencanaryd's `smb` module,
which tails the file as the unprivileged `nobody:nogroup` its unit drops
to, only needs world-read. Auditing the adjacent portscan prep for the
same class of bug turned up a real (if not yet reported) one: rsyslog's
own default `$FileCreateMode`/`$FileOwner`/`$FileGroup` (`0640 root:adm`
— see a fresh install's own `/etc/rsyslog.conf`) would make a freshly
created `kern.log` unreadable by that same unprivileged `nobody`, since
`nobody` isn't in the `adm` group either — fixed by pre-creating the file
`chmod 644` before rsyslog ever restarts (confirmed empirically that
rsyslogd only applies its own create-mode when it *creates* a file, never
when appending to one that already exists — an already-644 file it opens
for append stays 644). `NEW_SSH_PORT` (22222) is now just
`build_initialize_command`'s default — a "New SSH port" field on the
Initialize form (and round-tripped through the run page, `PendingInitializeRun`,
and `initialize_ws`) lets an operator override it per run, e.g. setting it
equal to the connect port to leave a device's SSH port unchanged on a
re-run. The run page's "Back to Initialize" link also now carries every
non-secret field (IP, device name, user, port, auth method, VPN provider,
new SSH port) back as query params the form pre-fills from — a failed run
no longer means retyping everything to retry, matching the POST-failure
re-render path's own long-standing "prefill non-secrets, never
passwords/keys" convention.

**One more found live, same day**: `gpg --dearmor -o
.../netbird-archive-keyring.gpg` crashed a re-run against a device that
already had that keyring from an earlier attempt — plain `gpg --dearmor`
silently prompts "overwrite existing file?" on stdin, and since Initialize
runs everything over a plain SSH exec with no pty allocated, gpg can't
read that prompt from `/dev/tty` at all, failing with `gpg: cannot open
'/dev/tty': No such device or address` (exit 2, which `set -e` then
aborts the whole script on) instead of just overwriting it. Reproduced
directly in a `debian:trixie-slim` container (`gpg --dearmor -o
/tmp/test.gpg` twice in a row against the same output path) before
fixing. Fixed with `gpg --batch --yes --dearmor`, which is genuinely
idempotent instead of just documented as such.

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
  today) — same mechanism as debcontrol, copied as-is. Coverage is now
  complete across every page, including tab-navigation labels built in
  Python (`_honeypot_tabs`/`_company_tabs`/`settings._tabs` all take
  `request` and call `t()` per label, rather than returning a static
  list) — extend it the same way debcontrol's wiki documents (add the key
  to **every** `app/i18n/locales/*.json` file, not just one). **A macro
  that calls `t(request, ...)` — directly, or indirectly via `{% include
  %}` inside its own body — needs `request` as an explicit parameter**:
  Jinja macros don't inherit the calling template's context by default,
  so omitting it fails with `UndefinedError: 'request' is undefined` the
  moment the macro actually renders (not a syntax error — a plain `{%
  parse %}` check won't catch it; caught two real instances of exactly
  this — `partials/_packages_summary.html`/`_services_summary.html` and
  `macros/charts.html` — while completing i18n).

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
