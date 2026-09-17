# 🛠️ Development

*Ruff, mypy, pytest, one alembic head — the gate that keeps main green, and CI runs the exact same one.*

## Setup

```bash
uv sync                # installs into .venv, including dev dependencies
```

No bare-metal run path (see [Installation](Installation.md)) — but tests run
against in-memory SQLite, not real Postgres, so `uv sync` alone is enough
for lint/type-check/tests.

## Commands

```bash
uv run pytest                        # full suite
uv run pytest tests/test_x.py -k y   # one test
uv run ruff check .                   # lint
uv run ruff format .                  # format
uv run mypy app alembic tests        # type check (strict for app/, alembic/)
```

**CI runs this same gate** on every push/PR
(`.github/workflows/ci.yml`) — ruff, mypy, the full test suite, and the
single-alembic-head check, plus a separate `pip-audit` pass over exactly
what `uv.lock` would install. [Dependabot](https://github.com/sparkycz1/honeypot-shelf/blob/main/.github/dependabot.yml)
watches for newer fixed versions of Python, Docker, and GitHub Actions
dependencies on top of that. Nothing here needs a real Postgres/Redis —
see `tests/conftest.py`.

## Adding a migration

```bash
uv run alembic revision --autogenerate -m "Add honeypot.notes"
```

**Always read the generated file** — autogenerate misses things (a renamed
column looks like a drop + an add; a server-side default on an existing
table needs a data migration if the column isn't nullable). Then:

```bash
uv run alembic upgrade head
uv run alembic heads     # must show exactly one head before committing
```

Every new/changed model must also be imported in
[`app/db/models/__init__.py`](https://github.com/sparkycz1/honeypot-shelf/blob/main/app/db/models/__init__.py) and
[`alembic/env.py`](https://github.com/sparkycz1/honeypot-shelf/blob/main/alembic/env.py) — a model not imported there is
invisible to `--autogenerate`.

## Adding a company-scoped route

1. Depend on `app.auth.dependencies.get_current_user` (read) or
   `require_write` (mutating).
2. Resolve the `company_id` in question and call
   `app.auth.scope.ensure_company_access(user, company_id, write=...)` —
   or, for a list view, filter by `app.auth.scope.visible_company_ids(user)`
   (a set of ids; `None` for a superadmin means "no filter").
3. If it's a mutation, wrap it with CSRF (`Depends(verify_csrf)` on the
   route, or the router-level `dependencies=[...]` if every route on it
   mutates) and call `app.audit.log_event(...)` after the commit.
4. Add the equivalent i18n keys to **every** `app/i18n/locales/*.json`
   file if the page has user-facing strings going through `t()`.

## Adding a new i18n string

Wrap it in `{{ t(request, "area.key") }}` in the template, then add
`"area.key"` to `app/i18n/locales/en.json` **and** `cs.json` (a missing key
in one locale falls back to English, but a key added to only one file is
an oversight, not a feature — see `app/i18n/__init__.py`'s docstring).

## Running it locally against real infrastructure

```bash
docker compose up -d --build
```

is the only supported way — see [Installation](Installation.md). No
`uvicorn app.main:app --reload` path yet (the app needs real Postgres/
Redis, and there's no hot-reload compose override); add one
(`docker-compose.override.yml` mounting `./app`, running `uvicorn
--reload`) if that workflow turns out to matter.
