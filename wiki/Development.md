# 🛠️ Development

## Setup

```bash
uv sync                # installs into .venv, including dev dependencies
```

The app itself has no supported bare-metal run path (see
[Installation](Installation.md)) — tests run against in-memory SQLite, not
a real Postgres, so `uv sync` alone is enough for lint/type-check/tests.

## Commands

```bash
uv run pytest                        # full suite
uv run pytest tests/test_x.py -k y   # one test
uv run ruff check .                   # lint
uv run ruff format .                  # format
uv run mypy app alembic tests        # type check (strict for app/, alembic/)
```

## Adding a migration

```bash
uv run alembic revision --autogenerate -m "Add honeypot.notes"
```

**Always read the generated file** — autogenerate misses some things
(renamed columns look like a drop + an add; server-side defaults on an
existing table need a data migration if the column isn't nullable). Then:

```bash
uv run alembic upgrade head
uv run alembic heads     # must show exactly one head before committing
```

Every new/changed model must also be imported in
[`app/db/models/__init__.py`](../app/db/models/__init__.py) and
[`alembic/env.py`](../alembic/env.py) — a model not imported there is
invisible to `--autogenerate`.

## Adding a company-scoped route

1. Depend on `app.auth.dependencies.get_current_user` (read) or
   `require_write` (mutating).
2. Resolve the `company_id` in question and call
   `app.auth.scope.ensure_company_access(user, company_id, write=...)` —
   or, for a list view, filter by `app.auth.scope.visible_company_id(user)`
   (`None` for a superadmin means "no filter").
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

is the only supported way — see [Installation](Installation.md). There's
no `uvicorn app.main:app --reload` path documented yet, since the app
expects real Postgres/Redis and there's no docker-compose override for a
hot-reloading dev container in this scaffold; add one
(`docker-compose.override.yml` mounting `./app` and running
`uvicorn --reload`) if that workflow turns out to matter.
