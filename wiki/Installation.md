# 🚀 Installation

## Quick start (Docker) — recommended

```bash
git clone https://github.com/sparkycz1/honeyhive.git
cd honeyhive
python scripts/setup.py
```

`scripts/setup.py` is a self-contained, pure-stdlib wizard (needs only a
system `python3` and Docker — nothing from this project's own virtualenv):
it generates every secret (`SECRET_KEY`, `ENCRYPTION_KEY`,
`POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `INFORM_TOKEN`, `INGEST_TOKEN`),
asks a handful of questions (timezone, whether to use the bundled Caddy
reverse proxy and its domain/email if so, whether the app's own port
should only accept local connections, the facts/reachability check
intervals, event retention, the superadmin password — or auto-generates
one — and the host port), writes `.env`, applies the Alembic migration,
brings the stack up, waits for it to become healthy, and creates the
first superadmin account (`admin`). Re-running it against an existing
`.env` just tops that file up with any new `.env.example` variables and
restarts the stack — it won't regenerate secrets or touch your data.

Once it finishes, log in and create at least one `Company` and one
`Honeypot` from the Companies/Honeypots pages (both superadmin-only) —
nothing shows up on the Dashboard before that. See
[Honeypot Onboarding](Honeypot-Onboarding.md) for pointing an actual
OpenCanary host at the honeypot you create.

## Manual setup

If you'd rather configure everything by hand instead of using
`scripts/setup.py`:

```bash
cp .env.example .env
python scripts/generate_secrets.py
```

Paste the printed values (`SECRET_KEY`, `ENCRYPTION_KEY`,
`POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `INFORM_TOKEN`, `INGEST_TOKEN`)
into `.env`. Optionally set `TZ` (e.g. `Europe/Prague`); defaults to UTC.
Then:

```bash
docker compose up -d --build
```

`alembic/versions/` already ships the initial schema migration
(`1aabc66480ab_initial_schema.py`) — the one-shot `migrate` service applies
it automatically (`alembic upgrade head`) before `web`/`worker`/`beat`
start. If you've changed a model since and need a new migration, see
[Development.md](Development.md#adding-a-migration).

The app listens on `APP_PORT` (default `8080`, plain HTTP, all interfaces
by default — meant to sit behind a TLS-terminating reverse proxy; set
`APP_BIND_ADDRESS=127.0.0.1` in `.env` — no `docker-compose.yml` edit
needed — or firewall the port off if you don't want that). Point your own
nginx/Traefik/Caddy at it — see the reverse-proxy guides:
[nginx](Reverse-Proxy-Nginx.md) · [Traefik](Reverse-Proxy-Traefik.md) ·
[Caddy (standalone)](Reverse-Proxy-Caddy.md). Or use the **bundled Caddy**
(automatic HTTPS via Let's Encrypt): set `DOMAIN` and `ACME_EMAIL` in
`.env`, point that domain's DNS at this host, open ports 80/tcp, 443/tcp
and 443/udp, then
`docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build`.

Then create the first superadmin account:

```bash
docker compose exec web python scripts/create_admin.py --username admin
```

Log in, then create at least one `Company` and one `Honeypot` from the
Companies/Honeypots pages — nothing shows up on the Dashboard before
that.

> [!WARNING]
> The app speaks **plain HTTP only**. Always put TLS termination in front
> of it, and firewall its port off (or set `APP_BIND_ADDRESS=127.0.0.1` in
> `.env`) if you don't want it reachable directly.

## Updating

```bash
./scripts/upgrade.sh
```

Pulls the latest code, syncs any new `.env.example` variables into your
`.env` (`scripts/env_sync.py`), rebuilds, and re-applies migrations.

## Locked out?

`scripts/reset_account.py` (console-only, same idea as debcontrol's) resets
a password and/or disables TOTP for an account already locked out of the
web UI:

```bash
docker compose exec web python scripts/reset_account.py --username admin
```

Non-interactively, set `HONEYHIVE_RESET_PASSWORD` in the environment
instead of being prompted (same reasoning as `create_admin.py`'s
`HONEYHIVE_ADMIN_PASSWORD` — it never shows up in a process listing the
way a `--password` flag would).

See [Development.md](Development.md) for running the test suite,
linting/type-checking, and adding a migration.
