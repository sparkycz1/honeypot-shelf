# 🚀 Installation

## Quick start (Docker)

```bash
git clone https://github.com/sparkycz1/honeyhive.git
cd honeyhive
cp .env.example .env
python scripts/generate_secrets.py
```

Paste the printed values (`SECRET_KEY`, `ENCRYPTION_KEY`,
`POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `INGEST_TOKEN`) into `.env`.
Optionally set `TZ` (e.g. `Europe/Prague`); defaults to UTC. Then:

```bash
docker compose up -d --build
```

> [!IMPORTANT]
> This scaffold ships **no initial Alembic migration yet** — the models
> exist but nothing has generated the first migration against them. Before
> `migrate` (the one-shot service that runs `alembic upgrade head`) has
> anything to apply, generate it once against a running Postgres:
> ```bash
> docker compose up -d db redis
> docker compose run --rm web alembic revision --autogenerate -m "Initial schema"
> docker compose run --rm web alembic upgrade head
> ```
> Commit the generated file under `alembic/versions/`. After that, `docker
> compose up -d --build` applies it automatically on every start via the
> `migrate` service.

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

You'll also need at least one `Company` and one `Honeypot` row before
anything shows up — there's no UI to create either yet (see
[Home.md](Home.md)'s open questions); insert them directly for now:

```bash
docker compose exec web python -c "
import asyncio, uuid
from app.db.session import AsyncSessionLocal
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot

async def main():
    async with AsyncSessionLocal() as db:
        company = Company(name='Example customer')
        db.add(company)
        await db.flush()
        db.add(Honeypot(company_id=company.id, hostname='example-honey1'))
        await db.commit()
        print(company.id)

asyncio.run(main())
"
```

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

See [Development.md](Development.md) for running the test suite,
linting/type-checking, and adding a migration.
