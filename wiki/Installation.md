# 🚀 Installation

*One `docker compose up`, and the fleet-watching begins.*

## Quick start (Docker) — recommended

```bash
git clone https://github.com/sparkycz1/honeypot-shelf.git
cd honeyhive
python3 scripts/setup.py
```

`scripts/setup.py` is a self-contained, pure-stdlib wizard (needs only a
system `python3` and Docker — nothing from this project's own virtualenv):
generates every secret (`SECRET_KEY`, `ENCRYPTION_KEY`,
`POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `INFORM_TOKEN`),
asks a handful of questions (timezone, whether to use the bundled Caddy
reverse proxy and its domain/email, whether to add the optional VPN
sidecar (`docker-compose.vpn.yml` — no provider/key/config asked here,
that's all Settings → VPN once the app is running, see
[Architecture](Architecture.md)'s "VPN connectivity" section), whether the
app's port should only accept local connections, the facts/reachability
check intervals, event retention, the deploy-wide default UI language
(`DEFAULT_LANGUAGE` — what a fresh account/anonymous request renders in;
anyone can still switch for themselves any time in My account →
Language), the superadmin password — or auto-generates one — and the host
port), writes `.env`, applies the
Alembic migration, brings the stack up, waits for it to become healthy,
and creates the first superadmin account (`admin`). Re-running against an
existing `.env` just tops it up with any new `.env.example` variables and
restarts the stack (auto-detecting whether Caddy/the VPN sidecar were
running, same as [`scripts/upgrade.sh`](#updating) does) — never
regenerates secrets or touches your data.

Once it finishes, log in and create at least one `Company` and one
`Honeypot` from the Companies/Honeypots pages (both superadmin-only) —
nothing shows up on the Dashboard before that. Pin that honeypot's SSH
host key and events start arriving automatically, no setup needed on the
Pi itself — see [Architecture](Architecture.md#-honeypot-data-model)'s
"How events arrive" section.

## Manual setup

If you'd rather configure everything by hand instead of using
`scripts/setup.py`:

```bash
cp .env.example .env
python3 scripts/generate_secrets.py
```

Paste the printed values (`SECRET_KEY`, `ENCRYPTION_KEY`,
`POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `INFORM_TOKEN`)
into `.env`. Optionally set `TZ` (e.g. `Europe/Prague`); defaults to UTC.
Then:

```bash
docker compose up -d --build
```

`alembic/versions/` already ships the initial schema migration; the
one-shot `migrate` service applies it automatically (`alembic upgrade
head`) before `web`/`worker`/`beat` start. Need a new migration? See
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

If a honeypot sits behind a NAT with no port forwarded to it, add
`-f docker-compose.vpn.yml` too (combine freely with `docker-compose.caddy.yml`
above) and connect either NetBird or WireGuard from Settings → VPN once
the app is running — see [Architecture](Architecture.md)'s "VPN
connectivity" section for what this does, which of the two to pick, and
why it's a separate container.

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

> [!WARNING]
> Two features are browser-disabled outright on plain HTTP, for any origin
> other than `http://localhost` — entirely absent from `window`/
> `navigator`, no server-side workaround: **WebAuthn/passkeys** (My
> account → Passkeys shows "This browser doesn't support passkeys" even in
> a browser that does) and **the honeypot terminal's clipboard copy/paste**
> (Ctrl+C/Ctrl+V and right-click copy; native Ctrl+V still works, since
> that skips the Clipboard API). Both need a real "secure context" —
> HTTPS (an `https://` reverse proxy, Caddy or otherwise) or
> `http://localhost` on the machine Honeypot Shelf runs on. A plain HTTP
> LAN IP/hostname (`http://192.168.1.x:8080`) satisfies neither, no matter
> how the app or host firewall is configured.
>
> **No public domain needed on a LAN-only deployment.** A browser treats
> any `https://` origin as secure regardless of certificate trust — a
> self-signed one is enough, at the cost of a one-time "proceed anyway"
> click per client. The bundled Caddy can mint one itself: in
> `./Caddyfile`, replace the site address with `tls internal` —
> ```
> :443 {
>     tls internal
>     reverse_proxy web:8080
> }
> ```
> then `docker compose -f docker-compose.yml -f docker-compose.caddy.yml up
> -d --build` and open `https://<this-host's-LAN-IP>`. `DOMAIN`/`ACME_EMAIL`
> aren't needed here. To stop the browser warning permanently, install
> Caddy's local CA on each client (`docker compose exec caddy caddy trust`
> prints where to find it) — cosmetic only, WebAuthn/clipboard work either
> way once the page loads over `https://`.
>
> **Already have HTTPS via a reverse proxy and still seeing this?** The
> app also needs to know the request arrived as HTTPS — otherwise it
> builds/verifies URLs as if still plain HTTP, failing WebAuthn
> ("Unexpected client data origin") and OIDC login the same way. Fixed by
> `TRUSTED_PROXY_IPS` (`.env.example`, default `*`) — already on for every
> setup above. See `app/core/proxy_headers.py` and
> [Architecture](Architecture.md#authentication--rbac) for the full story.
>
> **Audit log / rate limiter showing the proxy's IP instead of the real
> client's?** A separate, off-by-default fix — `TRUST_FORWARDED_FOR`
> (`.env.example`) — trusting it from anyone would let an attacker defeat
> the login rate limiter by spoofing a new "source" every attempt. Turn it
> on once `TRUSTED_PROXY_IPS` is narrowed to your real proxy (not `*`).

### Postgres tuning

`docker-compose.yml`'s `db` service applies a handful of Postgres tuning
flags from the very first `docker compose up` (`shared_buffers`,
`effective_cache_size`, `work_mem`, `maintenance_work_mem`, and two
`autovacuum_*_scale_factor` settings) — sized for a fleet up to roughly
100 honeypots while staying RAM-conscious, well under Postgres' own stock
"assume a big dedicated box" numbers. Override any of them via the
matching `POSTGRES_*` variable in `.env` (see `.env.example`) for a
bigger fleet/host, or a smaller/constrained one.

## Custom logo & favicon

By default, Honeypot Shelf shows its own built-in bee mark in the nav bar,
login/two-factor pages, and browser tab — it already adapts to the
in-app light/dark toggle (and the favicon separately follows the OS/
browser's own dark-mode preference). To replace it with your own:

```bash
# In .env — either works for LOGO_SOURCE and FAVICON_SOURCE independently:
LOGO_SOURCE=https://example.com/my-logo.svg   # a URL, fetched by the browser directly
LOGO_SOURCE=/app/branding/logo.svg            # a file path readable inside the `web` container
```

A filesystem path needs the file mounted into the container first —
uncomment the `branding` volume on the `web` service in
`docker-compose.yml`, drop the file(s) into a local `./branding/`
directory, and point `LOGO_SOURCE`/`FAVICON_SOURCE` at
`/app/branding/<filename>`. Any common image format works. Restart `web`
after changing either — see `.env.example`/`app/web/branding.py` for how
a URL vs. a local path is told apart.

## Updating

```bash
./scripts/upgrade.sh
```

Pulls the latest code, syncs any new `.env.example` variables into your
`.env` (`scripts/env_sync.py`), rebuilds, and re-applies migrations.
Auto-detects whether the bundled Caddy or the VPN sidecar are currently
running (by their Compose service label, not an `.env` flag) and includes
the matching overlay file(s) automatically — nothing to pass by hand.

## Stopping and starting

```bash
./scripts/stop.sh
./scripts/start.sh
```

`stop.sh` stops every container (`docker compose stop` — nothing removed,
your data stays exactly as it was); `start.sh` starts them again. Both
auto-detect whether Caddy and/or the VPN sidecar are part of this
deployment (by each container's own Compose service label, not `.env`),
so it's the same one command regardless of which overlay file(s) you're
actually running. `start.sh` refuses to run (pointing at `scripts/
setup.py` instead) if it finds no existing containers — it only starts a
stack already set up once, it doesn't create one.

For a one-off restart of a single service (e.g. after editing
`Caddyfile`), plain `docker compose restart <service>` still works —
these two scripts are for stopping/starting *everything* together.

## Backups

```bash
./scripts/backup.sh
```

Writes one timestamped directory under `./backups/` (override with
`BACKUP_DIR` in `.env`) holding everything needed to rebuild this instance
from nothing on a fresh host:

- `db.sql.gz` — a `pg_dump` of the whole database, taken live via
  Postgres's own MVCC snapshot (the stack does **not** need to be stopped).
- `env.backup` — a copy of `.env`. In particular `ENCRYPTION_KEY`: every
  encrypted secret in the database (honeypot passwords/private keys,
  LDAP/OIDC client secrets, NetBird/WireGuard config, TOTP secrets — see
  [Architecture](Architecture.md#secrets-at-rest)) is encrypted with it,
  so a database restored under a *different* key turns those permanently
  unreadable — no recovery after the fact, not even by hand. (Unlike
  debcontrol, Honeypot Shelf keeps no separate SSH identity volume to back
  up — every honeypot's credential already lives in the DB, covered by
  `db.sql.gz`.)

Old backup directories are pruned automatically — anything older than
`BACKUP_RETENTION_DAYS` (default 14, override in `.env`) is deleted at the
end of every run, safe to leave running unattended forever.

**The backup directory holds secrets in the clear** (`env.backup`, and
every value the DB dump can decrypt combined with it) — created `chmod
600`-ish but that only protects against other local accounts on the same
host. Copy it somewhere access-controlled and off this host (object
storage, another server's backup job pulling over `rsync`/`scp`, ...)
rather than trusting a local disk alone; losing the host and `./backups/`
together is the same as never having backed up at all.

### Automating it with cron

Run it daily at, say, 03:15 server time — as the same user that normally
runs `docker compose` here (needs Docker socket access), with output
mailed/logged rather than silently discarded so a failure doesn't go
unnoticed:

```bash
crontab -e
```

```cron
15 3 * * * cd /path/to/honeyhive && ./scripts/backup.sh >> /var/log/honeyhive-backup.log 2>&1
```

Adjust `/path/to/honeyhive` to the actual checkout path (`pwd` from
inside it), and make sure `/var/log/` (or wherever you point the log) is
writable by that user — `touch /var/log/honeyhive-backup.log && chown
that-user /var/log/honeyhive-backup.log` if it isn't yet. Check the log
after the first scheduled run to confirm it actually succeeded, and
periodically after that — a cron job that silently stopped working is
worse than no backup job, since it looks like there's one until the day
you need it.

If you'd rather ship backups straight off the host instead of relying on
someone to sync `./backups/` separately, append a second line to the same
cron entry (or a follow-up cron job a few minutes later) that
`rsync`/`scp`/`aws s3 sync`s the freshly-created directory (or the whole
`BACKUP_DIR`) to wherever your off-host storage is.

### Restoring

```bash
./scripts/restore.sh backups/20260909T031500Z
```

**Destructive** — replaces the current database and `.env` outright (the
current `.env` is saved as `.env.pre-restore` first, never silently
discarded). Requires typing `restore` to confirm (`--yes` skips that, for
a scripted DR runbook). Stops `web`/`worker`/`beat`, drops and recreates
the database from `db.sql.gz`, replaces `.env`, then starts the stack back
up. Restore onto a checkout already on the version the backup was taken
from — run `upgrade.sh` afterward if you need to move it forward.

## Upgrading stored secrets to AES-256-GCM

Every secret this app stores (honeypot passwords/private keys, LDAP/OIDC
client secrets, NetBird/WireGuard config, TOTP secrets) has used
AES-256-GCM since v0.17.0 — see
[Architecture → FIPS alignment](Architecture.md#fips-alignment). A value
encrypted by an older version is still read transparently forever
(nothing breaks by doing nothing), but a deployment that would rather not
carry any of the older AES-128 (Fernet) ciphertext going forward can
upgrade every remaining one in a single optional pass:

```bash
docker compose exec web python scripts/reencrypt_secrets.py --dry-run  # see what would change
docker compose exec web python scripts/reencrypt_secrets.py            # actually upgrade it
```

Re-encrypts under the same `ENCRYPTION_KEY` — this is a format upgrade,
not a key rotation, and it's safe to run repeatedly (idempotent).

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
