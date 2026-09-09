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
reverse proxy and its domain/email if so, whether to add the optional VPN
sidecar (`docker-compose.vpn.yml` — no provider/setup key/config asked
here, that's all done from Settings → VPN once the app is running, see
[Architecture](Architecture.md)'s "VPN connectivity" section), whether the
app's own port should only accept local connections, the facts/
reachability check intervals, event retention, the superadmin password —
or auto-generates one — and the host port), writes `.env`, applies the
Alembic migration, brings the stack up, waits for it to become healthy,
and creates the first superadmin account (`admin`). Re-running it against
an existing `.env` just tops that file up with any new `.env.example`
variables and restarts the stack (auto-detecting whether Caddy/the VPN
sidecar were previously running, same as [`scripts/upgrade.sh`](#updating)
does) — it won't regenerate secrets or touch your data.

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
> other than `http://localhost` — not just restricted, entirely absent from
> `window`/`navigator`, with no server-side workaround: **WebAuthn/
> passkeys** (My account → Passkeys shows "This browser doesn't support
> passkeys" even in a browser that does, once it notices) and **the
> honeypot terminal's clipboard copy/paste** (Ctrl+C/Ctrl+V and right-click
> copy; native Ctrl+V paste still works, since that doesn't go through the
> Clipboard API). Both need a real "secure context" — reached over HTTPS
> (an `https://` reverse proxy, Caddy or otherwise) or accessed as
> `http://localhost` on the machine HoneyHive itself runs on. A plain HTTP
> LAN IP/hostname (e.g. `http://192.168.1.x:8080`) satisfies neither, no
> matter how the app itself or its host firewall is configured.
>
> **No public domain needed to fix this on a LAN-only deployment.** A
> browser treats any `https://` origin as a secure context regardless of
> whether the certificate is trusted — a self-signed one is enough, at the
> cost of a one-time "this connection isn't private, proceed anyway"
> click per client. The bundled Caddy (below) can mint one itself: in
> `./Caddyfile`, replace the site address with `tls internal` —
> ```
> :443 {
>     tls internal
>     reverse_proxy web:8080
> }
> ```
> then `docker compose -f docker-compose.yml -f docker-compose.caddy.yml up
> -d --build` and open `https://<this-host's-LAN-IP>`. `DOMAIN`/`ACME_EMAIL`
> aren't needed for this path. To make the browser warning go away
> permanently instead of clicking through it every time, install Caddy's
> local CA on each client (`docker compose exec caddy caddy trust` prints
> where to find it) — optional, purely cosmetic, WebAuthn/clipboard work
> either way once the page has loaded over `https://`.
>
> **Already have HTTPS via a reverse proxy (bundled Caddy, your own, or one
> on a different host) and still seeing this?** The app itself also needs
> to know the request arrived as HTTPS — otherwise it builds/verifies URLs
> and origins as if it were still plain HTTP even though the browser used
> HTTPS, which fails WebAuthn with "Unexpected client data origin" and
> breaks OIDC login the same way. This is what `TRUSTED_PROXY_IPS` (see
> `.env.example`, default `*`) fixes — already on by default for every
> setup described above. See `app/core/proxy_headers.py` and
> [Architecture](Architecture.md#authentication--rbac) for the full story.
>
> **Audit log / rate limiter showing the proxy's IP instead of the real
> client's?** That's a separate correction (`X-Forwarded-For`, not
> `X-Forwarded-Proto`) with a different, off-by-default setting —
> `TRUST_FORWARDED_FOR` (see `.env.example`) — precisely because trusting
> it from just anyone would let an attacker defeat the login rate limiter
> by spoofing a different "source" on every attempt. Turn it on once
> `TRUSTED_PROXY_IPS` is narrowed to your real proxy's address (not `*`).

## Custom logo & favicon

By default, HoneyHive shows its own built-in bee mark in the nav bar,
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
`/app/branding/<filename>`. Any common image format works (SVG, PNG,
etc.). Restart `web` after changing either. See `.env.example` and
`app/web/branding.py` for exactly how a URL vs. a local path is told
apart.

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
deployment the same way `upgrade.sh` does — by each container's own
Compose service label, not anything in `.env` — so it's the same one
command whichever of `docker-compose.yml` alone,
`+ docker-compose.caddy.yml`, `+ docker-compose.vpn.yml`, or both overlays
together you're actually running; nothing to remember or pass by hand.
`start.sh` refuses to run (with a pointer to `scripts/setup.py` instead)
if it finds no existing HoneyHive containers at all — it only starts a
stack that's already been set up once, it doesn't create one.

For a one-off restart of just one service instead of the whole stack
(e.g. after editing `Caddyfile`), `docker compose restart <service>`
still works as usual — these two scripts are for stopping/starting
*everything* together.

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
