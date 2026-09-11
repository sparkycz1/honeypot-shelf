# <img src="app/web/static/img/logo.svg" width="32" height="32" align="center" alt=""> Honeypot Shelf

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.14-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/web-FastAPI-009688?logo=fastapi&logoColor=white)
![Task queue](https://img.shields.io/badge/task%20queue-Celery-37814A?logo=celery&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/db-PostgreSQL%2018-336791?logo=postgresql&logoColor=white)
![Docker Compose](https://img.shields.io/badge/deploy-Docker%20Compose-2496ED?logo=docker&logoColor=white)

Management and monitoring overview for a fleet of
[OpenCanary](https://github.com/thinkst/opencanary) honeypots deployed at
customer sites, across **multiple companies**, each with their own scoped
users. Every page requires a login; a user either is a superadmin (every
company) or belongs to exactly one company with **read** or **read +
write** access — nothing in between. Accounts can authenticate locally,
against LDAP, or via OIDC SSO, with optional TOTP/passkey two-factor.

Built on the same stack, project layout, and auth system as
[debcontrol](https://github.com/sparkycz1/debcontrol) (a sister project for
Debian fleet management) — see [CLAUDE.md](CLAUDE.md) for what was reused
and what's different.

**Full documentation lives in the [wiki](wiki/Home.md)** — feature status
and open product questions ([Home](wiki/Home.md)), technology choices and
the security/RBAC model ([Architecture](wiki/Architecture.md)), reverse
proxy guides, honeypot onboarding, and local development
([Development](wiki/Development.md)). This file only covers getting a
fresh instance running.

> [!NOTE]
> A honeypot is managed exactly like a machine in
> [debcontrol](https://github.com/sparkycz1/debcontrol) — terminal, facts,
> packages, system updates, power, scheduling — plus this project's own
> addition: honeypots push OpenCanary events in, and the Dashboard sums
> them per company. See [wiki/Home.md](wiki/Home.md)'s "Current state"
> section for exact coverage and open questions.

## 🚀 Quick start (Docker)

**Recommended — one interactive script does everything:**

```bash
git clone https://github.com/sparkycz1/honeypot-shelf.git
cd honeyhive
python scripts/setup.py
```

It generates every secret, asks a handful of questions (timezone, whether
to use the bundled Caddy reverse proxy, background-check intervals, the
superadmin password — or auto-generates one — and the host port), then
applies the DB migration, brings the stack up, and creates the first
superadmin account for you. Full details:
[wiki/Installation.md](wiki/Installation.md).

**Manual setup**, if you'd rather configure everything by hand:

```bash
cp .env.example .env
python scripts/generate_secrets.py
```

Paste the printed values into `.env`, then see
[wiki/Installation.md](wiki/Installation.md) for the rest (applying the DB
migration, bringing the stack up, creating the first superadmin account,
and reverse-proxy options).

```bash
docker compose up -d --build
docker compose exec web python scripts/create_admin.py --username admin
```

> [!WARNING]
> The app speaks **plain HTTP only**. Always put TLS termination in front
> of it, and firewall its port off (or set `APP_BIND_ADDRESS=127.0.0.1` in
> `.env`) if you don't want it reachable directly.

See [wiki/Installation.md](wiki/Installation.md) for the full walkthrough
and [wiki/Installation.md#updating](wiki/Installation.md#updating) for
upgrading later. See [wiki/Development.md](wiki/Development.md) for
running the test suite, linting/type-checking, adding a migration, and
other project conventions.

## 🔒 Security

See [.github/SECURITY.md](.github/SECURITY.md) — supported versions and how to report a vulnerability.

## 📄 License

[MIT](LICENSE)
