# ![Honeypot Shelf](app/web/static/img/logo.png)

[![CI](https://github.com/sparkycz1/honeypot-shelf/actions/workflows/ci.yml/badge.svg)](https://github.com/sparkycz1/honeypot-shelf/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sparkycz1/honeypot-shelf/actions/workflows/codeql.yml/badge.svg)](https://github.com/sparkycz1/honeypot-shelf/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sparkycz1/honeypot-shelf/badge)](https://scorecard.dev/viewer/?uri=github.com/sparkycz1/honeypot-shelf)
[![Secret scanning: enabled](https://img.shields.io/badge/secret%20scanning-enabled-brightgreen)](https://github.com/sparkycz1/honeypot-shelf/security)
[![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial%201.0.0-blue)](LICENSE)
![Python](https://img.shields.io/badge/python-3.14-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/web-FastAPI-009688?logo=fastapi&logoColor=white)
![Task queue](https://img.shields.io/badge/task%20queue-Celery-37814A?logo=celery&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/db-PostgreSQL%2018-336791?logo=postgresql&logoColor=white)
![Docker Compose](https://img.shields.io/badge/deploy-Docker%20Compose-2496ED?logo=docker&logoColor=white)
![Dependabot](https://img.shields.io/badge/dependabot-enabled-025E8C?logo=dependabot&logoColor=white)
![Security: ruff + pip-audit](https://img.shields.io/badge/security-ruff%20%2B%20pip--audit-4B8BBE)

Management and monitoring overview for a fleet of
[OpenCanary](https://github.com/thinkst/opencanary) honeypots deployed at
customer sites, across **multiple companies**, each with their own scoped
users. Every page requires a login; a user either is a superadmin (every
company) or holds zero or more per-company memberships, each its own
**read** or **read + write** access level — the same person can be
`read + write` at one company and `read`-only at another. Accounts can
authenticate locally, against LDAP, or via OIDC SSO, with optional
TOTP/passkey two-factor.

Built on the same stack, project layout, and auth system as
[debcontrol](https://github.com/sparkycz1/debcontrol) (a sister project for
Debian fleet management) — see [CLAUDE.md](CLAUDE.md) for what was reused
and what's different.

This project was originally built for [Faster CZ](https://www.faster.cz/);
most of it is vibecoded.

**Full documentation lives in the [wiki](https://github.com/sparkycz1/honeypot-shelf/wiki/Home)** — feature status
and open product questions ([Home](https://github.com/sparkycz1/honeypot-shelf/wiki/Home)), technology choices and
the security/RBAC model ([Architecture](https://github.com/sparkycz1/honeypot-shelf/wiki/Architecture)), reverse
proxy guides, honeypot onboarding, and local development
([Development](https://github.com/sparkycz1/honeypot-shelf/wiki/Development)). This file only covers getting a
fresh instance running.

> [!NOTE]
> A honeypot is managed exactly like a machine in
> [debcontrol](https://github.com/sparkycz1/debcontrol) — terminal, facts,
> packages, system updates, power, scheduling — plus this project's own
> addition: honeypots push OpenCanary events in, and the Dashboard sums
> them per company. See [Home](https://github.com/sparkycz1/honeypot-shelf/wiki/Home)'s "Current state"
> section for exact coverage and open questions.

## 🚀 Quick start (Docker)

**Recommended — one interactive script does everything:**

```bash
git clone https://github.com/sparkycz1/honeypot-shelf.git
cd honeypot-shelf
python3 scripts/setup.py
```

It generates every secret, asks a handful of questions (timezone, whether
to use the bundled Caddy reverse proxy, background-check intervals, the
superadmin password — or auto-generates one — and the host port), then
applies the DB migration, brings the stack up, and creates the first
superadmin account for you. Full details:
[Installation](https://github.com/sparkycz1/honeypot-shelf/wiki/Installation).

**Manual setup**, if you'd rather configure everything by hand:

```bash
cp .env.example .env
python3 scripts/generate_secrets.py
```

Paste the printed values into `.env`, then see
[Installation](https://github.com/sparkycz1/honeypot-shelf/wiki/Installation) for the rest (applying the DB
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

See [Installation](https://github.com/sparkycz1/honeypot-shelf/wiki/Installation) for the full walkthrough
and [Installation#updating](https://github.com/sparkycz1/honeypot-shelf/wiki/Installation#updating) for
upgrading later. See [Development](https://github.com/sparkycz1/honeypot-shelf/wiki/Development) for
running the test suite, linting/type-checking, adding a migration, and
other project conventions.

## 🔒 Security

See [.github/SECURITY.md](.github/SECURITY.md) — supported versions and how to report a vulnerability.

## 📄 License

[PolyForm Noncommercial 1.0.0](LICENSE) — free for any noncommercial
purpose (personal, research, nonprofit/educational/public use, ...).
Commercial use isn't a permitted purpose under this license and needs a
separate agreement with the licensor first — open an issue or reach out
directly.
