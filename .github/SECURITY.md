# 🔒 Security Policy

## Supported versions

Only the **latest released version** (the most recent [tag/release](https://github.com/sparkycz1/honeypot-shelf/releases)) is supported with security fixes. There are no maintained older branches — upgrade to the latest release before reporting an issue, and after a fix ships.

| Version | Supported |
|---|---|
| Latest release | ✅ |
| Anything older | ❌ |

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.** Instead, open a private draft security advisory: this repository's **Security** tab → **Advisories** → **Report a vulnerability** / **New draft security advisory**.

Include, if known:
- The affected version/commit.
- Steps to reproduce, or a proof of concept.
- The impact you'd expect (what an attacker could actually do).

## Scope

This is a self-hosted overview/monitoring tool for a fleet of honeypots across multiple companies — the threat model and existing safeguards are documented in the wiki:

- [Architecture → Security model](../wiki/Architecture.md#-security-model) — CSRF, headers, secrets at rest, FIPS alignment.
- [Authentication & RBAC](../wiki/Authentication-RBAC.md) — logins, sessions, company scoping, Impersonate.
- [Audit Log](../wiki/Audit-Log.md) — the hash-chained audit trail.

Dependency vulnerabilities are tracked automatically via [Dependabot](dependabot.yml) (alerts and security updates are enabled on this repository).
