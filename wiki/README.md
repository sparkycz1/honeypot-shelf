# 📁 About this folder

*The map of the maze, kept next to the maze.*

This directory mirrors the project's **GitHub wiki** (already published:
https://github.com/sparkycz1/honeypot-shelf/wiki, backed by its own
separate git repository, `honeypot-shelf.wiki.git`). Keeping a copy here
means the docs show up in code review/PR diffs like anything else,
instead of changing silently in a repo `git log` on this one never sees.

**The GitHub wiki is the one readers actually browse** — this folder is
the editable source that gets synced there by hand:

```bash
GH_TOKEN=$(gh auth token)
git clone "https://x-access-token:${GH_TOKEN}@github.com/sparkycz1/honeypot-shelf.wiki.git" /tmp/honeypot-shelf.wiki
cp wiki/*.md /tmp/honeypot-shelf.wiki/
rm /tmp/honeypot-shelf.wiki/README.md   # this file itself isn't a wiki page
cd /tmp/honeypot-shelf.wiki
git add -A && git commit -m "Sync wiki" && git push
```

A link from a wiki page to something in the main repo (not another wiki
page) needs a full `https://github.com/sparkycz1/honeypot-shelf/...` URL
(`blob/main/...` for a file, `raw.githubusercontent.com/.../main/...` for
an image) — a relative `../` path only resolves inside *this* repo, not
once the same file is copied into the wiki's own separate one.

## 📑 Pages

- [Home](Home.md) — overview, feature table, current state, and the open
  product questions this project is waiting on
- [Installation](Installation.md) — Docker quick start, with or without Caddy
- [Architecture](Architecture.md) — stack, project layout, the REST API, and
  cross-cutting security essentials — the hub for the four pages below
- [Authentication & RBAC](Authentication-RBAC.md) — logins, sessions, the
  company-membership model, 2FA, Impersonate
- [Honeypot Management](Honeypot-Management.md) — provisioning, VPN, the
  Config tab, the data model, how events arrive, syslog targets
- [Audit Log](Audit-Log.md) — hash-chain integrity, retention, export, SIEM forwarding
- [Notifications](Notifications.md) — rules, scope, wording, the webhook SSRF guard
- [Initialize](Honeypot-Initialize.md) — provisioning a brand new
  Raspberry Pi into a working OpenCanary honeypot over SSH
- [Reverse Proxy: Caddy](Reverse-Proxy-Caddy.md) — using the bundled Caddy service
- [Reverse Proxy: nginx](Reverse-Proxy-Nginx.md) — bring your own nginx
- [Reverse Proxy: Traefik](Reverse-Proxy-Traefik.md) — bring your own Traefik
- [Development](Development.md) — running locally, tests, migrations
