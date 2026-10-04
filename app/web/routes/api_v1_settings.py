"""REST API for Settings — deliberately a read-only subset of what
`app/web/routes/settings.py` exposes, superadmin-only (matching the web
page). What's exposed and why, and what's deliberately excluded, mirrors
debcontrol's own reasoning verbatim:

- **Version/commit info** and the **SSH public key/fingerprint** — safe to
  read over a bearer-token API; the public key is *meant* to be copied
  elsewhere (into `authorized_keys`).
- **Background-check intervals**, **audit log retention** and the **sign-in
  policy** (session lifetime, lockout, allowed networks) — operational
  facts, not secrets. Read-only like everything here: a wrong network
  allowlist locks every browser *and* every API token out at once, and
  the web form refuses a list that excludes the address saving it — a
  safeguard a script running from somewhere else wouldn't get.

What's deliberately **not** exposed here, even to a superadmin token:

- **Rotating the SSH key** (`/settings/ssh-key/...`) — a multi-step,
  human-in-the-loop process (generate, manually copy the public half onto
  every honeypot's `authorized_keys`, then activate) specifically designed
  so the app is never locked out of a honeypot mid-rotation. Left as a
  deliberately web-UI-only, human-paced action.
- **LDAP/OIDC configuration** — carries encrypted secrets and changes how
  *every* login on the instance is authenticated; a bug or a stolen token
  reconfiguring the login provider is a much bigger blast radius than
  anything else this API can do.
- **Syslog forwarding configuration** — a live security-monitoring
  integration point; left for the web UI, pending an explicit ask.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_api_superadmin
from app.core.app_settings import effective_event_retention_days, get_or_create_app_settings
from app.core.version import APP_VERSION, commit_url, get_git_commit
from app.db.session import get_db
from app.ssh.identity import get_or_create_identity

router = APIRouter(prefix="/api/v1/settings")

_view = Depends(require_api_superadmin)


@router.get("", dependencies=[_view])
async def get_settings_api(db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    identity = await get_or_create_identity(db)
    app_settings = await get_or_create_app_settings(db)
    git_commit = get_git_commit()
    return {
        "app_version": APP_VERSION,
        "git_commit": git_commit,
        "git_commit_url": commit_url(git_commit) if git_commit else None,
        "ssh_public_key": identity.public_key,
        "ssh_fingerprint": identity.fingerprint,
        "ssh_pending_fingerprint": identity.pending_fingerprint,
        "facts_refresh_interval_seconds": app_settings.facts_refresh_interval_seconds,
        "update_timeout_seconds": app_settings.update_timeout_seconds,
        "ssh_connect_timeout": app_settings.ssh_connect_timeout,
        "audit_log_retention_days": app_settings.audit_log_retention_days,
        # The value in force: Settings when set there, else EVENT_RETENTION_DAYS.
        "event_retention_days": effective_event_retention_days(app_settings),
        "session_idle_timeout_minutes": app_settings.session_idle_timeout_minutes,
        "session_absolute_max_hours": app_settings.session_absolute_max_hours,
        "login_max_failed_attempts": app_settings.login_max_failed_attempts,
        "login_lockout_minutes": app_settings.login_lockout_minutes,
        "login_allowed_networks": (app_settings.login_allowed_networks or "").split() or [],
    }
