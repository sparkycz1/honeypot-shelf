"""Shared Jinja2 templates instance (kept separate from `app.main` so it can be
imported from routers without a circular dependency)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import mistune
from fastapi import Request
from fastapi.templating import Jinja2Templates
from jinja2 import pass_context
from jinja2.runtime import Context
from markupsafe import Markup

from app.core.config import get_settings
from app.core.version import APP_VERSION, get_git_commit
from app.i18n import get_locale
from app.i18n import translate as _translate
from app.services.geoip_display import country_flag
from app.services.opencanary_logtypes import localized_logtype_label, logtype_label
from app.web import branding
from app.web.os_logos import badge_for

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.autoescape = True


@lru_cache
def _display_zone(tz_name: str) -> ZoneInfo:
    """`lru_cache`d per zone name so a template rendering many timestamps
    in a loop doesn't re-resolve the zone database on every one. Falls
    back to UTC for an unset or unrecognized `TZ` — see `Settings.tz`."""
    try:
        return ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def local_time(value: datetime | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    """Render a stored datetime in the configured `TZ` (default UTC).

    Every datetime this app writes to the DB is UTC, naive or not — a naive
    one is treated as UTC rather than local time. Include `%Z` in `fmt` to
    print the zone's abbreviation instead of hardcoding "UTC" in the
    template. Returns "—" for `None` so callers don't need their own
    `if value else "—"` ternary.
    """
    if value is None:
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(_display_zone(get_settings().tz)).strftime(fmt)


templates.env.filters["local_time"] = local_time


def format_uptime(seconds: int | None) -> str:
    """Render a honeypot's uptime as e.g. "12d 3h 4m" — the DB only stores
    the raw second count (`Honeypot.uptime_seconds`, from `/proc/uptime`)."""
    if seconds is None:
        return "—"
    days, remainder = divmod(int(seconds), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


templates.env.filters["format_uptime"] = format_uptime

templates.env.filters["os_badge"] = badge_for


def iso_list(timestamps: list[datetime]) -> list[str]:
    """`[t.isoformat() for t in timestamps]` — Jinja's `map` filter can read
    an attribute but not call a method, so this is the plain way to turn a
    list of datetimes into JS-parseable strings for `tojson` below (used by
    the Dashboard/Honeypot event-volume chart's hover data attributes)."""
    return [t.isoformat() for t in timestamps]


templates.env.filters["iso_list"] = iso_list

# `HoneypotEvent.event_type` (and OpenCanary's own raw `logtype`) is just a
# bare integer as a string, e.g. "4002" — see
# `app.services.opencanary_logtypes` for the full id -> label mapping and
# why it lives there rather than in the model itself. A `pass_context`
# filter (not a plain function like every other filter here) specifically
# so every `{{ event.event_type | canary_label }}` call site keeps working
# unchanged while still reading `request` out of the template's own
# context to localize through — found live: this was hardcoded English on
# the Dashboard's recent-events list even on an otherwise fully-translated
# Czech page. Falls back to the plain English label if `request` somehow
# isn't in context (never true for a real request, only a template
# rendered without one, e.g. a unit test).
@pass_context
def _canary_label_filter(context: Context, logtype: object) -> str:
    request = context.get("request")
    if request is None:
        return logtype_label(logtype)
    return localized_logtype_label(lambda key: t(request, key), logtype)


templates.env.filters["canary_label"] = _canary_label_filter


def tojson_filter(value: object) -> Markup:
    """A minimal `tojson`, since plain `jinja2.Environment` (unlike Flask's)
    doesn't ship one. Escapes the characters that would otherwise break out
    of an HTML attribute or a `<script>` block — same character set Flask's
    own `tojson` escapes — so the result is safe to drop straight into a
    single- or double-quoted attribute, e.g. `data-series='{{ x | tojson }}'`.
    """
    raw = json.dumps(value, default=str)
    escaped = (
        raw.replace("&", "\\u0026")
        .replace("'", "\\u0027")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
    return Markup(escaped)  # noqa: S704 - hand-escaped above, not raw interpolation


templates.env.filters["tojson"] = tojson_filter


# Deliberately NOT the `mistune.html` module-level convenience callable —
# that preset has `escape=False` (raw HTML in the source passes straight
# through unescaped), the opposite of what a stored-content renderer
# needs. `escape=True` here is what actually escapes a `<script>` in the
# source to inert text rather than executing it.
_markdown = mistune.create_markdown(escape=True)


def markdown_filter(text: str | None) -> Markup:
    """Renders `text` as Markdown to HTML — used for `Company.notes` and
    `Honeypot.notes`. Raw HTML in the source is escaped to plain text, not
    passed through — notes are admin-authored (only `READ_WRITE`/superadmin
    accounts can edit one) but there's no reason to trust it with markup
    injection just because of that; `javascript:`-scheme links are likewise
    stripped by mistune's own default link-safety check. `None`/empty
    renders as an empty string rather than an error, so a template can call
    this unconditionally."""
    if not text:
        return Markup("")
    html = _markdown(text)
    assert isinstance(html, str)
    return Markup(html)  # noqa: S704 - escape=True above, not raw interpolation


templates.env.filters["markdown"] = markdown_filter


def t(request: Request, key: str, **kwargs: object) -> str:
    """`{{ t(request, "nav.dashboard") }}` — the current request's language
    (`request.state.locale`, set by `app.auth.middleware` on every request,
    public or not) applied to `key`. See `app.i18n`'s module docstring for
    the lookup/fallback rules and the file format a new language file
    needs. `getattr(..., None)` rather than a direct attribute read: a
    handful of error-page renders (e.g. a raised `HTTPException` before the
    middleware runs, or a test hitting a route through a bare ASGI call)
    have no `request.state.locale` at all, and this should degrade to
    English then, not throw."""
    locale = getattr(request.state, "locale", None) or get_locale(None)
    return _translate(locale, key, **kwargs)


templates.env.globals["t"] = t

templates.env.globals["branding_logo_url"] = branding.logo_url
templates.env.globals["branding_favicon_url"] = branding.favicon_url

# Footer (base.html) — same values settings/_general.html's "Version" panel
# used to show before that panel was removed in favor of the footer.
templates.env.globals["app_version"] = APP_VERSION
templates.env.globals["git_commit"] = get_git_commit

# A flag emoji from a 2-letter country code — see app.services.geoip_display
# for why this and the GeoIP lookups themselves are kept separate modules.
templates.env.globals["geoip_flag"] = country_flag
