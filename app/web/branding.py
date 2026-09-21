"""Resolves a deployment's optional custom logo/favicon
(`LOGO_SOURCE`/`FAVICON_SOURCE`, see `app.core.config.Settings`) into a URL
templates can drop straight into `<img src>`/`<link rel="icon" href>`.

Each setting is either:

- a remote `http://`/`https://` URL — fetched server-side and re-served
  from this app's own origin at a fixed URL (`/branding/logo` /
  `/branding/favicon`, see `app.web.routes.branding`), never linked to
  directly. This app's CSP is deliberately strict (`img-src 'self'
  data:;` — see `app.main.CONTENT_SECURITY_POLICY`, "no CDN" is a
  documented stance, not an oversight), so a browser would just refuse to
  load a third-party image URL dropped straight into `<img src>`;
- an already site-relative path (`/static/...`, `/branding/...`) or a
  `data:...` URI — used as-is, already same-origin (or self-contained)
  and so already CSP-safe with no fetch needed;
- a filesystem path readable inside the `web` container — also served by
  `app.web.routes.branding`, at the same fixed URLs. The path itself
  comes only from this deployment's own `.env`/environment, never from a
  request, so serving "by path" here isn't an arbitrary-file-read
  endpoint the way it would be if the path came from user input.

`None` means "not configured" — callers fall back to the built-in mark.
"""

from __future__ import annotations

from pathlib import Path

from app.core.config import get_settings

LOGO_ROUTE = "/branding/logo"
FAVICON_ROUTE = "/branding/favicon"

# The built-in honeycomb mark (from the brand sheet), served as a plain
# static file same as any other asset under app/web/static/ — see
# app/web/static/img/icon.png.
DEFAULT_FAVICON_URL = "/static/img/icon.png"


def is_remote_url(source: str) -> bool:
    """A `source` this app has to fetch itself and re-serve from its own
    origin — see this module's own docstring for why a plain `<img src>`
    to it wouldn't load under this app's CSP."""
    return source.startswith(("http://", "https://"))


def resolve_local_branding_path(source: str | None) -> Path | None:
    """`source` as an existing local file to serve, or `None` if it's
    unset, a remote URL or `data:` URI (nothing to read from disk — see
    `is_remote_url`/`app.web.routes.branding`), or doesn't exist on disk.
    Used by `app.web.routes.branding`, not by templates.

    Deliberately keyed on "does this file exist", not on whether `source`
    starts with `/` — an absolute filesystem path (`/app/branding/logo.svg`)
    and a site-relative URL (`/static/img/logo.png`) both start with `/` on
    Linux, so a leading slash alone can't tell them apart; only one of them
    resolves to a real file inside this container."""
    if not source or is_remote_url(source) or source.startswith("data:"):
        return None
    path = Path(source)
    return path if path.is_file() else None


def resolve_branding_url(source: str | None, *, served_route: str) -> str | None:
    """`source` as configured in `.env` → a URL to actually use, or `None`
    if unset. `served_route` is `/branding/logo` or `/branding/favicon` —
    what a remote URL or an existing local file both resolve to (the
    route itself re-reads `source` from `Settings` at request time, see
    `app.web.routes.branding`). A `data:` URI or an already site-relative
    reference (e.g. `/static/img/logo.png`) is used directly, unchanged —
    already same-origin or self-contained, no fetch needed. Checked in
    this order deliberately: an absolute filesystem path
    (`/app/branding/logo.svg`) and a site-relative URL
    (`/static/img/logo.png`) both start with `/` on Linux, so `source`
    only falls through to "used directly" once it's confirmed to be
    neither a remote URL nor an existing local file — see
    `resolve_local_branding_path`'s own docstring."""
    if not source:
        return None
    if source.startswith("data:"):
        return source
    if is_remote_url(source) or resolve_local_branding_path(source) is not None:
        return served_route
    return source


def logo_url() -> str | None:
    return resolve_branding_url(get_settings().logo_source, served_route=LOGO_ROUTE)


def favicon_url() -> str:
    """Unlike `logo_url()`, this never returns `None` — a `<link rel=
    icon>` needs *something*, so an unconfigured `FAVICON_SOURCE` falls
    back to the built-in mark (`DEFAULT_FAVICON_URL`) rather than
    leaving the caller to handle "no favicon" as a separate case."""
    return (
        resolve_branding_url(get_settings().favicon_source, served_route=FAVICON_ROUTE)
        or DEFAULT_FAVICON_URL
    )
