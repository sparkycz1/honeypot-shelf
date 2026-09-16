"""Resolves a deployment's optional custom logo/favicon
(`LOGO_SOURCE`/`FAVICON_SOURCE`, see `app.core.config.Settings`) into a URL
templates can drop straight into `<img src>`/`<link rel="icon" href>`.

Each setting is either:

- a URL (`http://`/`https://`) or an already site-relative path
  (`/static/...`, `/branding/...`, `data:...`) — used as-is, no request to
  this app involved beyond fetching it normally;
- a filesystem path readable inside the `web` container — served by
  `app.web.routes.branding` at a fixed URL (`/branding/logo` /
  `/branding/favicon`). The path itself comes only from this deployment's
  own `.env`/environment, never from a request, so serving "by path" here
  isn't an arbitrary-file-read endpoint the way it would be if the path
  came from user input.

`None` means "not configured" — callers fall back to the built-in mark.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

from app.core.config import get_settings

LOGO_ROUTE = "/branding/logo"
FAVICON_ROUTE = "/branding/favicon"

# The built-in honeycomb mark, standalone (no page CSS to inherit from —
# this is a separate document the browser tab fetches on its own).
# Outline-only in the brand's fixed amber: unlike a filled shape, a stroke
# alone reads fine against both a light and a dark browser tab background,
# so this needs no `prefers-color-scheme` trick the way a filled mark
# would (see app/web/templates/partials/_brand_mark.html, the same shape
# used inline in the app itself).
_FAVICON_SVG = """\
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" fill="none"
     stroke="#e0a761" stroke-width="6" stroke-linejoin="round" stroke-linecap="round">
<polygon points="50,2 70.78,14 70.78,38 50,50 29.22,38 29.22,14"/>
<polygon points="29.22,38 50,50 50,74 29.22,86 8.44,74 8.44,50"/>
<polygon points="70.78,38 91.56,50 91.56,74 70.78,86 50,74 50,50"/>
</svg>"""

DEFAULT_FAVICON_DATA_URI = "data:image/svg+xml," + quote(_FAVICON_SVG)


def _is_url(source: str) -> bool:
    return source.startswith(("http://", "https://", "data:"))


def resolve_local_branding_path(source: str | None) -> Path | None:
    """`source` as an existing local file to serve, or `None` if it's
    unset, an `http(s)://`/`data:` URL (nothing to serve — the template
    links to it directly), or doesn't exist on disk. Used by
    `app.web.routes.branding`, not by templates.

    Deliberately keyed on "does this file exist", not on whether `source`
    starts with `/` — an absolute filesystem path (`/app/branding/logo.svg`)
    and a site-relative URL (`/static/img/logo.png`) both start with `/` on
    Linux, so a leading slash alone can't tell them apart; only one of them
    resolves to a real file inside this container."""
    if not source or _is_url(source):
        return None
    path = Path(source)
    return path if path.is_file() else None


def resolve_branding_url(source: str | None, *, served_route: str) -> str | None:
    """`source` as configured in `.env` → a URL to actually use, or `None`
    if unset. `served_route` is `/branding/logo` or `/branding/favicon` —
    what an existing local file resolves to (the route itself re-reads
    `source` from `Settings` at request time, see
    `app.web.routes.branding`). Anything else — an `http(s)://`/`data:` URL,
    or a site-relative reference like `/static/img/logo.png` that isn't a
    real file inside this container — is used directly, unchanged."""
    if not source:
        return None
    if resolve_local_branding_path(source) is not None:
        return served_route
    return source


def logo_url() -> str | None:
    return resolve_branding_url(get_settings().logo_source, served_route=LOGO_ROUTE)


def favicon_url() -> str:
    """Unlike `logo_url()`, this never returns `None` — a `<link rel=
    icon>` needs *something*, so an unconfigured `FAVICON_SOURCE` falls
    back to the built-in mark (`DEFAULT_FAVICON_DATA_URI`) rather than
    leaving the caller to handle "no favicon" as a separate case."""
    return (
        resolve_branding_url(get_settings().favicon_source, served_route=FAVICON_ROUTE)
        or DEFAULT_FAVICON_DATA_URI
    )
