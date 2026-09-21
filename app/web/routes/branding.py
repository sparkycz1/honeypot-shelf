"""Serves a deployment's custom logo/favicon (`LOGO_SOURCE`/
`FAVICON_SOURCE`, see `app.core.config.Settings`) from this app's own
origin — from a local filesystem path readable inside the `web`
container, or fetched once from a remote `http(s)://` URL and cached in
memory for the life of this process (`Settings` themselves are resolved
once per process too — see `app.core.config.get_settings`'s own
`lru_cache` — so re-fetching on every request would just repeat the same
round trip for no benefit; a changed `LOGO_SOURCE`/`FAVICON_SOURCE` needs
a restart to take effect either way). Public (see `_PUBLIC_PREFIXES` in
`app.auth.middleware`) — the login page needs the logo before a session
exists.

Never linked to directly from a template — see `app.web.branding`'s own
module docstring for why (this app's CSP only allows `img-src 'self'
data:;`, so a remote logo has to come from this app's own origin, not a
third-party one, to load at all).

The local path/remote URL served here comes only from this deployment's
own environment, never from the request, so this isn't an arbitrary-
file-read/SSRF endpoint despite reading from disk or fetching a URL by
"path" — there is no user-supplied path/URL component at all, just two
fixed routes reading a fixed, operator-set config value.
"""

from __future__ import annotations

import logging
import mimetypes

import httpx
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse, Response

from app.core.config import get_settings
from app.web.branding import is_remote_url, resolve_local_branding_path

logger = logging.getLogger(__name__)

router = APIRouter()

_FETCH_TIMEOUT_SECONDS = 10.0
# Generous for a logo/favicon (realistically a few KB to a few hundred
# KB) while still bounding memory/time spent on a misconfigured
# LOGO_SOURCE/FAVICON_SOURCE pointing at something much bigger.
_MAX_BYTES = 5 * 1024 * 1024

# Keyed by the configured URL itself (not by which route asked) — fetched
# once, kept for the life of this process. `None` means a fetch was tried
# and failed, cached too so a permanently-unreachable URL doesn't retry
# (and re-log a warning) on every single page load.
_remote_cache: dict[str, tuple[bytes, str] | None] = {}


async def _fetch_remote(url: str) -> tuple[bytes, str] | None:
    if url in _remote_cache:
        return _remote_cache[url]
    result: tuple[bytes, str] | None = None
    try:
        async with httpx.AsyncClient(
            timeout=_FETCH_TIMEOUT_SECONDS, follow_redirects=True
        ) as client:
            response = await client.get(url)
            response.raise_for_status()
        if len(response.content) > _MAX_BYTES:
            logger.warning("Branding URL %s is larger than %d bytes — ignoring.", url, _MAX_BYTES)
        else:
            content_type = response.headers.get("content-type", "").split(";")[0].strip()
            if not content_type:
                content_type = mimetypes.guess_type(url)[0] or "application/octet-stream"
            result = (response.content, content_type)
    except httpx.HTTPError as exc:
        logger.warning("Could not fetch branding URL %s: %s", url, exc)
    _remote_cache[url] = result
    return result


async def _serve(source: str | None) -> Response:
    local_path = resolve_local_branding_path(source)
    if local_path is not None:
        media_type = mimetypes.guess_type(local_path.name)[0] or "application/octet-stream"
        return FileResponse(local_path, media_type=media_type)
    if source and is_remote_url(source):
        fetched = await _fetch_remote(source)
        if fetched is not None:
            content, media_type = fetched
            return Response(content=content, media_type=media_type)
    raise HTTPException(status.HTTP_404_NOT_FOUND)


@router.get("/branding/logo", include_in_schema=False)
async def branding_logo() -> Response:
    return await _serve(get_settings().logo_source)


@router.get("/branding/favicon", include_in_schema=False)
async def branding_favicon() -> Response:
    return await _serve(get_settings().favicon_source)
