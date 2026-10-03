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

import httpx2
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
# Tests swap in an `httpx2.MockTransport`; None means the real network.
_transport: httpx2.AsyncBaseTransport | None = None


def _image_type(url: str, header: str) -> str | None:
    """The response's media type if it is an image, else None — a logo is
    served from this app's own origin, so a remote server (or a redirect
    target) answering with HTML or anything else must not be passed
    through as if it were ours."""
    content_type = header.split(";")[0].strip().lower()
    if not content_type or content_type == "application/octet-stream":
        content_type = (mimetypes.guess_type(url)[0] or "").lower()
    return content_type if content_type.startswith("image/") else None


async def _fetch_remote(url: str) -> tuple[bytes, str] | None:
    if url in _remote_cache:
        return _remote_cache[url]
    result: tuple[bytes, str] | None = None
    try:
        async with (
            httpx2.AsyncClient(
                timeout=_FETCH_TIMEOUT_SECONDS, follow_redirects=True, transport=_transport
            ) as client,
            client.stream("GET", url) as response,
        ):
            response.raise_for_status()
            content_type = _image_type(url, response.headers.get("content-type", ""))
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > _MAX_BYTES:
                    break
        if content_type is None:
            logger.warning("Branding URL %s did not return an image — ignoring.", url)
        elif len(body) > _MAX_BYTES:
            logger.warning("Branding URL %s is larger than %d bytes — ignoring.", url, _MAX_BYTES)
        else:
            result = (bytes(body), content_type)
    except httpx2.HTTPError as exc:
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
