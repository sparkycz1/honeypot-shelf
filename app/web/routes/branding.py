"""Serves a custom logo/favicon from a local filesystem path, when
`LOGO_SOURCE`/`FAVICON_SOURCE` (see `app.core.config.Settings`) point at a
file rather than a URL. Public (see `_PUBLIC_PREFIXES` in
`app.auth.middleware`) — the login page needs the logo before a session
exists.

The path served here comes only from this deployment's own environment,
never from the request, so this isn't an arbitrary-file-read endpoint
despite reading from disk by path — there is no user-supplied path
component at all, just two fixed routes.
"""

from __future__ import annotations

import mimetypes

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse

from app.core.config import get_settings
from app.web.branding import resolve_local_branding_path

router = APIRouter()


@router.get("/branding/logo", include_in_schema=False)
async def branding_logo() -> FileResponse:
    path = resolve_local_branding_path(get_settings().logo_source)
    if path is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    return FileResponse(path, media_type=media_type)


@router.get("/branding/favicon", include_in_schema=False)
async def branding_favicon() -> FileResponse:
    path = resolve_local_branding_path(get_settings().favicon_source)
    if path is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    return FileResponse(path, media_type=media_type)
