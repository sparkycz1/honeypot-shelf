"""The ASGI middleware that puts auth in front of every page.

Registered in `app.main` — see that module's comment on middleware
ordering for why it has to be registered *before* the security-headers
middleware (so CSP etc. still land on a redirect-to-login response, not
just on responses that reached a real route).

Two things happen on every request, public or not:

1. A CSRF token is ensured (`app.core.csrf`) and stashed on
   `request.state.csrf_token` — this lets `base.html` (and the login pages)
   render a token-carrying form without every route needing its own
   `get_or_create_csrf_token`/`set_csrf_cookie` dance just for that.
2. `request.state.locale` is set to the default (English) — overwritten
   below with the session's own account's chosen language, if any — so
   every template can call `t(request, "some.key")` unconditionally,
   logged in or not. See `app.i18n`'s module docstring.

Everything *not* on the public allowlist below requires a valid session
(`app.auth.sessions`); `request.state.user`/`request.state.session` are
set from it for the rest of the request. A missing/expired/revoked session
redirects to `/login?next=<path>`.

Unlike debcontrol, TOTP/passkey enrollment is purely self-service here —
there is no per-role `require_totp` (there are no roles at all, see
`app.db.models.user`'s module docstring) forcing a mid-session redirect
into enrollment. An account either has a second factor enrolled or it
doesn't; nothing here blocks a request over that.

This opens its own DB session via `request.app.state.db_session_factory`
rather than FastAPI's `Depends(get_db)` — middleware runs outside the
dependency-injection system. The factory is on `app.state` (see
`app.main`'s `lifespan`) rather than imported directly so tests can point
it at their own SQLite engine (see `tests/conftest.py`).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from urllib.parse import quote

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse

from app.auth.sessions import SESSION_COOKIE_NAME, get_valid_session
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie
from app.i18n import get_locale

# Reachable with no session at all. Exact paths, plus two prefixes below.
_PUBLIC_PATHS = frozenset(
    {
        "/login",
        "/login/password",
        "/login/totp",
        "/login/webauthn/options",
        "/login/webauthn/verify",
        "/logout",
        "/healthz",
        "/auth/oidc/login",
        "/auth/oidc/callback",
    }
)
# `/static/`: CSS/JS/the vendored htmx build — the login page needs these
# too. `/api/`: machine-to-machine endpoints (event ingest from a honeypot,
# and the token-authenticated REST API) authenticated with their own
# bearer token, not a user session at all. `/branding/`: a deployment's
# optional custom logo/favicon (app.web.routes.branding) — same reasoning
# as `/static/`, the login page needs it too.
_PUBLIC_PREFIXES = ("/static/", "/api/", "/branding/")


def _is_public(path: str) -> bool:
    return path in _PUBLIC_PATHS or path.startswith(_PUBLIC_PREFIXES)


def _redirect_to_login(request: Request) -> Response:
    next_path = request.url.path
    if request.url.query:
        next_path += f"?{request.url.query}"
    login_url = f"/login?next={quote(next_path, safe='')}"
    if request.headers.get("HX-Request") == "true":
        # A plain redirect response to an htmx-driven request gets its HTML
        # swapped into whatever element made the request, not navigated.
        # HX-Redirect tells htmx to navigate the whole page instead.
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": login_url})
    return RedirectResponse(url=login_url, status_code=status.HTTP_303_SEE_OTHER)


async def require_auth(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    csrf_token, new_csrf_cookie = get_or_create_csrf_token(request)
    request.state.csrf_token = csrf_token
    # Default for every request, including the login page and every other
    # public/anonymous one — there's no account yet to have a preference.
    # Overwritten below once a session resolves to one that has chosen a
    # non-default language. See app.i18n's module docstring.
    request.state.locale = get_locale(None)

    if not _is_public(request.url.path):
        session = None
        raw_token = request.cookies.get(SESSION_COOKIE_NAME)
        if raw_token:
            db_session_factory = request.app.state.db_session_factory
            async with db_session_factory() as db:
                session = await get_valid_session(db, raw_token)

        if session is None:
            if request.headers.get("accept", "").startswith("application/json"):
                response: Response = JSONResponse(
                    {"detail": "Not authenticated."}, status_code=status.HTTP_401_UNAUTHORIZED
                )
            else:
                response = _redirect_to_login(request)
            if new_csrf_cookie:
                set_csrf_cookie(response, new_csrf_cookie)
            return response

        request.state.user = session.user
        request.state.session = session
        request.state.locale = get_locale(session.user.locale)

    response = await call_next(request)
    if new_csrf_cookie:
        set_csrf_cookie(response, new_csrf_cookie)
    return response
