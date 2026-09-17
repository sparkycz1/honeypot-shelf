"""FastAPI application entry point."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import redis.asyncio as aioredis
from fastapi import FastAPI, Request, Response
from fastapi.openapi.utils import get_openapi
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.auth.middleware import require_auth
from app.core.app_settings import get_or_create_app_settings
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.proxy_headers import ProxyHeadersMiddleware
from app.core.security import decrypt_secret
from app.core.version import APP_VERSION
from app.db.models.app_settings import VpnProvider
from app.db.session import AsyncSessionLocal
from app.scheduling.builtin_actions import register_builtin_actions
from app.services import netbird, wireguard
from app.web.routes import (
    api_docs,
    api_v1,
    api_v1_account,
    api_v1_audit,
    api_v1_dashboard,
    api_v1_events,
    api_v1_scheduling,
    api_v1_settings,
    api_v1_users,
    audit,
    auth,
    branding,
    companies,
    dashboard,
    honeypots,
    impersonation,
    inform,
    initialize,
    initialize_ws,
    live_ws,
    notifications,
    scheduling,
    terminal_ws,
    theme,
    users,
)
from app.web.routes import (
    map as map_routes,
)
from app.web.routes import (
    settings as settings_routes,
)

settings = get_settings()
configure_logging(settings.log_level)
# Populates app.scheduling.actions' registry — the "New scheduled task"
# form reads from it. Idempotent, and also called from
# app.scheduling.jobs (and again in each forked Celery worker child) so
# the worker processes have it too without needing to import this module.
register_builtin_actions()

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "web" / "static"

# Strict CSP: no inline scripts/styles, no external CDN (htmx and Swagger UI
# are both vendored locally). See wiki/Architecture.md.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)


def _custom_openapi(app: FastAPI) -> dict[str, Any]:
    """Injects a `bearerAuth` security scheme into the generated OpenAPI
    schema, so Swagger UI (`GET /api`) shows an "Authorize" button and sends
    `Authorization: Bearer <token>` on every "Try it out" request under
    `/api/v1/...`. See debcontrol's identically-named function this is
    copied from for the full reasoning — unchanged here."""
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title=app.title, version=app.version, description=app.description, routes=app.routes
    )
    schema.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "description": "A per-user API token, created at /account.",
    }
    for path, operations in schema.get("paths", {}).items():
        if not path.startswith("/api/v1/"):
            continue
        for operation in operations.values():
            if isinstance(operation, dict):
                operation["security"] = [{"bearerAuth": []}]

    app.openapi_schema = schema
    return schema


logger = logging.getLogger(__name__)


async def _reconnect_vpn_if_configured() -> None:
    """Best-effort, fire-and-forget: reconnect whichever VPN provider (see
    Settings -> VPN, `AppSettings.vpn_provider`) was active before, after a
    restart/redeploy — otherwise a honeypot only reachable over it stays
    unreachable until someone notices and clicks Connect again. Never
    raises — the app must still start normally with no VPN sidecar at all
    (the common case, since it's an optional overlay), and a failed
    reconnect just leaves the status badge showing disconnected/
    unavailable, same as any other integration that isn't currently
    working.

    For NetBird specifically: only re-runs `netbird up --setup-key ...` when
    the daemon *isn't* already connected. The sidecar's own state
    (`/etc/netbird`, a named volume — see `docker-compose.vpn.yml`) usually
    survives a `web`/`worker` restart on its own and the daemon reconnects
    the already-registered peer by itself; blindly resending the stored
    setup key on every startup fails once that key (single-use on NetBird's
    side) has already been consumed by the first successful registration —
    seen in the wild as a `setup key is invalid` retry loop in the NetBird
    log after a plain container restart that changed nothing else."""
    try:
        async with AsyncSessionLocal() as db:
            app_settings = await get_or_create_app_settings(db)
            provider = app_settings.vpn_provider
            if provider == VpnProvider.NETBIRD and app_settings.netbird_setup_key_encrypted:
                current_status = await netbird.status()
                if current_status.connected:
                    logger.info("NetBird already connected on startup — leaving it as is.")
                else:
                    await netbird.connect(
                        setup_key=decrypt_secret(app_settings.netbird_setup_key_encrypted),
                        management_url=app_settings.netbird_management_url,
                        hostname=app_settings.netbird_hostname,
                    )
                    logger.info("Reconnected to NetBird on startup.")
            elif provider == VpnProvider.WIREGUARD and app_settings.wireguard_config_encrypted:
                await wireguard.connect(
                    config=decrypt_secret(app_settings.wireguard_config_encrypted)
                )
                logger.info("Reconnected WireGuard on startup.")
    except Exception:
        logger.warning("Could not reconnect the configured VPN on startup.", exc_info=True)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    # One long-lived Redis connection pool for the login rate limiter
    # (app.auth.rate_limit) — nothing to do with the Celery broker, which
    # talks to Redis from the worker processes on its own.
    app.state.redis = aioredis.from_url(settings.redis_url)  # type: ignore[no-untyped-call]
    # The auth middleware (app.auth.middleware) needs a DB session but runs
    # outside FastAPI's dependency injection — this is what it opens one
    # from. Kept on app.state rather than imported directly so tests can
    # point it at their own SQLite engine.
    app.state.db_session_factory = AsyncSessionLocal
    # Fire-and-forget, not awaited — a slow/unavailable netbird daemon must
    # never delay the app itself from becoming ready.
    reconnect_task = asyncio.ensure_future(_reconnect_vpn_if_configured())
    try:
        yield
    finally:
        reconnect_task.cancel()
        await app.state.redis.aclose()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Honeypot Shelf",
        description=(
            "Management and monitoring overview for a fleet of OpenCanary "
            "honeypots, across multiple companies — see /api for interactive docs."
        ),
        version=APP_VERSION,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        # Disabled here too (`None`) — `app/web/routes/api_docs.py` defines
        # its own `GET /openapi.json` instead, gated the same way `GET
        # /api` is (write access AND `User.api_access_enabled`), since
        # FastAPI's own built-in route accepts no `Depends` to add that
        # check to. Ported from debcontrol (see that project's own
        # `app/web/routes/api_docs.py` docstring for the full reasoning) —
        # this app's own `/api` was already gated, but `/openapi.json`
        # itself was only ever session-login-gated (by the auth
        # middleware, same as any other page), letting any logged-in user
        # — including a READ-only company account, or a write account with
        # `api_access_enabled=False` — fetch the complete endpoint map
        # regardless.
        openapi_url=None,
    )
    app.openapi = lambda: _custom_openapi(app)  # type: ignore[method-assign]

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Registered first so it ends up outermost (see the `require_auth`
    # comment below for why registration order maps to layering here) —
    # every other middleware, and every route/WebSocket handler, needs to
    # see the corrected scheme, not just the ones that happen to run after
    # some other check. See app.core.proxy_headers's own module docstring
    # for what this fixes and why trusting it is safe.
    app.add_middleware(
        ProxyHeadersMiddleware,
        trust_all=settings.trust_all_proxies,
        trusted_networks=settings.trusted_proxy_networks,
        trust_forwarded_for=settings.trust_forwarded_for,
    )

    # Starlette's own session middleware — used *only* to carry OIDC's
    # `state`/`nonce` across the redirect to/from the provider. Unrelated to
    # the app's own login sessions (app.auth.sessions, a DB row + a separate
    # cookie).
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key.get_secret_value(),
        session_cookie="oidc_flow",
        same_site="lax",
        https_only=settings.is_production,
        max_age=600,
    )

    # Registered before `security_headers` below so that middleware ends up
    # *outermost* (Starlette wraps middleware in reverse registration order)
    # — meaning it still gets to add CSP/etc. headers to a response
    # `require_auth` returns directly (a redirect to /login), not just to
    # ones that reached a route.
    @app.middleware("http")
    async def _require_auth(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        return await require_auth(request, call_next)

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if settings.is_production:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response

    app.include_router(api_docs.router)
    app.include_router(auth.router)
    app.include_router(branding.router)
    app.include_router(dashboard.router)
    app.include_router(map_routes.router)
    app.include_router(honeypots.router)
    app.include_router(companies.router)
    app.include_router(initialize.router)
    app.include_router(scheduling.router)
    app.include_router(audit.router)
    app.include_router(inform.router)
    app.include_router(api_v1.router)
    app.include_router(api_v1_scheduling.router)
    app.include_router(api_v1_users.router)
    app.include_router(api_v1_audit.router)
    app.include_router(api_v1_settings.router)
    app.include_router(api_v1_dashboard.router)
    app.include_router(api_v1_events.router)
    app.include_router(api_v1_account.router)
    app.include_router(users.router)
    app.include_router(impersonation.router)
    app.include_router(notifications.router)
    app.include_router(settings_routes.router)
    app.include_router(theme.router)
    # No HTTP dependency here — WebSocket connections never go through
    # `app.auth.middleware`, so each of these routers does its own auth
    # entirely inside the handler. See terminal_ws.py's module docstring.
    app.include_router(terminal_ws.router)
    app.include_router(initialize_ws.router)
    app.include_router(live_ws.router)

    @app.get("/", include_in_schema=False)
    async def root() -> Response:
        return RedirectResponse(url="/dashboard")

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
