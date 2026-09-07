"""FastAPI application entry point."""

from __future__ import annotations

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
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.version import APP_VERSION
from app.db.session import AsyncSessionLocal
from app.scheduling.builtin_actions import register_builtin_actions
from app.web.routes import (
    api_docs,
    api_v1,
    api_v1_account,
    api_v1_audit,
    api_v1_dashboard,
    api_v1_scheduling,
    api_v1_settings,
    api_v1_users,
    audit,
    auth,
    companies,
    dashboard,
    honeypots,
    inform,
    ingest,
    live_ws,
    scheduling,
    terminal_ws,
    theme,
    users,
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
    try:
        yield
    finally:
        await app.state.redis.aclose()


def create_app() -> FastAPI:
    app = FastAPI(
        title="HoneyHive",
        description=(
            "Management and monitoring overview for a fleet of OpenCanary "
            "honeypots, across multiple companies — see /api for interactive docs."
        ),
        version=APP_VERSION,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json",
    )
    app.openapi = lambda: _custom_openapi(app)  # type: ignore[method-assign]

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

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
    app.include_router(dashboard.router)
    app.include_router(honeypots.router)
    app.include_router(companies.router)
    app.include_router(scheduling.router)
    app.include_router(audit.router)
    app.include_router(inform.router)
    app.include_router(ingest.router)
    app.include_router(api_v1.router)
    app.include_router(api_v1_scheduling.router)
    app.include_router(api_v1_users.router)
    app.include_router(api_v1_audit.router)
    app.include_router(api_v1_settings.router)
    app.include_router(api_v1_dashboard.router)
    app.include_router(api_v1_account.router)
    app.include_router(users.router)
    app.include_router(settings_routes.router)
    app.include_router(theme.router)
    # No HTTP dependency here — WebSocket connections never go through
    # `app.auth.middleware`, so each of these routers does its own auth
    # entirely inside the handler. See terminal_ws.py's module docstring.
    app.include_router(terminal_ws.router)
    app.include_router(live_ws.router)

    @app.get("/", include_in_schema=False)
    async def root() -> Response:
        return RedirectResponse(url="/dashboard")

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
