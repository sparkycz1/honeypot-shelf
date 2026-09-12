from __future__ import annotations

import os

# Set these BEFORE importing `app.main` — configuration (`Settings`) is
# validated right at import time, and tests don't run against real
# infrastructure (the DB dependency is swapped for SQLite below; Redis is
# never touched in tests via ASGITransport, since that doesn't trigger
# FastAPI's lifespan; Celery's `apply_async` is monkeypatched away by the
# autouse `celery_calls` fixture below so no broker is contacted either).
os.environ.setdefault("SECRET_KEY", "test-only-secret-key-not-for-real-use-000000")
os.environ.setdefault("ENCRYPTION_KEY", "IYH8EiMlmjkDacPXmvWQgDjTojLMD6GDwD8STyL1x0Y=")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
# Required fields even though DATABASE_URL/REDIS_URL above override them —
# see app.core.config.Settings.
os.environ.setdefault("POSTGRES_PASSWORD", "test-only-not-for-real-use")
os.environ.setdefault("REDIS_PASSWORD", "test-only-not-for-real-use")
os.environ.setdefault("INFORM_TOKEN", "test-only-inform-token-not-for-real-use-000000")

import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
import pytest_asyncio
from celery.app.task import Task
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.auth.security import hash_password
from app.auth.sessions import SESSION_COOKIE_NAME, create_session
from app.db.base import Base
from app.db.models.company import Company
from app.db.models.company_membership import CompanyMembership
from app.db.models.user import AccessLevel, AuthProvider, User
from app.db.session import get_db
from app.main import app

ADMIN_USERNAME = "test-superadmin"


_DEFAULT_TASK_RESULT: Any = {"ok": True, "output": "fake"}


class FakeAsyncResult:
    """Stand-in for `celery.result.AsyncResult` — enough for the handful of
    routes that enqueue a task and then block on its return value."""

    def __init__(self, task_name: str, result: Any = None) -> None:
        self.task_name = task_name
        self._result = result

    def get(self, timeout: float | None = None, **kwargs: Any) -> Any:
        # Routes call this through `asyncio.to_thread(async_result.get,
        # timeout=...)`, so it is deliberately synchronous, like the real one.
        return self._result


class RecordedCeleryCalls(list[tuple[str, tuple[Any, ...], dict[str, Any]]]):
    """Every `(task_name, args, kwargs)` a test's requests enqueued.

    No Celery broker, worker, or Redis exists in tests (they run through
    ASGITransport, which never triggers FastAPI's lifespan either), so
    `Task.apply_async` — what `.delay()` calls underneath — is monkeypatched
    for the whole session to append here and hand back a `FakeAsyncResult`
    instead of publishing a message.

    Set `.result_for[task_name]` to override what a specific task's
    `AsyncResult.get()` returns; anything not overridden gets
    `{"ok": True, "output": "fake"}`.
    """

    def __init__(self) -> None:
        super().__init__()
        self.result_for: dict[str, Any] = {}

    @property
    def names(self) -> list[str]:
        return [name for name, _args, _kwargs in self]


@pytest.fixture(autouse=True)
def celery_calls(monkeypatch: pytest.MonkeyPatch) -> RecordedCeleryCalls:
    """Autouse: every test gets a clean recorder, reachable both as this
    fixture and as `app.state.celery_calls`."""
    recorded = RecordedCeleryCalls()

    def _fake_apply_async(self, args=None, kwargs=None, **options):
        recorded.append((self.name, tuple(args or ()), dict(kwargs or {})))
        result = recorded.result_for.get(self.name, _DEFAULT_TASK_RESULT)
        return FakeAsyncResult(self.name, result)

    monkeypatch.setattr(Task, "apply_async", _fake_apply_async)
    app.state.celery_calls = recorded
    return recorded


class FakeRedis:
    """Stand-in for `app.state.redis` — the plain Redis connection
    `app.main`'s lifespan opens for the login rate limiter (and nothing
    else). Minimal INCR/EXPIRE only, with no real TTL behaviour (counters
    never expire within a test), which is fine since each test gets its own
    fresh instance anyway."""

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}

    async def incr(self, key: str) -> int:
        self._counters[key] = self._counters.get(key, 0) + 1
        return self._counters[key]

    async def expire(self, key: str, seconds: int) -> bool:
        return True


@pytest_asyncio.fixture
async def db_session_factory():
    """Isolated in-memory SQLite DB for each test (no real Postgres).

    Known aiosqlite quirk to watch for when writing a new test: a route
    that UPDATEs a row with an `onupdate=func.now()` column (e.g.
    `User.updated_at`) into a UNIQUE-constraint violation raises
    `sqlalchemy.exc.MissingGreenlet` here instead of the expected
    `IntegrityError` — SQLAlchemy emits an implicit `UPDATE ... RETURNING
    updated_at` for such columns, and a failing RETURNING-augmented UPDATE
    corrupts aiosqlite's greenlet/asyncio bridging. Confirmed to be an
    aiosqlite-only artifact, not a production behavior (production always
    uses asyncpg, a completely different RETURNING/error-handling path —
    see `app.core.config`). Routes that update a unique field check for a
    conflicting row proactively instead of relying on catching
    `IntegrityError` from the commit (see `_duplicate_username_error` in
    `app/web/routes/users.py` and `app/web/routes/api_v1_users.py`)
    specifically so this scenario is testable at all under this fixture —
    follow that pattern for any new "edit to a duplicate unique value"
    test. Ported from an identical fix in debcontrol.
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


async def create_company(db_session_factory: Any, *, name: str = "Acme Corp") -> Company:
    async with db_session_factory() as db:
        company = Company(name=name)
        db.add(company)
        await db.commit()
        await db.refresh(company)
    return company


def _memberships_for(
    company_id: uuid.UUID | None, access_level: AccessLevel | None
) -> list[CompanyMembership]:
    """`company_id`/`access_level` kwargs are kept on every test factory
    below as the common single-company shorthand (most tests only need
    one) — internally always expressed as a `CompanyMembership` list, the
    real shape now that a user can hold any number of them. Pass neither
    for a superadmin (no memberships) or a deliberately company-less
    account."""
    if company_id is None:
        return []
    assert access_level is not None, "company_id needs access_level too"
    return [CompanyMembership(company_id=company_id, access_level=access_level)]


async def _create_user(
    db_session_factory: Any,
    *,
    username: str,
    auth_provider: AuthProvider = AuthProvider.LOCAL,
    is_superadmin: bool = False,
    company_id: uuid.UUID | None = None,
    access_level: AccessLevel | None = None,
    **user_kwargs: Any,
) -> tuple[User, str]:
    """Creates a user (superadmin, or company-scoped with `access_level`)
    plus a real login session — returns (user, raw session token) so a
    test can put the token on whichever `AsyncClient` needs to act as
    them."""
    async with db_session_factory() as db:
        user = User(
            username=username,
            auth_provider=auth_provider,
            is_active=True,
            is_superadmin=is_superadmin,
            memberships=_memberships_for(company_id, access_level),
            **user_kwargs,
        )
        db.add(user)
        await db.flush()

        _session, raw_token = await create_session(
            db, user, ip_address="testclient", user_agent="pytest"
        )
        await db.commit()
        await db.refresh(user)
    return user, raw_token


async def create_local_user(
    db_session_factory: Any,
    *,
    username: str,
    password: str,
    is_superadmin: bool = False,
    company_id: uuid.UUID | None = None,
    access_level: AccessLevel | None = None,
    is_active: bool = True,
    **user_kwargs: Any,
) -> User:
    """For tests that exercise the actual `/login` form (as opposed to
    `client`/`login_as`, which skip it and inject a session directly) — a
    real local account with a real, known password."""
    async with db_session_factory() as db:
        user = User(
            username=username,
            auth_provider=AuthProvider.LOCAL,
            password_hash=hash_password(password),
            is_active=is_active,
            is_superadmin=is_superadmin,
            memberships=_memberships_for(company_id, access_level),
            **user_kwargs,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
    return user


def _configure_app_for_tests(db_session_factory: Any) -> None:
    async def _override_get_db():
        async with db_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.state.redis = FakeRedis()
    # The auth middleware (app.auth.middleware) opens its own DB session
    # from `request.app.state.db_session_factory` rather than through
    # FastAPI's dependency injection — point it at the same SQLite engine
    # `get_db` was just overridden to use, or every request would otherwise
    # try (and fail) to reach the real Postgres `AsyncSessionLocal` is
    # bound to. See app.main's `lifespan` for the production equivalent.
    app.state.db_session_factory = db_session_factory


@pytest_asyncio.fixture
async def client(db_session_factory):
    """An `AsyncClient` already logged in as a superadmin — this is what
    most tests want, since they're exercising a feature, not RBAC itself.
    Use `anonymous_client` for login/logout/access-denied tests, or
    `login_as` to act as a company-scoped user."""
    _configure_app_for_tests(db_session_factory)
    _, raw_token = await _create_user(
        db_session_factory,
        username=ADMIN_USERNAME,
        is_superadmin=True,
        api_access_enabled=True,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        ac.cookies.set(SESSION_COOKIE_NAME, raw_token)
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def anonymous_client(db_session_factory):
    """An `AsyncClient` with no session cookie at all."""
    _configure_app_for_tests(db_session_factory)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture
def login_as(db_session_factory: Any) -> Callable[..., Awaitable[User]]:
    """`await login_as(some_client, company_id=..., access_level=AccessLevel.READ)`
    — creates a company-scoped user and points `some_client`'s session
    cookie at them, replacing whatever it had. Pass `is_superadmin=True`
    instead for a superadmin."""

    async def _login_as(
        ac: AsyncClient,
        *,
        username: str = "scoped-user",
        is_superadmin: bool = False,
        company_id: uuid.UUID | None = None,
        access_level: AccessLevel | None = None,
        **user_kwargs: Any,
    ) -> User:
        user, raw_token = await _create_user(
            db_session_factory,
            username=username,
            is_superadmin=is_superadmin,
            company_id=company_id,
            access_level=access_level,
            **user_kwargs,
        )
        ac.cookies.set(SESSION_COOKIE_NAME, raw_token)
        return user

    return _login_as
