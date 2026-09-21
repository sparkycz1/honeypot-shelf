"""`app.web.branding` (resolving `LOGO_SOURCE`/`FAVICON_SOURCE` into a
URL templates can use) and `app.web.routes.branding` (serving a local
file, or fetching+caching a remote URL, from this app's own origin —
this app's strict CSP, `img-src 'self' data:;`, means a template can
never link to a third-party URL directly)."""

from __future__ import annotations

import httpx
import pytest
from fastapi.responses import FileResponse

from app.web import branding
from app.web.routes import branding as branding_routes

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _clear_remote_cache():
    branding_routes._remote_cache.clear()
    yield
    branding_routes._remote_cache.clear()


class _FakeSettings:
    def __init__(self, *, logo_source: str | None = None, favicon_source: str | None = None):
        self.logo_source = logo_source
        self.favicon_source = favicon_source


# --- app.web.branding.resolve_branding_url -----------------------------


def test_resolve_branding_url_unset_returns_none():
    assert branding.resolve_branding_url(None, served_route="/branding/logo") is None


def test_resolve_branding_url_remote_url_goes_through_served_route():
    """The regression this all exists to fix: a remote LOGO_SOURCE used
    to be handed straight to the template as-is, which this app's CSP
    (img-src 'self' data:;) then silently refused to load — a broken
    image icon, not an error anywhere in this app's own logs."""
    url = branding.resolve_branding_url(
        "https://example.com/logo.svg", served_route="/branding/logo"
    )
    assert url == "/branding/logo"


def test_resolve_branding_url_data_uri_used_directly():
    data_uri = "data:image/png;base64,aGVsbG8="
    assert branding.resolve_branding_url(data_uri, served_route="/branding/logo") == data_uri


def test_resolve_branding_url_site_relative_used_directly():
    assert (
        branding.resolve_branding_url("/static/img/logo.png", served_route="/branding/logo")
        == "/static/img/logo.png"
    )


def test_resolve_branding_url_local_file_goes_through_served_route(tmp_path):
    logo = tmp_path / "logo.png"
    logo.write_bytes(b"fake-png-bytes")
    url = branding.resolve_branding_url(str(logo), served_route="/branding/logo")
    assert url == "/branding/logo"


def test_favicon_url_falls_back_to_the_built_in_mark(monkeypatch):
    monkeypatch.setattr("app.web.branding.get_settings", lambda: _FakeSettings())
    assert branding.favicon_url() == branding.DEFAULT_FAVICON_URL


# --- app.web.routes.branding (the actual serving routes) ---------------


async def test_serves_an_existing_local_file(tmp_path, monkeypatch):
    logo = tmp_path / "logo.png"
    logo.write_bytes(b"fake-png-bytes")
    monkeypatch.setattr(
        "app.web.routes.branding.get_settings",
        lambda: _FakeSettings(logo_source=str(logo)),
    )

    response = await branding_routes.branding_logo()

    assert isinstance(response, FileResponse)
    assert str(response.path) == str(logo)
    assert response.media_type == "image/png"


async def test_404s_when_nothing_configured(monkeypatch):
    monkeypatch.setattr("app.web.routes.branding.get_settings", lambda: _FakeSettings())

    with pytest.raises(Exception) as exc_info:
        await branding_routes.branding_logo()
    assert exc_info.value.status_code == 404  # type: ignore[attr-defined]


class _FakeHttpxResponse:
    def __init__(self, *, content: bytes, content_type: str, status_code: int = 200):
        self.content = content
        self.headers = {"content-type": content_type}
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("boom", request=None, response=self)  # type: ignore[arg-type]


async def test_fetches_and_serves_a_remote_url(monkeypatch):
    calls = []

    async def fake_get(self, url, **kwargs):
        calls.append(url)
        return _FakeHttpxResponse(content=b"<svg>logo</svg>", content_type="image/svg+xml")

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    monkeypatch.setattr(
        "app.web.routes.branding.get_settings",
        lambda: _FakeSettings(logo_source="https://example.com/logo.svg"),
    )

    response = await branding_routes.branding_logo()

    assert response.body == b"<svg>logo</svg>"
    assert response.media_type == "image/svg+xml"
    assert calls == ["https://example.com/logo.svg"]


async def test_remote_fetch_is_cached_across_requests(monkeypatch):
    calls = []

    async def fake_get(self, url, **kwargs):
        calls.append(url)
        return _FakeHttpxResponse(content=b"data", content_type="image/png")

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    monkeypatch.setattr(
        "app.web.routes.branding.get_settings",
        lambda: _FakeSettings(favicon_source="https://example.com/favicon.png"),
    )

    await branding_routes.branding_favicon()
    await branding_routes.branding_favicon()

    assert len(calls) == 1


async def test_remote_fetch_failure_404s_and_does_not_retry_every_request(monkeypatch):
    calls = []

    async def fake_get(self, url, **kwargs):
        calls.append(url)
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    monkeypatch.setattr(
        "app.web.routes.branding.get_settings",
        lambda: _FakeSettings(logo_source="https://unreachable.example/logo.png"),
    )

    for _ in range(2):
        with pytest.raises(Exception) as exc_info:
            await branding_routes.branding_logo()
        assert exc_info.value.status_code == 404  # type: ignore[attr-defined]

    assert len(calls) == 1


async def test_remote_fetch_larger_than_cap_is_rejected(monkeypatch):
    async def fake_get(self, url, **kwargs):
        return _FakeHttpxResponse(
            content=b"x" * (branding_routes._MAX_BYTES + 1), content_type="image/png"
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    monkeypatch.setattr(
        "app.web.routes.branding.get_settings",
        lambda: _FakeSettings(logo_source="https://example.com/huge.png"),
    )

    with pytest.raises(Exception) as exc_info:
        await branding_routes.branding_logo()
    assert exc_info.value.status_code == 404  # type: ignore[attr-defined]
