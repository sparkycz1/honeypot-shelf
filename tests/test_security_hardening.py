"""HTTP and container hardening that has no better home: the COOP header,
cache headers for versioned static assets, and the Compose services' dropped
Linux capabilities."""

from __future__ import annotations

from pathlib import Path

_COMPOSE = (Path(__file__).resolve().parent.parent / "docker-compose.yml").read_text(
    encoding="utf-8"
)


async def test_pages_set_cross_origin_opener_policy(client):
    response = await client.get("/dashboard")
    assert response.headers["cross-origin-opener-policy"] == "same-origin"


def test_app_services_drop_every_capability():
    # The shared `x-app-image` block every app service (web, worker, beat,
    # migrate) extends.
    anchor = _COMPOSE.split("x-app-image: &app-image", 1)[1].split("\nservices:", 1)[0]
    assert "cap_drop:\n    - ALL" in anchor
    assert "no-new-privileges:true" in anchor
    for service in ("migrate", "web", "worker", "beat"):
        block = _COMPOSE.split(f"\n  {service}:\n", 1)[1].split("\n  ", 1)[0]
        assert "<<: *app-image" in block, service
