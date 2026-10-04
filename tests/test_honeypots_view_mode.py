"""The "Table / List / Cards" toggle above the honeypot list only ever
redirects back into `/honeypots...`."""

from __future__ import annotations

from typing import Any

import pytest

from app.web.routes.honeypots_list import _safe_honeypots_redirect


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("/honeypots", "/honeypots"),
        ("/honeypots?q=acme&page=2", "/honeypots?q=acme&page=2"),
        ("/dashboard", "/honeypots"),
        ("//evil.example/honeypots", "/honeypots"),
        ("https://evil.example/honeypots", "/honeypots"),
        ("/\evil.example/honeypots", "/honeypots"),
        ("", "/honeypots"),
    ],
)
def test_redirect_target_stays_under_honeypots(given: str, expected: str) -> None:
    assert _safe_honeypots_redirect(given) == expected


async def test_toggle_sets_the_cookie_and_goes_back_to_the_list(client: Any) -> None:
    await client.get("/honeypots")
    response = await client.post(
        "/honeypots/view-mode",
        data={
            "csrf_token": client.cookies.get("csrftoken"),
            "view": "cards",
            "next": "https://evil.example/",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/honeypots"
    assert "honeypots_view=cards" in response.headers.get("set-cookie", "")
