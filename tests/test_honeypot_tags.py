"""Regression guards for the honeypot list's search box folding tag search
into itself, rather than a separate `<select multiple>` tag picker
(matching debcontrol's own machine list — see
app.web.honeypot_search.honeypot_search_clause's docstring and
partials/honeypot_search_form.html)."""

from __future__ import annotations

import pytest

from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


async def _create_honeypot(
    client, csrf_token: str, company_id, *, name: str, ip_address: str, tags: str = ""
) -> None:
    response = await client.post(
        "/honeypots",
        data={
            "name": name,
            "ip_address": ip_address,
            "port": "22",
            "username": "pi",
            "auth_method": "ssh_key",
            "company_id": str(company_id),
            "tags": tags,
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 303, response.text


def _csrf_from(response) -> str:
    import re

    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


async def test_honeypot_list_has_no_separate_tag_picker(client, db_session_factory):
    """The honeypot list used to (potentially) show a `<select multiple>`
    tag picker alongside the plain search box; folding tag search into that
    one field instead means it should never render one — a company's own
    "All honeypots" page keeps its one-tag `<select>`, unaffected (this
    only checks the plain honeypot list)."""
    company = await create_company(db_session_factory)
    new_form = await client.get("/honeypots/new")
    csrf_token = _csrf_from(new_form)
    await _create_honeypot(
        client, csrf_token, company.id, name="has-a-tag", ip_address="10.0.0.5", tags="prod"
    )

    list_response = await client.get("/honeypots")
    assert '<select name="tag"' not in list_response.text


async def test_table_view_shows_tags_in_their_own_column(client, db_session_factory):
    """Tags used to render wrapped under the honeypot's name in the Name
    cell — now a dedicated column between Name and IP (see
    honeypots/list.html's table `<thead>`)."""
    company = await create_company(db_session_factory)
    new_form = await client.get("/honeypots/new")
    csrf_token = _csrf_from(new_form)
    await _create_honeypot(
        client, csrf_token, company.id, name="tagged-one", ip_address="10.0.0.6", tags="prod,edge"
    )

    list_response = await client.get("/honeypots")
    assert list_response.status_code == 200
    name_index = list_response.text.index('<th>Name</th>')
    tags_index = list_response.text.index('<th>Tags</th>')
    ip_index = list_response.text.index('<th>IP</th>')
    assert name_index < tags_index < ip_index
    assert '?tag=prod' in list_response.text
    assert '?tag=edge' in list_response.text


async def test_plain_search_box_also_matches_a_tag_name(client, db_session_factory):
    """The honeypot list folds tag search into its one plain search field
    rather than a separate picker control."""
    company = await create_company(db_session_factory)
    new_form = await client.get("/honeypots/new")
    csrf_token = _csrf_from(new_form)
    await _create_honeypot(
        client, csrf_token, company.id, name="tagged-prod", ip_address="10.0.0.5", tags="prod"
    )
    await _create_honeypot(
        client, csrf_token, company.id, name="untagged", ip_address="10.0.0.6"
    )

    response = await client.get("/honeypots", params={"q": "prod"})

    assert "tagged-prod" in response.text
    assert "untagged" not in response.text


async def test_plain_search_box_also_matches_a_company_name(client, db_session_factory):
    """The same one search field also matches the honeypot's own
    company — searching by company, IP, name, tag, or hostname is all
    folded into this single box, no separate company picker."""
    acme = await create_company(db_session_factory, name="Acme Corp")
    globex = await create_company(db_session_factory, name="Globex Inc")
    new_form = await client.get("/honeypots/new")
    csrf_token = _csrf_from(new_form)
    await _create_honeypot(
        client, csrf_token, acme.id, name="acme-honey", ip_address="10.0.0.7"
    )
    await _create_honeypot(
        client, csrf_token, globex.id, name="globex-honey", ip_address="10.0.0.8"
    )

    response = await client.get("/honeypots", params={"q": "Acme"})

    assert "acme-honey" in response.text
    assert "globex-honey" not in response.text
