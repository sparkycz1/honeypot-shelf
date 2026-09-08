"""The Logs tab's "browse" picker (clickable `ls` instead of typing a
path by hand) and the "Honeypot logs" shortcut. See app.ssh.logs and
app.web.routes.honeypots's honeypot_logs route.
"""

from __future__ import annotations

from app.db.models.honeypot import AuthMethod, Honeypot
from app.ssh.logs import HONEYPOT_LOG_PATH, parse_directory_listing
from tests.conftest import create_company


def test_parse_directory_listing_splits_files_and_dirs():
    raw = "access.log\nnginx/\n.hidden\nopencanary.log\n"
    entries = parse_directory_listing(raw)
    assert entries == [
        ("access.log", False),
        ("nginx", True),
        ("opencanary.log", False),
    ]


def test_parse_directory_listing_empty_output():
    assert parse_directory_listing("") == []


async def _create_pinned_honeypot(db_session_factory, company_id) -> Honeypot:
    async with db_session_factory() as db:
        honeypot = Honeypot(
            company_id=company_id,
            name="acme-honey1",
            ip_address="192.0.2.10",
            port=22,
            username="honeyhive",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fake-fingerprint-for-tests",
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
    return honeypot


async def test_logs_page_offers_journal_browse_and_honeypot_logs_links(
    client, db_session_factory, celery_calls
):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)

    response = await client.get(f"/honeypots/{honeypot.id}/logs")
    assert response.status_code == 200
    assert ">Journal<" in response.text
    assert ">Browse files<" in response.text
    assert ">Honeypot logs<" in response.text
    assert HONEYPOT_LOG_PATH in response.text


async def test_browse_lists_directory_entries_as_links(client, db_session_factory, celery_calls):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)
    celery_calls.result_for["app.tasks.jobs.list_honeypot_log_directory"] = {
        "ok": True,
        "entries": [["nginx", True], ["syslog", False]],
    }

    response = await client.get(f"/honeypots/{honeypot.id}/logs", params={"browse": "/var/log"})
    assert response.status_code == 200
    assert "nginx" in response.text
    assert "syslog" in response.text
    call = next(
        c for c in celery_calls if c[0] == "app.tasks.jobs.list_honeypot_log_directory"
    )
    assert call[2] == {"path": "/var/log"}
    # The manual "type a path" fallback stays available inside browse mode.
    assert 'name="path"' in response.text
