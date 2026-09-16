"""The Logs tab's "browse" picker (clickable `ls` instead of typing a
path by hand) and the "Honeypot logs" shortcut. See app.ssh.logs and
app.web.routes.honeypots's honeypot_logs route.
"""

from __future__ import annotations

from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.ssh.logs import HONEYPOT_LOG_PATH, is_path_allowed, parse_directory_listing
from tests.conftest import create_company

# The default LOG_FILE_ALLOWED_PATHS (app.core.config) — kept as a literal
# here rather than importing get_settings(), so this test fails loudly if
# either that default or a device's actual OpenCanary log path ever drift
# out of sync with each other.
_DEFAULT_ALLOWED_PATHS = ["/var/log", "/var/lib/docker/containers", "/mnt/tmpfs"]


def test_both_opencanary_log_path_variants_are_within_the_default_allowed_paths():
    """`HONEYPOT_LOG_PATH`/the tmpfs default (Raspberry Pi OS) and
    `PERSISTENT_LOG_PATH` (Debian/Ubuntu, see app.ssh.initialize) must both
    pass `is_path_allowed` against the *default* `LOG_FILE_ALLOWED_PATHS`
    — an operator who never touches that setting must still be able to
    open either OS's own "Honeypot logs" shortcut out of the box."""
    from app.ssh.initialize import PERSISTENT_LOG_PATH

    assert is_path_allowed(HONEYPOT_LOG_PATH, _DEFAULT_ALLOWED_PATHS)
    assert is_path_allowed(PERSISTENT_LOG_PATH, _DEFAULT_ALLOWED_PATHS)


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
        company = await db.get(Company, company_id)
        honeypot = Honeypot(
            companies=[company],
            name="acme-honey1",
            ip_address="192.0.2.10",
            port=22,
            username="honeypotshelf",
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


async def test_honeypot_logs_shortcut_follows_this_devices_own_log_path_not_the_rpi_default(
    client, db_session_factory, celery_calls
):
    """The "Honeypot logs" shortcut must point at *this* honeypot's own
    `opencanary_log_path` (set per-device at Initialize/facts-refresh time
    — tmpfs on Raspberry Pi OS, a persistent `/var/log/...` path on
    Debian/Ubuntu, see app.ssh.platform_detect/app.ssh.initialize), never
    the legacy `HONEYPOT_LOG_PATH` constant that only ever matches the
    Raspberry Pi OS default. A honeypot Initialized as Debian/Ubuntu (or
    self-healed to that path by a facts refresh) whose Logs tab still
    offered the tmpfs shortcut would silently 404/empty-output every time,
    since that path never existed on that device at all."""
    from app.ssh.initialize import PERSISTENT_LOG_PATH

    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)
    async with db_session_factory() as db:
        db_honeypot = await db.get(Honeypot, honeypot.id)
        db_honeypot.opencanary_log_path = PERSISTENT_LOG_PATH
        await db.commit()

    response = await client.get(f"/honeypots/{honeypot.id}/logs")
    assert response.status_code == 200
    assert PERSISTENT_LOG_PATH in response.text
    assert HONEYPOT_LOG_PATH not in response.text


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
