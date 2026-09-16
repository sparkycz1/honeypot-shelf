"""`app.tasks.jobs._refresh_honeypot_facts`'s handling of a changed
`opencanary_log_path` — found live: a honeypot's log path defaulted to
the legacy tmpfs path until its first facts refresh corrected it to the
platform-appropriate one (app.ssh.platform_detect), and the Activity tab
stayed empty until the next scheduled poll happened to pick that up, up
to a full poll interval later. Now the very same refresh that corrects
the path also resets the (now-meaningless) byte offset and immediately
triggers a canary-log poll, rather than making an operator wait."""

from __future__ import annotations

import pytest

from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.ssh.facts import HoneypotFacts
from app.tasks.jobs import _refresh_honeypot_facts
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


def _fake_facts(*, opencanary_log_path: str | None) -> HoneypotFacts:
    return HoneypotFacts(
        hostname="acme-honey1",
        os_version="Debian GNU/Linux 13 (trixie)",
        os_id="debian",
        kernel_version="6.12.0",
        cpu_architecture="x86_64",
        cpu_cores=4,
        cpu_model="",
        ram_bytes=None,
        ram_speed_mhz=None,
        disks=[],
        reboot_required=None,
        uptime_seconds=None,
        process_count=None,
        filesystems=[],
        network_interfaces=[],
        supports_readonly_root=False,
        opencanary_log_path=opencanary_log_path,
    )


async def _make_honeypot(db_session_factory, company_id, *, offset: int = 500) -> Honeypot:
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, company_id)],
            name="acme-honey1",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fakefingerprint",
            opencanary_log_path="/mnt/tmpfs/opencanary.log",
            opencanary_log_offset=offset,
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
        return honeypot


async def test_changed_log_path_resets_offset_and_triggers_an_immediate_poll(
    db_session_factory, monkeypatch, celery_calls
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    company = await create_company(db_session_factory)
    honeypot = await _make_honeypot(db_session_factory, company.id)

    async def fake_gather_facts(honeypot, secret, timeout_seconds):
        return _fake_facts(opencanary_log_path="/var/log/opencanary/opencanary.log")

    monkeypatch.setattr("app.tasks.jobs.gather_facts", fake_gather_facts)

    result = await _refresh_honeypot_facts(str(honeypot.id))
    assert result == {"ok": True}

    async with db_session_factory() as db:
        refreshed = await db.get(Honeypot, honeypot.id)
        assert refreshed is not None
        assert refreshed.opencanary_log_path == "/var/log/opencanary/opencanary.log"
        assert refreshed.opencanary_log_offset == 0

    assert "app.tasks.jobs.poll_honeypot_canary_log" in celery_calls.names
    call = next(c for c in celery_calls if c[0] == "app.tasks.jobs.poll_honeypot_canary_log")
    assert call[1] == (str(honeypot.id),)


async def test_unchanged_log_path_does_not_reset_offset_or_poll(
    db_session_factory, monkeypatch, celery_calls
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    company = await create_company(db_session_factory)
    honeypot = await _make_honeypot(db_session_factory, company.id)

    async def fake_gather_facts(honeypot, secret, timeout_seconds):
        return _fake_facts(opencanary_log_path="/mnt/tmpfs/opencanary.log")

    monkeypatch.setattr("app.tasks.jobs.gather_facts", fake_gather_facts)

    await _refresh_honeypot_facts(str(honeypot.id))

    async with db_session_factory() as db:
        refreshed = await db.get(Honeypot, honeypot.id)
        assert refreshed is not None
        assert refreshed.opencanary_log_offset == 500  # untouched

    assert "app.tasks.jobs.poll_honeypot_canary_log" not in celery_calls.names


async def test_unreadable_log_path_leaves_the_existing_value_and_offset_alone(
    db_session_factory, monkeypatch, celery_calls
):
    """OpenCanary not installed/configured yet on this honeypot - facts
    couldn't read a path back at all (None) - must never be treated as
    "changed to None"."""
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    company = await create_company(db_session_factory)
    honeypot = await _make_honeypot(db_session_factory, company.id)

    async def fake_gather_facts(honeypot, secret, timeout_seconds):
        return _fake_facts(opencanary_log_path=None)

    monkeypatch.setattr("app.tasks.jobs.gather_facts", fake_gather_facts)

    await _refresh_honeypot_facts(str(honeypot.id))

    async with db_session_factory() as db:
        refreshed = await db.get(Honeypot, honeypot.id)
        assert refreshed is not None
        assert refreshed.opencanary_log_path == "/mnt/tmpfs/opencanary.log"
        assert refreshed.opencanary_log_offset == 500

    assert "app.tasks.jobs.poll_honeypot_canary_log" not in celery_calls.names
