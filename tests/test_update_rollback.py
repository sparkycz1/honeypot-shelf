"""Rolling back an update run — snapshot capture (`app.ssh.updates.
capture_package_snapshot`, taken before every real update run) and the
rollback itself (`app.tasks.jobs._rollback_honeypot_update`, which diffs a
fresh snapshot against the source run's stored one and re-installs only
what changed). See `app/web/routes/honeypots.py`'s
`rollback_honeypot_update_endpoint` and `app/web/routes/api_v1.py`'s
`rollback_honeypot_update_api` for the two trigger points.
"""

from __future__ import annotations

import json
import re
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.auth.api_tokens import create_api_token
from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.honeypot_update_run import HoneypotUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.user import AccessLevel, User
from app.ssh.updates import build_rollback_command, parse_package_snapshot
from app.tasks.jobs import _rollback_honeypot_update
from tests.conftest import ADMIN_USERNAME, create_company

pytestmark = pytest.mark.asyncio

# --- parse_package_snapshot / build_rollback_command: pure, no I/O -----


def test_parse_package_snapshot_reads_tab_separated_pairs():
    raw = "bash\t5.2.15-2\ncoreutils\t9.4-3\n"
    assert parse_package_snapshot(raw) == {"bash": "5.2.15-2", "coreutils": "9.4-3"}


def test_parse_package_snapshot_ignores_blank_and_malformed_lines():
    raw = "bash\t5.2.15-2\n\nno-tab-here\ncoreutils\t9.4-3\n"
    assert parse_package_snapshot(raw) == {"bash": "5.2.15-2", "coreutils": "9.4-3"}


def test_build_rollback_command_pins_exact_versions():
    command = build_rollback_command({"bash": "5.2.15-1", "coreutils": "9.4-2"})

    assert "bash=5.2.15-1" in command
    assert "coreutils=9.4-2" in command
    assert "--allow-downgrades" in command
    assert "install" in command


def test_build_rollback_command_quotes_each_spec():
    command = build_rollback_command({"pkg": "1.0; rm -rf /"})

    assert "'pkg=1.0; rm -rf /'" in command


# --- _rollback_honeypot_update: mocked SSH, no network -------------------


class _FakeResult:
    def __init__(self, stdout: str, exit_status: int) -> None:
        self.stdout = stdout
        self.exit_status = exit_status


class _FakeConnection:
    """Routes each `conn.run(command, ...)` to a canned result by whether
    `command` looks like the dpkg snapshot query or the apt-get rollback
    install — same call signature both `capture_package_snapshot` and
    `run_rollback` use."""

    def __init__(self, *, snapshot_stdout: str, install_result: _FakeResult | None) -> None:
        self._snapshot_stdout = snapshot_stdout
        self._install_result = install_result
        self.install_called = False

    async def run(self, command: str, **kwargs: object) -> _FakeResult:
        if "dpkg-query" in command:
            return _FakeResult(self._snapshot_stdout, 0)
        self.install_called = True
        assert self._install_result is not None, "apt-get install run but none was expected"
        return self._install_result

    async def __aenter__(self) -> _FakeConnection:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


async def _make_honeypot_with_run(
    db_session_factory: async_sessionmaker[AsyncSession], *, snapshot: dict[str, str] | None
) -> tuple[uuid.UUID, uuid.UUID]:
    async with db_session_factory() as session:
        company = await create_company(db_session_factory)
        honeypot = Honeypot(
            companies=[await session.get(Company, company.id)],
            name="rollback-target",
            ip_address="10.9.9.20",
            port=22,
            username="root",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fakefingerprint",
        )
        session.add(honeypot)
        await session.flush()

        source_run = HoneypotUpdateRun(
            honeypot_id=honeypot.id,
            strategy=UpgradeStrategy.DIST_UPGRADE,
            status=UpdateRunStatus.SUCCEEDED,
            package_snapshot=json.dumps(snapshot) if snapshot is not None else None,
        )
        session.add(source_run)
        await session.flush()

        rollback_run = HoneypotUpdateRun(
            honeypot_id=honeypot.id,
            strategy=source_run.strategy,
            rollback_of_run_id=source_run.id,
        )
        session.add(rollback_run)
        await session.commit()
        return honeypot.id, rollback_run.id


async def test_rollback_reinstalls_only_changed_packages(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    _honeypot_id, run_id = await _make_honeypot_with_run(
        db_session_factory, snapshot={"bash": "5.2.15-1", "coreutils": "9.4-2"}
    )

    # Current state: bash was upgraded since the snapshot, coreutils wasn't
    # touched, and there's a package on the honeypot the snapshot never knew
    # about (irrelevant to this rollback).
    fake_conn = _FakeConnection(
        snapshot_stdout="bash\t5.2.15-2\ncoreutils\t9.4-2\nvim\t9.1-1\n",
        install_result=_FakeResult("Setting up bash (5.2.15-1) ...\n", 0),
    )

    async def fake_open_connection(
        honeypot: object, secret: object, timeout_seconds: int
    ) -> object:
        return fake_conn

    monkeypatch.setattr("app.ssh.updates.open_connection", fake_open_connection)

    await _rollback_honeypot_update(str(run_id))

    assert fake_conn.install_called is True
    async with db_session_factory() as session:
        run = await session.get(HoneypotUpdateRun, run_id)
        assert run is not None
        assert run.status == UpdateRunStatus.SUCCEEDED
        assert "bash (5.2.15-1)" in (run.output or "")


async def test_rollback_is_a_no_op_when_nothing_changed(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    _honeypot_id, run_id = await _make_honeypot_with_run(
        db_session_factory, snapshot={"bash": "5.2.15-2"}
    )

    fake_conn = _FakeConnection(snapshot_stdout="bash\t5.2.15-2\n", install_result=None)

    async def fake_open_connection(
        honeypot: object, secret: object, timeout_seconds: int
    ) -> object:
        return fake_conn

    monkeypatch.setattr("app.ssh.updates.open_connection", fake_open_connection)

    await _rollback_honeypot_update(str(run_id))

    assert fake_conn.install_called is False
    async with db_session_factory() as session:
        run = await session.get(HoneypotUpdateRun, run_id)
        assert run is not None
        assert run.status == UpdateRunStatus.SUCCEEDED
        assert "Nothing to roll back" in (run.output or "")


async def test_rollback_fails_without_a_source_snapshot(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    _honeypot_id, run_id = await _make_honeypot_with_run(db_session_factory, snapshot=None)

    await _rollback_honeypot_update(str(run_id))

    async with db_session_factory() as session:
        run = await session.get(HoneypotUpdateRun, run_id)
        assert run is not None
        assert run.status == UpdateRunStatus.FAILED
        assert run.error


# --- The web/API endpoints: dispatch only, real SSH stays mocked out ----


def _csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


async def _create_honeypot_with_source_run(
    db_session_factory, *, snapshot: dict[str, str] | None
) -> tuple[uuid.UUID, uuid.UUID]:
    async with db_session_factory() as session:
        created_company = await create_company(db_session_factory)
        company = await session.get(Company, created_company.id)
        honeypot = Honeypot(
            companies=[company],
            name="rollback-web",
            host_key_fingerprint="SHA256:fakefingerprint",
        )
        session.add(honeypot)
        await session.commit()
        await session.refresh(honeypot)

        source_run = HoneypotUpdateRun(
            honeypot_id=honeypot.id,
            strategy=UpgradeStrategy.DIST_UPGRADE,
            status=UpdateRunStatus.SUCCEEDED,
            package_snapshot=json.dumps(snapshot) if snapshot is not None else None,
        )
        session.add(source_run)
        await session.commit()
        await session.refresh(source_run)
        return honeypot.id, source_run.id


async def test_rollback_endpoint_creates_a_new_run_and_enqueues_it(client, db_session_factory):
    honeypot_id, source_run_id = await _create_honeypot_with_source_run(
        db_session_factory, snapshot={"bash": "5.2.15-1"}
    )
    edit_page = await client.get(f"/honeypots/{honeypot_id}/edit")

    response = await client.post(
        f"/honeypots/{honeypot_id}/updates/{source_run_id}/rollback",
        data={"csrf_token": _csrf_from(edit_page)},
        follow_redirects=False,
    )
    assert response.status_code == 303

    async with db_session_factory() as session:
        result = await session.execute(
            select(HoneypotUpdateRun).where(
                HoneypotUpdateRun.rollback_of_run_id == source_run_id
            )
        )
        rollback_runs = result.scalars().all()
        assert len(rollback_runs) == 1


async def test_rollback_endpoint_requires_a_snapshot(client, db_session_factory):
    honeypot_id, source_run_id = await _create_honeypot_with_source_run(
        db_session_factory, snapshot=None
    )
    edit_page = await client.get(f"/honeypots/{honeypot_id}/edit")

    response = await client.post(
        f"/honeypots/{honeypot_id}/updates/{source_run_id}/rollback",
        data={"csrf_token": _csrf_from(edit_page)},
    )
    assert response.status_code == 400


async def test_rollback_endpoint_requires_write_access(client, login_as, db_session_factory):
    honeypot_id, source_run_id = await _create_honeypot_with_source_run(
        db_session_factory, snapshot={"bash": "5.2.15-1"}
    )
    async with db_session_factory() as session:
        honeypot = await session.get(Honeypot, honeypot_id)
        assert honeypot is not None
        company_id = honeypot.companies[0].id

    edit_page = await client.get(f"/honeypots/{honeypot_id}/edit")
    csrf_token = _csrf_from(edit_page)

    await login_as(client, company_id=company_id, access_level=AccessLevel.READ)
    response = await client.post(
        f"/honeypots/{honeypot_id}/updates/{source_run_id}/rollback",
        data={"csrf_token": csrf_token},
    )
    assert response.status_code == 403


async def test_api_rollback_endpoint(client, db_session_factory):
    honeypot_id, source_run_id = await _create_honeypot_with_source_run(
        db_session_factory, snapshot={"bash": "5.2.15-1"}
    )

    async with db_session_factory() as session:
        result = await session.execute(select(User).where(User.username == ADMIN_USERNAME))
        admin_user = result.scalar_one()
        _token, raw_token = await create_api_token(
            session, admin_user, name="rollback-test", expires_at=None
        )

    response = await client.post(
        f"/api/v1/honeypots/{honeypot_id}/updates/{source_run_id}/rollback",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["rollback_of_run_id"] == str(source_run_id)
