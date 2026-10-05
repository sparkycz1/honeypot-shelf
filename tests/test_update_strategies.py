"""Update strategies (`upgrade`, `security`), held packages, the changelog
of a pending update, and what a scheduled "System update" can do after the
update itself: reboot only if needed, and one honeypot at a time
(`app.tasks.jobs._finish_update_run`).
"""

from __future__ import annotations

import re
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.auth.api_tokens import create_api_token
from app.db.models.audit_log import AuditLogEntry
from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.honeypot_update_run import HoneypotUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.user import User
from app.services.honeypot_actions import trigger_updates
from app.ssh.facts import parse_reboot_check
from app.ssh.updates import (
    build_changelog_command,
    build_hold_command,
    build_update_command,
    build_update_preview_command,
    changelog_since,
    is_safe_package_name,
    parse_apt_upgradable_packages,
    parse_held_packages,
    reboot_hint_packages,
)
from app.tasks import jobs
from tests.conftest import ADMIN_USERNAME, create_company

pytestmark = pytest.mark.asyncio


# --- pure helpers ------------------------------------------------------------


def test_each_strategy_builds_its_own_upgrade_step():
    assert "apt-get" in build_update_command(UpgradeStrategy.UPGRADE)
    assert " upgrade" in build_update_command(UpgradeStrategy.UPGRADE)
    assert "full-upgrade" in build_update_command(UpgradeStrategy.FULL_UPGRADE)
    assert "dist-upgrade" in build_update_command(UpgradeStrategy.DIST_UPGRADE)

    security = build_update_command(UpgradeStrategy.SECURITY)
    assert "install --only-upgrade $pkgs" in security
    assert "-security" in security
    assert "No pending security updates." in security


def test_security_preview_simulates_only_the_security_packages():
    preview = build_update_preview_command(UpgradeStrategy.SECURITY)

    assert "-s install --only-upgrade $pkgs" in preview


def test_pending_packages_are_marked_as_security():
    raw = (
        "===APT_UPGRADABLE===\n"
        "openssl/stable-security 3.0.15-1 amd64 [upgradable from: 3.0.14-1]\n"
        "vim/stable 9.1-2 amd64 [upgradable from: 9.1-1]\n"
        "===FLATPAK_UPGRADABLE===\n===SNAP_UPGRADABLE===\n"
    )

    packages = {p["name"]: p for p in parse_apt_upgradable_packages(raw)}

    assert packages["openssl"]["security"] is True
    assert packages["vim"]["security"] is False


def test_held_packages_are_read_from_their_own_section():
    raw = (
        "===APT_UPGRADABLE===\n===FLATPAK_UPGRADABLE===\n===SNAP_UPGRADABLE===\n"
        "===APT_HELD===\nvim\nbash\n$(bad)\n"
    )

    assert parse_held_packages(raw) == ["bash", "vim"]
    # An older honeypot answer without the section: unknown, not "none held".
    assert parse_held_packages("===APT_UPGRADABLE===\n") is None


def test_package_names_are_validated_and_quoted():
    assert is_safe_package_name("libc6:amd64")
    assert not is_safe_package_name("a;b")
    assert not is_safe_package_name("")
    assert "apt-mark hold vim" in build_hold_command("vim", hold=True)
    assert "apt-mark unhold vim" in build_hold_command("vim", hold=False)
    assert "apt-mark hold 'bad name'" in build_hold_command("bad name", hold=True)
    assert "-- 'a b'" in build_changelog_command("a b")


def test_changelog_is_cut_at_the_installed_version():
    text = (
        "vim (9.1-2) stable; urgency=medium\n  * newer\n\n"
        "vim (9.1-1) stable; urgency=low\n  * installed\n"
    )

    assert "installed" not in changelog_since(text, "9.1-1")
    assert "newer" in changelog_since(text, "9.1-1")
    # Unknown installed version: everything (capped).
    assert "installed" in changelog_since(text, None)


def test_reboot_hint_names_kernel_packages_only():
    packages: list[dict[str, object]] = [
        {"name": "linux-image-6.1.0-28-amd64"},
        {"name": "vim"},
        {"name": "libc6"},
    ]

    assert reboot_hint_packages(packages) == ["linux-image-6.1.0-28-amd64", "libc6"]
    assert reboot_hint_packages(None) == []


def test_reboot_check_reads_the_flag_and_the_kernel():
    same = "===KERNEL===\n6.1.0-28-amd64\n===KERNEL_LATEST===\n6.1.0-28-amd64\n"
    newer = "===KERNEL===\n6.1.0-27-amd64\n===KERNEL_LATEST===\n6.1.0-28-amd64\n"

    assert parse_reboot_check(same) is False
    assert parse_reboot_check(newer) is True
    assert parse_reboot_check("HONEYPOTSHELF_REBOOT_FLAG\n" + same) is True


# --- rolling batches and "reboot only if needed" ----------------------------


async def _make_honeypots(
    db_session_factory: async_sessionmaker[AsyncSession], names: list[str]
) -> list[uuid.UUID]:
    company = await create_company(db_session_factory)
    async with db_session_factory() as session:
        honeypots = [
            Honeypot(
                companies=[await session.get(Company, company.id)],
                name=name,
                ip_address=f"10.9.8.{index + 10}",
                port=22,
                username="root",
                auth_method=AuthMethod.SSH_KEY,
                host_key_fingerprint="SHA256:fakefingerprint",
            )
            for index, name in enumerate(names)
        ]
        session.add_all(honeypots)
        await session.commit()
        return [h.id for h in honeypots]


@pytest.fixture
def enqueued(monkeypatch) -> dict[str, list[str]]:
    """Every task the code under test enqueues, by task name."""
    calls: dict[str, list[str]] = {}
    for name in (
        "run_honeypot_update",
        "finish_update_run",
        "refresh_honeypot_facts",
        "refresh_honeypot_packages",
        "check_honeypot_updates",
    ):

        def record(*args: object, _name: str = name) -> None:
            calls.setdefault(_name, []).append(str(args[0]))

        monkeypatch.setattr(getattr(jobs, name), "delay", record)
    return calls


async def test_rolling_batch_enqueues_only_the_first_honeypot(db_session_factory, enqueued):
    await _make_honeypots(db_session_factory, ["charlie", "alpha", "Bravo"])
    async with db_session_factory() as session:
        honeypots = list((await session.execute(select(Honeypot))).scalars().all())
        batch_id, skipped = await trigger_updates(
            session, honeypots, UpgradeStrategy.SECURITY, reboot_if_required=True, rolling=True
        )
        runs = list(
            (
                await session.execute(
                    select(HoneypotUpdateRun)
                    .where(HoneypotUpdateRun.batch_id == batch_id)
                    .order_by(HoneypotUpdateRun.rollout_position)
                )
            )
            .scalars()
            .all()
        )
        names = [(await session.get(Honeypot, run.honeypot_id)).name for run in runs]

    assert skipped == 0
    assert names == ["alpha", "Bravo", "charlie"]
    assert [run.rollout_position for run in runs] == [0, 1, 2]
    assert all(run.reboot_if_required for run in runs)
    assert enqueued["run_honeypot_update"] == [str(runs[0].id)]


async def test_a_plain_batch_stays_parallel(db_session_factory, enqueued):
    await _make_honeypots(db_session_factory, ["one", "two"])
    async with db_session_factory() as session:
        honeypots = list((await session.execute(select(Honeypot))).scalars().all())
        batch_id, _skipped = await trigger_updates(session, honeypots, UpgradeStrategy.UPGRADE)
        runs = list(
            (
                await session.execute(
                    select(HoneypotUpdateRun).where(HoneypotUpdateRun.batch_id == batch_id)
                )
            )
            .scalars()
            .all()
        )

    assert len(enqueued["run_honeypot_update"]) == 2
    assert all(run.rollout_position is None and not run.reboot_if_required for run in runs)


async def _rolling_runs(
    db_session_factory: async_sessionmaker[AsyncSession],
    first_status: UpdateRunStatus,
    *,
    reboot_if_required: bool = False,
) -> list[uuid.UUID]:
    honeypot_ids = await _make_honeypots(db_session_factory, ["alpha", "bravo", "charlie"])
    batch_id = uuid.uuid4()
    async with db_session_factory() as session:
        runs = [
            HoneypotUpdateRun(
                honeypot_id=honeypot_id,
                strategy=UpgradeStrategy.FULL_UPGRADE,
                batch_id=batch_id,
                rollout_position=position,
                reboot_if_required=reboot_if_required,
                status=first_status if position == 0 else UpdateRunStatus.PENDING,
            )
            for position, honeypot_id in enumerate(honeypot_ids)
        ]
        session.add_all(runs)
        await session.commit()
        return [run.id for run in runs]


async def test_rollout_continues_after_a_successful_run(db_session_factory, monkeypatch, enqueued):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    run_ids = await _rolling_runs(db_session_factory, UpdateRunStatus.SUCCEEDED)

    result = await jobs._finish_update_run(str(run_ids[0]))

    assert result["ok"] is True
    assert enqueued["run_honeypot_update"] == [str(run_ids[1])]


async def test_rollout_stops_after_a_failed_run(db_session_factory, monkeypatch, enqueued):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    run_ids = await _rolling_runs(db_session_factory, UpdateRunStatus.FAILED)

    await jobs._finish_update_run(str(run_ids[0]))

    assert "run_honeypot_update" not in enqueued
    async with db_session_factory() as session:
        for run_id in run_ids[1:]:
            run = await session.get(HoneypotUpdateRun, run_id)
            assert run is not None
            assert run.status == UpdateRunStatus.FAILED
            assert run.error is not None and "Rolling update stopped" in run.error
            assert run.finished_at is not None
        actions = list((await session.execute(select(AuditLogEntry.action))).scalars().all())
    assert "honeypot.update.rollout_stopped" in actions


@pytest.mark.parametrize(
    ("needed", "back", "outcome", "continues"),
    [
        (False, True, "not_needed", True),
        (True, True, "rebooted", True),
        (True, False, "not_back", False),
    ],
)
async def test_reboot_only_if_needed(
    db_session_factory, monkeypatch, enqueued, needed, back, outcome, continues
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    run_ids = await _rolling_runs(
        db_session_factory, UpdateRunStatus.SUCCEEDED, reboot_if_required=True
    )
    power_calls: list[object] = []

    async def fake_check(honeypot: object, secret: object, timeout_seconds: int) -> bool:
        return needed

    async def fake_power(
        honeypot: object, secret: object, action: object, timeout_seconds: int
    ) -> None:
        power_calls.append(action)

    async def fake_wait(honeypot: object) -> bool:
        return back

    monkeypatch.setattr(jobs, "check_reboot_required", fake_check)
    monkeypatch.setattr(jobs, "send_power_command", fake_power)
    monkeypatch.setattr(jobs, "_wait_until_back", fake_wait)

    await jobs._finish_update_run(str(run_ids[0]))

    async with db_session_factory() as session:
        run = await session.get(HoneypotUpdateRun, run_ids[0])
        assert run is not None
        assert run.reboot_outcome == outcome
        assert "[Honeypot Shelf]" in (run.output or "")
        actions = list((await session.execute(select(AuditLogEntry.action))).scalars().all())
    assert len(power_calls) == (1 if needed else 0)
    assert "honeypot.update.reboot" in actions
    assert ("run_honeypot_update" in enqueued) is continues


# --- hold / changelog: tasks, web, API --------------------------------------


class _FakeResult:
    def __init__(self, stdout: str, exit_status: int) -> None:
        self.stdout = stdout
        self.exit_status = exit_status


class _FakeConnection:
    def __init__(self, result: _FakeResult) -> None:
        self._result = result
        self.commands: list[str] = []

    async def run(self, command: str, **kwargs: object) -> _FakeResult:
        self.commands.append(command)
        return self._result

    async def __aenter__(self) -> _FakeConnection:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


def _fake_ssh(monkeypatch, result: _FakeResult) -> _FakeConnection:
    conn = _FakeConnection(result)

    async def fake_open_connection(
        honeypot: object, secret: object, timeout_seconds: int
    ) -> object:
        return conn

    monkeypatch.setattr("app.ssh.updates.open_connection", fake_open_connection)
    return conn


async def test_hold_task_updates_the_stored_list(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    (honeypot_id,) = await _make_honeypots(db_session_factory, ["holder"])
    conn = _fake_ssh(monkeypatch, _FakeResult("vim set on hold.\n", 0))

    held = await jobs._set_honeypot_package_hold(str(honeypot_id), "vim", True)
    async with db_session_factory() as session:
        after_hold = (await session.get(Honeypot, honeypot_id)).apt_held_packages
    released = await jobs._set_honeypot_package_hold(str(honeypot_id), "vim", False)
    async with db_session_factory() as session:
        after_release = (await session.get(Honeypot, honeypot_id)).apt_held_packages

    assert held["ok"] is True and released["ok"] is True
    assert after_hold == ["vim"]
    assert after_release == []
    assert "apt-mark hold vim" in conn.commands[0]
    assert "apt-mark unhold vim" in conn.commands[1]


async def test_hold_task_reports_a_failing_apt_mark(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    (honeypot_id,) = await _make_honeypots(db_session_factory, ["holder"])
    _fake_ssh(monkeypatch, _FakeResult("E: not allowed\n", 100))

    result = await jobs._set_honeypot_package_hold(str(honeypot_id), "vim", True)

    assert result == {"ok": False, "error": "E: not allowed"}
    async with db_session_factory() as session:
        assert (await session.get(Honeypot, honeypot_id)).apt_held_packages is None


async def test_changelog_task_trims_to_the_installed_version(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    (honeypot_id,) = await _make_honeypots(db_session_factory, ["reader"])
    async with db_session_factory() as session:
        honeypot = await session.get(Honeypot, honeypot_id)
        honeypot.apt_upgradable_packages = [
            {"name": "vim", "current_version": "9.1-1", "new_version": "9.1-2"}
        ]
        await session.commit()
    _fake_ssh(
        monkeypatch,
        _FakeResult("vim (9.1-2) stable\n  * newer\n\nvim (9.1-1) stable\n  * installed\n", 0),
    )

    result = await jobs._view_package_changelog(str(honeypot_id), "vim")

    assert result["ok"] is True
    assert result["installed_version"] == "9.1-1"
    assert "newer" in result["changelog"] and "installed" not in result["changelog"]


class _Delayed:
    """Stands in for a Celery `AsyncResult`: `.get()` answers at once."""

    def __init__(self, result: dict[str, object]) -> None:
        self._result = result

    def get(self, timeout: float | None = None) -> dict[str, object]:
        return self._result


async def test_hold_page_action_redirects_and_audits(client, db_session_factory, monkeypatch):
    (honeypot_id,) = await _make_honeypots(db_session_factory, ["web-hold"])
    async with db_session_factory() as session:
        honeypot = await session.get(Honeypot, honeypot_id)
        honeypot.apt_upgradable_packages = [{"name": "vim", "new_version": "2"}]
        await session.commit()
    calls: list[tuple[object, ...]] = []

    def fake_delay(*args: object) -> _Delayed:
        calls.append(args)
        return _Delayed({"ok": True})

    monkeypatch.setattr(jobs.set_honeypot_package_hold, "delay", fake_delay)
    updates_page = await client.get(f"/honeypots/{honeypot_id}/updates")
    match = re.search(r'name="csrf_token" value="([^"]+)"', updates_page.text)
    assert match, "no csrf_token found on the updates page"
    csrf = match.group(1)

    response = await client.post(
        f"/honeypots/{honeypot_id}/updates/hold",
        data={"csrf_token": csrf, "package": "vim", "hold": "1"},
        follow_redirects=False,
    )
    invalid = await client.post(
        f"/honeypots/{honeypot_id}/updates/hold",
        data={"csrf_token": csrf, "package": "a;b", "hold": "1"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"].endswith("/updates?hold=held&package=vim")
    assert calls == [(str(honeypot_id), "vim", True)]
    # A package the honeypot is not known to have: no name in the address.
    unknown = await client.post(
        f"/honeypots/{honeypot_id}/updates/hold",
        data={"csrf_token": csrf, "package": "nano", "hold": "1"},
        follow_redirects=False,
    )
    assert unknown.headers["location"].endswith("/updates?hold=held")
    assert invalid.status_code == 400
    async with db_session_factory() as session:
        actions = list((await session.execute(select(AuditLogEntry.action))).scalars().all())
    assert actions.count("honeypot.package.hold") == 2


async def test_updates_page_lists_held_packages_and_new_strategies(client, db_session_factory):
    (honeypot_id,) = await _make_honeypots(db_session_factory, ["web-list"])
    async with db_session_factory() as session:
        honeypot = await session.get(Honeypot, honeypot_id)
        honeypot.apt_held_packages = ["vim"]
        await session.commit()

    page = await client.get(f"/honeypots/{honeypot_id}/updates?hold=held&package=vim")

    assert page.status_code == 200
    assert 'value="security"' in page.text and 'value="upgrade"' in page.text
    assert "Held packages" in page.text
    assert "vim is held at its installed version." in page.text


async def test_changelog_page_shows_the_text(client, db_session_factory, monkeypatch):
    (honeypot_id,) = await _make_honeypots(db_session_factory, ["web-log"])
    monkeypatch.setattr(
        jobs.view_package_changelog,
        "delay",
        lambda *args: _Delayed(
            {"ok": True, "changelog": "vim (9.1-2) <b>x</b>", "installed_version": "9.1-1"}
        ),
    )

    page = await client.get(f"/honeypots/{honeypot_id}/updates/changelog?package=vim")
    invalid = await client.get(f"/honeypots/{honeypot_id}/updates/changelog?package=a;b")

    assert page.status_code == 200
    assert "vim (9.1-2) &lt;b&gt;x&lt;/b&gt;" in page.text
    assert "isn&#39;t a valid package name" in invalid.text or "valid package name" in invalid.text


async def test_api_holds_releases_and_reads_a_changelog(client, db_session_factory, monkeypatch):
    (honeypot_id,) = await _make_honeypots(db_session_factory, ["api-hold"])
    async with db_session_factory() as session:
        admin = (
            await session.execute(select(User).where(User.username == ADMIN_USERNAME))
        ).scalar_one()
        _token, raw = await create_api_token(
            session, admin, name="updates", expires_at=None
        )
        await session.commit()
    headers = {"Authorization": f"Bearer {raw}"}
    monkeypatch.setattr(
        jobs.set_honeypot_package_hold, "delay", lambda *args: _Delayed({"ok": True})
    )
    monkeypatch.setattr(
        jobs.view_package_changelog,
        "delay",
        lambda *args: _Delayed({"ok": True, "changelog": "text", "installed_version": None}),
    )
    base = f"/api/v1/honeypots/{honeypot_id}/packages"

    held = await client.post(f"{base}/vim/hold", headers=headers)
    released = await client.delete(f"{base}/vim/hold", headers=headers)
    changelog = await client.get(f"{base}/vim/changelog", headers=headers)
    invalid = await client.post(f"{base}/a;b/hold", headers=headers)

    assert held.status_code == 200 and held.json()["held"] is True
    assert released.status_code == 200 and released.json()["held"] is False
    assert changelog.json() == {"package": "vim", "installed_version": None, "changelog": "text"}
    assert invalid.status_code == 400


async def test_api_reports_a_failed_hold_as_bad_gateway(client, db_session_factory, monkeypatch):
    (honeypot_id,) = await _make_honeypots(db_session_factory, ["api-fail"])
    async with db_session_factory() as session:
        admin = (
            await session.execute(select(User).where(User.username == ADMIN_USERNAME))
        ).scalar_one()
        _token, raw = await create_api_token(
            session, admin, name="updates", expires_at=None
        )
        await session.commit()
    monkeypatch.setattr(
        jobs.set_honeypot_package_hold,
        "delay",
        lambda *args: _Delayed({"ok": False, "error": "sudo: a password is required"}),
    )

    response = await client.post(
        f"/api/v1/honeypots/{honeypot_id}/packages/vim/hold",
        headers={"Authorization": f"Bearer {raw}"},
    )

    assert response.status_code == 502
    assert "password is required" in response.json()["detail"]
