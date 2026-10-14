"""Files watched for changes on a honeypot (`app.services.watched_files`):
the default list, reading as root, the first reading as the baseline,
later differences recorded on the History tab and announced without their
content, and the diff only for accounts that may write the honeypot."""

from __future__ import annotations

import base64
import uuid
from typing import Any

import pytest
from httpx2 import AsyncClient
from sqlalchemy import select

from app.auth.api_tokens import create_api_token
from app.db.models.access_level import AccessLevel
from app.db.models.audit_log import AuditLogEntry
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_watched_file import HoneypotWatchedFile
from app.db.models.notification_log import NotificationChannel
from app.db.models.notification_rule import NotificationRule, NotificationScope
from app.db.models.user import User
from app.services import watched_files
from app.tasks import jobs
from tests.conftest import create_company


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


class _Result:
    def __init__(self, output: str) -> None:
        self.exit_status = 0
        self.output = output


async def _honeypot(db_session_factory: Any, name: str = "hp1") -> tuple[uuid.UUID, uuid.UUID]:
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, company.id)],
            name=name,
            username="honeypotshelf",
            host_key_fingerprint="SHA256:test",
        )
        db.add(honeypot)
        await db.commit()
        return honeypot.id, company.id


async def _api_headers(client: AsyncClient, login_as: Any, db_session_factory: Any) -> Any:
    user = await login_as(client, username="api-admin", is_superadmin=True, api_access_enabled=True)
    async with db_session_factory() as db:
        db_user = await db.get(User, user.id)
        assert db_user is not None
        _token, raw = await create_api_token(db, db_user, name="t", expires_at=None)
    return {"Authorization": f"Bearer {raw}"}


def test_paths_must_be_plain_absolute_files() -> None:
    assert watched_files.parse_paths("/etc/ssh/sshd_config\n\n/etc/hosts\n") == [
        "/etc/ssh/sshd_config",
        "/etc/hosts",
    ]
    assert watched_files.parse_paths("/etc/a\n/etc/a\n") == ["/etc/a"]
    for bad in ("etc/passwd", "/etc/../shadow", "/etc/a b", "/etc/$(id)", "/etc/dir/", "/a;b"):
        with pytest.raises(watched_files.WatchedFilesError):
            watched_files.parse_paths(bad)
    with pytest.raises(watched_files.WatchedFilesError):
        watched_files.parse_paths("\n".join(f"/etc/f{i}" for i in range(21)))


def test_defaults_include_the_login_accounts_keys_only_when_its_home_is_plain() -> None:
    assert watched_files.default_paths("/home/honeypotshelf")[-1] == (
        "/home/honeypotshelf/.ssh/authorized_keys"
    )
    assert watched_files.default_paths(None) == list(watched_files.DEFAULT_PATHS)
    # root's own is already in the list; a strange home is not trusted.
    assert watched_files.default_paths("/root") == list(watched_files.DEFAULT_PATHS)
    assert watched_files.default_paths("/home/x;reboot") == list(watched_files.DEFAULT_PATHS)


def test_output_is_read_per_file_and_the_command_runs_as_root() -> None:
    raw = (
        "===FILE 0 ok===\n" + _b64("Port 22\n") + "\n"
        "===FILE 1 missing===\n"
        "===FILE 2 ok===\n!!! not base64 !!!\n"
        "===FILE 3 too_large===\n"
        "===FILE 9 ok===\n" + _b64("ignored") + "\n"
    )

    assert watched_files.parse_output(raw, 4) == {
        0: ("ok", "Port 22\n"),
        1: ("missing", None),
        2: ("unreadable", None),
        3: ("too_large", None),
    }
    command = watched_files.build_command(["/etc/ssh/sshd_config"])
    assert "base64 < /etc/ssh/sshd_config" in command
    # Through the onboarding sudoers rule (`bash /tmp/.honeypotshelf-*`),
    # falling back to the login account, and always cleaned up.
    assert "mktemp /tmp/.honeypotshelf-watch-" in command
    assert 'sudo -n bash "$f" 2>/dev/null || bash "$f"' in command
    assert 'rm -f "$f"' in command
    with pytest.raises(ValueError):
        watched_files.build_command(["/etc/x; reboot"])


async def test_default_list_is_applied_until_someone_edits_it(
    client: AsyncClient, db_session_factory: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    honeypot_id, _company = await _honeypot(db_session_factory)
    commands: list[str] = []

    async def fake_run(_honeypot: Any, _secret: Any, command: str, *_args: Any) -> Any:
        commands.append(command)
        if command.startswith("getent passwd"):
            return _Result("/home/honeypotshelf\n")
        return _Result("")

    monkeypatch.setattr(jobs, "run_command", fake_run)
    await jobs._check_watched_files(str(honeypot_id))

    async with db_session_factory() as db:
        paths = sorted(
            (await db.execute(select(HoneypotWatchedFile.path))).scalars().all()
        )
        honeypot = await db.get(Honeypot, honeypot_id)
        assert honeypot is not None and not honeypot.watched_files_customized
    assert paths == sorted(
        [*watched_files.DEFAULT_PATHS, "/home/honeypotshelf/.ssh/authorized_keys"]
    )
    assert commands[0] == "getent passwd honeypotshelf | cut -d: -f6"

    # Emptied by a person: the defaults never come back.
    page = await client.get(f"/honeypots/{honeypot_id}/files")
    assert "default files are watched" in page.text
    await client.post(
        f"/honeypots/{honeypot_id}/files",
        data={"csrf_token": client.cookies.get("csrftoken"), "paths": ""},
    )
    await jobs._check_watched_files(str(honeypot_id))
    async with db_session_factory() as db:
        assert (await db.execute(select(HoneypotWatchedFile))).scalars().all() == []


async def test_changes_are_recorded_announced_and_shown_as_a_diff(
    client: AsyncClient, login_as: Any, db_session_factory: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    posted: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "app.services.notifications.send_webhook", lambda url, payload: posted.append(payload)
    )
    honeypot_id, _company = await _honeypot(db_session_factory)
    base = f"/honeypots/{honeypot_id}/files"
    await client.get(base)
    csrf = client.cookies.get("csrftoken")
    async with db_session_factory() as db:
        owner = (await db.execute(select(User))).scalars().first()
        assert owner is not None
        db.add(
            NotificationRule(
                user_id=owner.id,
                name="files",
                scope=NotificationScope.HONEYPOT,
                honeypots=[await db.get(Honeypot, honeypot_id)],
                delivery_channel=NotificationChannel.WEBHOOK,
                webhook_url="https://hooks.example.com/x",
                notify_on_alert=False,
                notify_on_unavailable=False,
                notify_on_recovered=False,
                notify_on_file_changed=True,
            )
        )
        await db.commit()

    refused = await client.post(base, data={"csrf_token": csrf, "paths": "relative/path"})
    saved = await client.post(
        base,
        data={"csrf_token": csrf, "paths": "/etc/ssh/sshd_config\n/etc/gone.conf"},
        follow_redirects=False,
    )
    versions = iter(
        [
            "Port 22\nPermitRootLogin no\nPasswordAuthentication no\n",
            "Port 22\nPermitRootLogin no\nPasswordAuthentication no\n",
            "Port 2222\nPermitRootLogin yes\nPasswordAuthentication no\nAllowUsers ops\n",
        ]
    )

    async def fake_run(*_args: Any, **_kwargs: Any) -> Any:
        # /etc/gone.conf sorts first.
        return _Result("===FILE 0 missing===\n===FILE 1 ok===\n" + _b64(next(versions)) + "\n")

    monkeypatch.setattr(jobs, "run_command", fake_run)
    first = await jobs._check_watched_files(str(honeypot_id))
    same = await jobs._check_watched_files(str(honeypot_id))
    changed = await jobs._check_watched_files(str(honeypot_id))

    assert "not usable" in refused.text
    assert saved.headers["location"] == f"{base}?saved=1"
    assert (first["changed"], same["changed"], changed["changed"]) == (0, 0, 1)
    async with db_session_factory() as db:
        rows = {
            row.path: row
            for row in (await db.execute(select(HoneypotWatchedFile))).scalars().all()
        }
        summaries = list(
            (
                await db.execute(
                    select(AuditLogEntry.summary).where(
                        AuditLogEntry.action == "honeypot.watched_file.change"
                    )
                )
            )
            .scalars()
            .all()
        )
    config = rows["/etc/ssh/sshd_config"]
    assert rows["/etc/gone.conf"].state == "missing"
    assert (config.lines_added, config.lines_removed) == (3, 2)
    # Stored encrypted, never as it is.
    assert config.content_encrypted is not None and b"Port 2222" not in config.content_encrypted
    assert summaries == ["Watched file /etc/ssh/sshd_config changed: +3 / -2 lines"]
    # The notification names the file, not its lines.
    assert len(posted) == 1
    assert posted[0]["kind"] == "file_changed"
    assert "/etc/ssh/sshd_config" in posted[0]["details"]
    assert "PermitRootLogin" not in str(posted[0])

    page = await client.get(f"{base}?diff={config.id}")
    timeline = await client.get(f"/honeypots/{honeypot_id}/history")
    assert "+Port 2222" in page.text and "-PermitRootLogin no" in page.text
    assert "/etc/ssh/sshd_config" in timeline.text

    headers = await _api_headers(client, login_as, db_session_factory)
    listed = (
        await client.get(f"/api/v1/honeypots/{honeypot_id}/watched-files", headers=headers)
    ).json()
    diff = (
        await client.get(
            f"/api/v1/honeypots/{honeypot_id}/watched-files/{config.id}/diff", headers=headers
        )
    ).json()
    assert {f["path"]: f["state"] for f in listed} == {
        "/etc/gone.conf": "missing",
        "/etc/ssh/sshd_config": "ok",
    }
    assert all("content" not in f for f in listed)
    assert "+AllowUsers ops" in diff["diff"]


async def test_a_file_that_appears_is_reported(db_session_factory: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    honeypot_id, _company = await _honeypot(db_session_factory)
    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, honeypot_id)
        assert honeypot is not None
        await watched_files.set_paths(db, honeypot, ["/root/.ssh/authorized_keys"])
    readings = iter(
        [
            "===FILE 0 missing===\n",
            "===FILE 0 ok===\n" + _b64("ssh-ed25519 AAAA intruder\n") + "\n",
        ]
    )

    async def fake_run(*_args: Any, **_kwargs: Any) -> Any:
        return _Result(next(readings))

    monkeypatch.setattr(jobs, "run_command", fake_run)
    assert (await jobs._check_watched_files(str(honeypot_id)))["changed"] == 0
    assert (await jobs._check_watched_files(str(honeypot_id)))["changed"] == 1


async def test_read_only_user_sees_the_list_but_not_the_diff_or_the_form(
    client: AsyncClient, login_as: Any, db_session_factory: Any
) -> None:
    honeypot_id, company_id = await _honeypot(db_session_factory)
    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, honeypot_id)
        assert honeypot is not None
        await watched_files.set_paths(db, honeypot, ["/etc/hosts"])
    await login_as(client, company_id=company_id, access_level=AccessLevel.READ)

    page = await client.get(f"/honeypots/{honeypot_id}/files")
    posted = await client.post(
        f"/honeypots/{honeypot_id}/files",
        data={"csrf_token": client.cookies.get("csrftoken") or "", "paths": ""},
    )

    assert page.status_code == 200 and "/etc/hosts" in page.text
    assert 'name="paths"' not in page.text
    assert posted.status_code == 403


async def test_removing_a_path_forgets_the_file(
    client: AsyncClient, login_as: Any, db_session_factory: Any
) -> None:
    honeypot_id, _company = await _honeypot(db_session_factory)
    headers = await _api_headers(client, login_as, db_session_factory)
    url = f"/api/v1/honeypots/{honeypot_id}/watched-files"

    both = await client.put(url, headers=headers, json={"paths": ["/etc/a", "/etc/b"]})
    one = await client.put(url, headers=headers, json={"paths": ["/etc/b"]})
    bad = await client.put(url, headers=headers, json={"paths": ["/etc/../x"]})

    assert [f["path"] for f in both.json()] == ["/etc/a", "/etc/b"]
    assert [f["path"] for f in one.json()] == ["/etc/b"]
    assert bad.status_code == 422
