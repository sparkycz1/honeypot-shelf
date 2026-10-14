"""Recording browser terminal sessions (`app.services.terminal_recording`):
off by default, output only, stored encrypted, replayed by a superadmin,
purged after its own retention. Ported from debcontrol."""

from __future__ import annotations

import asyncio
import re
import types
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from httpx2 import AsyncClient
from sqlalchemy import select

from app.auth.api_tokens import create_api_token
from app.core.app_settings import get_or_create_app_settings
from app.db.models.access_level import AccessLevel
from app.db.models.audit_log import AuditLogEntry
from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.terminal_recording import TerminalRecording
from app.db.models.user import AuthProvider, User
from app.services import terminal_recording
from app.tasks import jobs
from app.web.routes import terminal_ws as terminal_ws_module
from app.web.routes.terminal_ws import terminal_websocket
from tests.conftest import create_company


def test_recorder_keeps_output_in_order_and_joins_split_characters() -> None:
    recorder = terminal_recording.Recorder(cols=80, rows=24)

    recorder.output(b"ls\r\n")
    recorder.output("ž".encode()[:1])  # a multi-byte character split in two
    recorder.output("ž".encode()[1:] + b"x")
    recorder.resize(120, 40)

    cast = terminal_recording.parse_cast(recorder.cast())
    assert (cast["cols"], cast["rows"]) == (80, 24)
    assert [(e[1], e[2]) for e in cast["events"]] == [("o", "ls\r\n"), ("o", "žx"), ("r", "120x40")]
    assert all(isinstance(e[0], int | float) for e in cast["events"])
    assert recorder.output_bytes == 7 and not recorder.truncated


def test_recorder_stops_at_the_size_limit(monkeypatch: Any) -> None:
    monkeypatch.setattr(terminal_recording, "MAX_OUTPUT_BYTES", 10)
    recorder = terminal_recording.Recorder(cols=80, rows=24)

    recorder.output(b"12345678")
    recorder.output(b"abcdefgh")
    recorder.output(b"ignored")

    assert recorder.truncated and recorder.output_bytes == 10
    assert "".join(e[2] for e in recorder.events) == "12345678ab"


def test_a_recording_is_stored_unreadable_and_reads_back() -> None:
    cast = '{"version": 2, "width": 80, "height": 24}\n[0.5, "o", "secret-token-123"]\n'

    packed = terminal_recording.pack(cast)

    assert b"secret-token-123" not in packed
    assert terminal_recording.unpack(packed) == cast
    assert terminal_recording.parse_cast("not json\n[1]\n")["events"] == []


class _FakeWebSocket:
    def __init__(self, db_session_factory: Any) -> None:
        self.app = types.SimpleNamespace(
            state=types.SimpleNamespace(db_session_factory=db_session_factory)
        )
        self.closed: tuple[int, str] | None = None

    async def accept(self) -> None:
        pass

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = (code, reason)

    async def send_text(self, text: str) -> None:
        pass

    async def send_bytes(self, data: bytes) -> None:
        pass

    async def receive(self) -> dict[str, Any]:
        await asyncio.sleep(999)
        return {"type": "websocket.disconnect"}  # pragma: no cover - never reached


class _Stdout:
    """A shell that prints two chunks and exits."""

    def __init__(self) -> None:
        self._chunks = [b"$ whoami\r\n", b"root\r\n"]

    async def read(self, n: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""


class _Process:
    def __init__(self) -> None:
        self.stdout = _Stdout()
        self.stdin = types.SimpleNamespace(write=lambda data: None)

    def change_terminal_size(self, cols: int, rows: int) -> None:
        pass

    def terminate(self) -> None:
        pass


class _Connection:
    def close(self) -> None:
        pass


async def _make_honeypot(db_session_factory: Any) -> Honeypot:
    async with db_session_factory() as db:
        honeypot = Honeypot(
            name="term-honeypot",
            ip_address="192.0.2.5",
            port=22,
            username="honeypotshelf",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fake",
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
        return honeypot


async def _run_session(db_session_factory: Any, monkeypatch: Any) -> uuid.UUID:
    honeypot = await _make_honeypot(db_session_factory)
    async with db_session_factory() as db:
        user = User(
            username="operator",
            auth_provider=AuthProvider.LOCAL,
            is_active=True,
            is_superadmin=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

    async def fake_auth(websocket: Any, honeypot_id: Any) -> Any:
        return user, honeypot

    async def no_secret(honeypot: Any, db: Any) -> None:
        return None

    async def fake_open(*_args: Any, **_kwargs: Any) -> tuple[Any, Any]:
        return _Connection(), _Process()

    monkeypatch.setattr(terminal_ws_module, "_authenticate", fake_auth)
    monkeypatch.setattr(terminal_ws_module, "resolve_honeypot_credential", no_secret)
    monkeypatch.setattr(terminal_ws_module, "open_shell_session", fake_open)
    await terminal_websocket(_FakeWebSocket(db_session_factory), honeypot.id)  # type: ignore[arg-type]
    return honeypot.id


async def test_nothing_is_recorded_unless_turned_on(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    await _run_session(db_session_factory, monkeypatch)

    async with db_session_factory() as db:
        assert (await db.execute(select(TerminalRecording))).scalars().first() is None


async def test_a_session_is_recorded_when_turned_on(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    async with db_session_factory() as db:
        (await get_or_create_app_settings(db)).terminal_recording_enabled = True
        await db.commit()

    honeypot_id = await _run_session(db_session_factory, monkeypatch)

    async with db_session_factory() as db:
        recording = (await db.execute(select(TerminalRecording))).scalar_one()
        close = (
            await db.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "honeypot.terminal.close")
            )
        ).scalar_one()
    assert recording.honeypot_id == honeypot_id and recording.honeypot_name == "term-honeypot"
    assert recording.output_bytes == len(b"$ whoami\r\nroot\r\n")
    assert b"whoami" not in recording.data_encrypted
    cast = terminal_recording.parse_cast(terminal_recording.unpack(recording.data_encrypted))
    assert "".join(e[2] for e in cast["events"]) == "$ whoami\r\nroot\r\n"
    assert close.details is not None and close.details["recording_id"] == str(recording.id)


async def _stored(db_session_factory: Any, *, days_ago: int = 0) -> uuid.UUID:
    async with db_session_factory() as db:
        recording = TerminalRecording(
            honeypot_id=None,
            honeypot_name="gone-honeypot",
            username="alice",
            started_at=datetime.now(UTC) - timedelta(days=days_ago),
            duration_seconds=95.0,
            cols=80,
            rows=24,
            output_bytes=6,
            data_encrypted=terminal_recording.pack(
                '{"version": 2, "width": 80, "height": 24}\n[0.1, "o", "hello\\r\\n"]\n'
            ),
        )
        db.add(recording)
        await db.commit()
        return recording.id


async def test_recordings_page_player_and_audit(
    client: AsyncClient, db_session_factory: Any
) -> None:
    recording_id = await _stored(db_session_factory)

    listing = await client.get("/audit/terminal-recordings")
    page = await client.get(f"/audit/terminal-recordings/{recording_id}")
    cast = await client.get(f"/audit/terminal-recordings/{recording_id}/cast")
    missing = await client.get(f"/audit/terminal-recordings/{uuid.uuid4()}")
    audit_page = await client.get("/audit")

    assert listing.status_code == 200
    assert "gone-honeypot" in listing.text and "alice" in listing.text
    # Off by default, and the page says so.
    assert "Recording is off" in listing.text
    assert page.status_code == 200 and "terminal-player.js" in page.text
    assert f'data-cast-url="/audit/terminal-recordings/{recording_id}/cast"' in page.text
    assert cast.headers["cache-control"] == "no-store"
    assert cast.json() == {"cols": 80, "rows": 24, "events": [[0.1, "o", "hello\r\n"]]}
    assert missing.status_code == 404
    assert 'href="/audit/terminal-recordings"' in audit_page.text
    async with db_session_factory() as db:
        actions = list((await db.execute(select(AuditLogEntry.action))).scalars().all())
    # Opening the page is not watching; fetching the content is.
    assert actions.count("terminal.recording.view") == 1


async def test_recordings_are_superadmin_only(
    client: AsyncClient, login_as: Any, db_session_factory: Any
) -> None:
    recording_id = await _stored(db_session_factory)
    company = await create_company(db_session_factory)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ_WRITE)

    for path in (
        "/audit/terminal-recordings",
        f"/audit/terminal-recordings/{recording_id}",
        f"/audit/terminal-recordings/{recording_id}/cast",
    ):
        assert (await client.get(path)).status_code == 403, path


async def test_settings_turn_recording_on_and_the_terminal_page_says_so(
    client: AsyncClient, db_session_factory: Any
) -> None:
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, company.id)],
            name="hp",
            ip_address="192.0.2.9",
            username="honeypotshelf",
            host_key_fingerprint="SHA256:fake",
        )
        db.add(honeypot)
        await db.commit()
        honeypot_id = honeypot.id
    settings_page = await client.get("/settings?tab=security")
    match = re.search(r'name="csrf_token" value="([^"]+)"', settings_page.text)
    assert match is not None
    before = await client.get(f"/honeypots/{honeypot_id}/terminal")

    saved = await client.post(
        "/settings/terminal-recording",
        data={"csrf_token": match.group(1), "enabled": "1", "retention_days": "7"},
        follow_redirects=False,
    )
    after = await client.get(f"/honeypots/{honeypot_id}/terminal")

    assert "Record browser terminal sessions" in settings_page.text
    assert "This session is recorded" not in before.text
    assert saved.status_code == 303
    assert "This session is recorded" in after.text
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        assert app_settings.terminal_recording_enabled is True
        assert app_settings.terminal_recording_retention_days == 7
        actions = list((await db.execute(select(AuditLogEntry.action))).scalars().all())
    assert "settings.terminal_recording.update" in actions


async def test_old_recordings_are_purged(db_session_factory: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    old = await _stored(db_session_factory, days_ago=40)
    fresh = await _stored(db_session_factory, days_ago=1)

    await jobs._purge_old_terminal_recordings()

    async with db_session_factory() as db:
        left = list((await db.execute(select(TerminalRecording.id))).scalars().all())
        actions = list((await db.execute(select(AuditLogEntry.action))).scalars().all())
    assert left == [fresh] and old not in left
    assert "terminal_recordings.purge" in actions


async def test_recordings_api(client: AsyncClient, login_as: Any, db_session_factory: Any) -> None:
    recording_id = await _stored(db_session_factory)
    user = await login_as(client, username="api-admin", is_superadmin=True, api_access_enabled=True)
    async with db_session_factory() as db:
        db_user = await db.get(User, user.id)
        assert db_user is not None
        _token, raw = await create_api_token(db, db_user, name="t", expires_at=None)
    headers = {"Authorization": f"Bearer {raw}"}

    listing = await client.get("/api/v1/terminal-recordings", headers=headers)
    one = await client.get(f"/api/v1/terminal-recordings/{recording_id}", headers=headers)
    missing = await client.get(f"/api/v1/terminal-recordings/{uuid.uuid4()}", headers=headers)
    settings = await client.get("/api/v1/settings", headers=headers)

    assert [r["id"] for r in listing.json()["recordings"]] == [str(recording_id)]
    assert "events" not in listing.json()["recordings"][0]
    assert one.json()["events"] == [[0.1, "o", "hello\r\n"]]
    assert one.json()["username"] == "alice"
    assert missing.status_code == 404
    assert settings.json()["terminal_recording_enabled"] is False
    assert settings.json()["terminal_recording_retention_days"] == 30
