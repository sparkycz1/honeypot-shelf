"""Live log following: the `-f` command builder (`app.ssh.logs.
build_follow_command`) and the WebSocket handler (`app/web/routes/
logs_ws.py`). Ported from debcontrol. The handler's own authentication is
`terminal_ws._authenticate`, covered with the terminal; here it is
replaced so the test drives the streaming part directly."""

from __future__ import annotations

import asyncio
import json
import types
from typing import Any

import pytest
from sqlalchemy import select

from app.db.models.audit_log import AuditLogEntry
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.user import AuthProvider, User
from app.ssh.exceptions import SSHConnectionError
from app.ssh.logs import LogAccessError, build_follow_command
from app.web.routes import logs_ws as logs_ws_module
from app.web.routes.logs_ws import follow_logs_websocket


def test_follow_journal_command():
    assert build_follow_command(source="journal", path="", search="") == (
        "journalctl --no-pager -f -n 50"
    )
    command = build_follow_command(
        source="journal", path="", search="a b", priority="err", unit="opencanary.service"
    )
    assert command == "journalctl --no-pager -f -n 50 -g 'a b' -p err -u opencanary.service"


def test_follow_file_command_quotes_and_filters():
    command = build_follow_command(source="file", path="/var/log/syslog", search="o'k")
    assert command.startswith("tail -n 50 -F -- /var/log/syslog 2>&1")
    assert "grep --line-buffered -F --" in command
    assert "'o'\"'\"'k'" in command


def test_follow_refuses_disallowed_paths_and_unknown_sources():
    with pytest.raises(LogAccessError):
        build_follow_command(source="file", path="/etc/shadow", search="")
    with pytest.raises(LogAccessError):
        build_follow_command(source="nope", path="", search="")


class _FakeWebSocket:
    def __init__(self, db_session_factory: Any, params: dict[str, str]) -> None:
        self.app = types.SimpleNamespace(
            state=types.SimpleNamespace(db_session_factory=db_session_factory)
        )
        self.query_params = params
        self.accepted = False
        self.closed: tuple[int, str] | None = None
        self.sent_text: list[str] = []
        self._never = asyncio.Event()

    async def accept(self) -> None:
        self.accepted = True

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = (code, reason)

    async def send_text(self, text: str) -> None:
        self.sent_text.append(text)

    async def receive(self) -> dict[str, Any]:
        await self._never.wait()
        return {"type": "websocket.disconnect"}


class _LinesStdout:
    def __init__(self, lines: list[str]) -> None:
        self._lines = list(lines)

    async def readline(self) -> str:
        return self._lines.pop(0) if self._lines else ""


class _LinesProcess:
    def __init__(self, lines: list[str]) -> None:
        self.stdout = _LinesStdout(lines)
        self.terminated = False

    def terminate(self) -> None:
        self.terminated = True


class _FakeConnection:
    def __init__(self, process: _LinesProcess) -> None:
        self.process = process
        self.commands: list[str] = []
        self.closed = False

    async def create_process(self, command: str, **kwargs: object) -> _LinesProcess:
        self.commands.append(command)
        return self.process

    def close(self) -> None:
        self.closed = True


async def _setup(db_session_factory, monkeypatch) -> Honeypot:
    async with db_session_factory() as db:
        user = (await db.execute(select(User))).scalars().first()
        if user is None:
            user = User(
                username="follower",
                auth_provider=AuthProvider.LOCAL,
                is_active=True,
                is_superadmin=True,
            )
            db.add(user)
        honeypot = Honeypot(
            name="acme-honey1",
            ip_address="192.0.2.10",
            port=22,
            username="honeypotshelf",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fake",
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
        await db.refresh(user)

    async def _fake_auth(websocket, honeypot_id):
        return user, honeypot

    async def _no_secret(honeypot, db):
        return None

    monkeypatch.setattr(logs_ws_module, "_authenticate", _fake_auth)
    monkeypatch.setattr(logs_ws_module, "resolve_honeypot_credential", _no_secret)
    return honeypot


async def test_follow_streams_lines_audits_and_tears_down(db_session_factory, monkeypatch):
    honeypot = await _setup(db_session_factory, monkeypatch)
    process = _LinesProcess(["first\n", "second\r\n"])
    conn = _FakeConnection(process)

    async def _fake_open(honeypot, secret, timeout_seconds):
        return conn

    monkeypatch.setattr(logs_ws_module, "open_connection", _fake_open)
    ws = _FakeWebSocket(db_session_factory, {"unit": "opencanary.service"})

    await follow_logs_websocket(ws, honeypot.id)  # type: ignore[arg-type]

    frames = [json.loads(text) for text in ws.sent_text]
    assert frames[:2] == [{"t": "line", "v": "first"}, {"t": "line", "v": "second"}]
    assert frames[-1] == {"t": "end", "v": "The log stream ended."}
    assert conn.commands == ["journalctl --no-pager -f -n 50 -u opencanary.service"]
    assert process.terminated and conn.closed

    async with db_session_factory() as db:
        actions = [e.action for e in (await db.execute(select(AuditLogEntry))).scalars()]
    assert "honeypot.logs.follow" in actions
    assert "honeypot.logs.follow_end" in actions


async def test_follow_rejects_a_disallowed_path_before_accepting(
    db_session_factory, monkeypatch
):
    honeypot = await _setup(db_session_factory, monkeypatch)
    ws = _FakeWebSocket(db_session_factory, {"path": "/etc/shadow"})

    await follow_logs_websocket(ws, honeypot.id)  # type: ignore[arg-type]

    assert not ws.accepted
    assert ws.closed is not None and ws.closed[0] == 1008


async def test_follow_reports_a_connection_failure(db_session_factory, monkeypatch):
    honeypot = await _setup(db_session_factory, monkeypatch)

    async def _fail(honeypot, secret, timeout_seconds):
        raise SSHConnectionError("connection refused")

    monkeypatch.setattr(logs_ws_module, "open_connection", _fail)
    ws = _FakeWebSocket(db_session_factory, {})

    await follow_logs_websocket(ws, honeypot.id)  # type: ignore[arg-type]

    assert ws.accepted
    assert json.loads(ws.sent_text[-1]) == {"t": "error", "v": "connection refused"}
    assert ws.closed is not None and ws.closed[0] == 1011
