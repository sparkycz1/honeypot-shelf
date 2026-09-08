"""HoneyHive's own NetBird connection (Settings -> NetBird) —
`app.services.netbird` (subprocess control, mocked here — there's no real
`netbird` daemon/socket in the test environment) and the Settings routes
built on top of it."""

from __future__ import annotations

import re

import pytest

from app.services import netbird

pytestmark = pytest.mark.asyncio


def _csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


class _FakeProcess:
    def __init__(self, *, stdout: bytes, returncode: int) -> None:
        self._stdout = stdout
        self.returncode = returncode
        self.killed = False

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, b""

    def kill(self) -> None:
        self.killed = True


async def test_run_raises_unavailable_when_binary_missing(monkeypatch):
    async def _fake_exec(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr("asyncio.create_subprocess_exec", _fake_exec)
    with pytest.raises(netbird.NetbirdUnavailableError):
        await netbird.connect(setup_key="abc123", management_url=None)


async def test_run_raises_command_error_on_nonzero_exit(monkeypatch):
    async def _fake_exec(*args, **kwargs):
        return _FakeProcess(stdout=b"invalid setup key", returncode=1)

    monkeypatch.setattr("asyncio.create_subprocess_exec", _fake_exec)
    with pytest.raises(netbird.NetbirdCommandError) as exc_info:
        await netbird.connect(setup_key="abc123", management_url=None)
    assert "invalid setup key" in exc_info.value.output


async def test_connect_passes_setup_key_and_management_url(monkeypatch):
    captured_program = ""
    captured_args: tuple[str, ...] = ()

    async def _fake_exec(program, *args, **kwargs):
        nonlocal captured_program, captured_args
        captured_program = program
        captured_args = args
        return _FakeProcess(stdout=b"Connecting", returncode=0)

    monkeypatch.setattr("asyncio.create_subprocess_exec", _fake_exec)
    await netbird.connect(setup_key="my-key", management_url="https://nb.example.com")

    assert captured_program == "netbird"
    assert "up" in captured_args
    assert "--setup-key" in captured_args and "my-key" in captured_args
    assert "--management-url" in captured_args and "https://nb.example.com" in captured_args


async def test_status_parses_connected(monkeypatch):
    async def _fake_exec(*args, **kwargs):
        return _FakeProcess(
            stdout=b"Daemon version: 0.34.0\nManagement: Connected\nPeers count: 1/1 Connected",
            returncode=0,
        )

    monkeypatch.setattr("asyncio.create_subprocess_exec", _fake_exec)
    result = await netbird.status()
    assert result.connected is True
    assert "Management: Connected" in result.raw


async def test_status_unavailable_when_daemon_unreachable(monkeypatch):
    async def _fake_exec(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr("asyncio.create_subprocess_exec", _fake_exec)
    result = await netbird.status()
    assert result.connected is False
    assert result.error is not None


async def test_tail_log_missing_file_returns_empty(tmp_path, monkeypatch):
    from app.core.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("NETBIRD_LOG_PATH", str(tmp_path / "does-not-exist.log"))
    assert netbird.tail_log() == ""
    get_settings.cache_clear()


async def test_tail_log_returns_last_n_lines(tmp_path, monkeypatch):
    from app.core.config import get_settings

    log_path = tmp_path / "client.log"
    log_path.write_text("\n".join(f"line {i}" for i in range(1, 11)) + "\n")

    get_settings.cache_clear()
    monkeypatch.setenv("NETBIRD_LOG_PATH", str(log_path))
    tail = netbird.tail_log(lines=3)
    assert tail.strip().splitlines() == ["line 8", "line 9", "line 10"]
    get_settings.cache_clear()


# --- Settings -> NetBird routes --------------------------------------------


async def test_netbird_tab_shows_unavailable_without_the_sidecar(client):
    """No overlay applied in this test environment — the real behavior a
    deployment without docker-compose.vpn.yml sees too."""
    response = await client.get("/settings", params={"tab": "netbird"})
    assert response.status_code == 200
    assert "NetBird" in response.text


async def test_connect_saves_settings_and_reports_failure_cleanly(client, monkeypatch):
    """The daemon isn't reachable in tests — connecting should fail
    gracefully (a readable error, not a 500) while still saving the
    submitted config, exactly like a real deployment before the sidecar is
    up yet."""
    form = await client.get("/settings", params={"tab": "netbird"})
    response = await client.post(
        "/settings/netbird",
        data={
            "netbird_setup_key": "test-setup-key",
            "netbird_management_url": "https://nb.example.com",
            "csrf_token": _csrf_from(form),
        },
    )
    assert response.status_code == 200
    assert "netbird" in response.text.lower()


async def test_connect_rejects_malformed_management_url(client):
    form = await client.get("/settings", params={"tab": "netbird"})
    response = await client.post(
        "/settings/netbird",
        data={
            "netbird_setup_key": "test-setup-key",
            "netbird_management_url": "not-a-url",
            "csrf_token": _csrf_from(form),
        },
    )
    assert response.status_code == 200
    assert "http://" in response.text


async def test_connect_requires_a_setup_key_the_first_time(client):
    form = await client.get("/settings", params={"tab": "netbird"})
    response = await client.post(
        "/settings/netbird",
        data={
            "netbird_setup_key": "",
            "netbird_management_url": "",
            "csrf_token": _csrf_from(form),
        },
    )
    assert response.status_code == 200
    assert "setup key" in response.text.lower() or "Setup key" in response.text


async def test_connect_succeeds_when_netbird_mocked(client, monkeypatch):
    async def _fake_connect(*, setup_key, management_url):
        assert setup_key == "test-setup-key"
        return "Connected"

    monkeypatch.setattr("app.web.routes.settings.netbird.connect", _fake_connect)

    form = await client.get("/settings", params={"tab": "netbird"})
    response = await client.post(
        "/settings/netbird",
        data={
            "netbird_setup_key": "test-setup-key",
            "netbird_management_url": "",
            "csrf_token": _csrf_from(form),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/settings?tab=netbird"


async def test_disconnect_and_restart_flow(client, monkeypatch):
    connect_calls = []
    disconnect_calls = []

    async def _fake_connect(*, setup_key, management_url):
        connect_calls.append(setup_key)
        return "Connected"

    async def _fake_disconnect():
        disconnect_calls.append(True)
        return "Disconnected"

    monkeypatch.setattr("app.web.routes.settings.netbird.connect", _fake_connect)
    monkeypatch.setattr("app.web.routes.settings.netbird.disconnect", _fake_disconnect)

    form = await client.get("/settings", params={"tab": "netbird"})
    await client.post(
        "/settings/netbird",
        data={
            "netbird_setup_key": "test-setup-key",
            "netbird_management_url": "",
            "csrf_token": _csrf_from(form),
        },
    )
    assert connect_calls == ["test-setup-key"]

    disconnect_response = await client.post(
        "/settings/netbird/disconnect",
        data={"csrf_token": _csrf_from(form)},
        follow_redirects=False,
    )
    assert disconnect_response.status_code == 303
    assert disconnect_calls == [True]

    restart_response = await client.post(
        "/settings/netbird/restart",
        data={"csrf_token": _csrf_from(form)},
        follow_redirects=False,
    )
    assert restart_response.status_code == 303
    # restart() = disconnect() then connect() again, reusing the stored key.
    assert disconnect_calls == [True, True]
    assert connect_calls == ["test-setup-key", "test-setup-key"]
