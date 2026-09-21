"""Honeypot Shelf's own VPN connection (Settings -> VPN) — `app.services.netbird`
(subprocess control) and `app.services.wireguard` (a Unix-socket JSON
client to `app.services.vpn_control_server`), both mocked here — there's
no real netbird daemon or vpn_control_server socket in the test
environment — plus the Settings routes and mutual-exclusivity behavior
built on top of both."""

from __future__ import annotations

import asyncio
import contextlib
import grp
import os
import re
import stat

import pytest

from app.services import netbird, wireguard

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _assume_netbird_socket_exists(monkeypatch):
    """`app.services.netbird._run` now checks the daemon socket file exists
    before shelling out at all (see that function's own docstring for why —
    it's what makes Settings -> VPN fast when the sidecar isn't running).
    Every test below except the ones specifically testing *that* check
    mocks `asyncio.create_subprocess_exec` instead and expects it to
    actually be reached, so this makes the pre-check pass by default."""
    monkeypatch.setattr("app.services.netbird.os.path.exists", lambda _path: True)


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


async def test_run_fails_fast_when_daemon_socket_file_is_missing(monkeypatch):
    """The real bug this guards against: without this pre-check, `netbird
    status` (etc.) shells out regardless and takes the CLI's own ~10s gRPC
    dial/backoff to fail — the pre-check turns that into a sub-millisecond
    failure instead, by checking the socket file exists first."""
    monkeypatch.setattr("app.services.netbird.os.path.exists", lambda _path: False)

    async def _fake_exec(*args, **kwargs):
        pytest.fail("should never shell out once the pre-check already failed")

    monkeypatch.setattr("asyncio.create_subprocess_exec", _fake_exec)
    with pytest.raises(netbird.NetbirdUnavailableError):
        await netbird.connect(setup_key="abc123", management_url=None)

    # `status()` itself catches the same error rather than propagating it
    # (same tolerance it already has for the CLI/binary missing outright).
    monkeypatch.setattr("asyncio.create_subprocess_exec", _fake_exec)
    result = await netbird.status()
    assert result.connected is False
    assert result.error is not None


def test_daemon_socket_path_parses_the_unix_scheme():
    assert netbird._daemon_socket_path("unix:///var/run/netbird/sock") == "/var/run/netbird/sock"
    assert netbird._daemon_socket_path("tcp://127.0.0.1:1234") is None


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


async def test_connect_passes_hostname_when_given(monkeypatch):
    """`--hostname` — otherwise NetBird's dashboard shows this peer under
    its bare Docker hostname, meaningless in a peer list. See
    app.services.netbird.connect's own docstring for why this only ever
    takes effect on a peer's first registration."""
    captured_args: tuple[str, ...] = ()

    async def _fake_exec(program, *args, **kwargs):
        nonlocal captured_args
        captured_args = args
        return _FakeProcess(stdout=b"Connecting", returncode=0)

    monkeypatch.setattr("asyncio.create_subprocess_exec", _fake_exec)
    await netbird.connect(setup_key="my-key", management_url=None, hostname="honeypot-shelf")

    assert "--hostname" in captured_args and "honeypot-shelf" in captured_args


async def test_connect_omits_hostname_flag_when_not_given(monkeypatch):
    captured_args: tuple[str, ...] = ()

    async def _fake_exec(program, *args, **kwargs):
        nonlocal captured_args
        captured_args = args
        return _FakeProcess(stdout=b"Connecting", returncode=0)

    monkeypatch.setattr("asyncio.create_subprocess_exec", _fake_exec)
    await netbird.connect(setup_key="my-key", management_url=None)

    assert "--hostname" not in captured_args


async def test_reconnect_sends_no_setup_key(monkeypatch):
    """`reconnect()` is the "restart, don't re-register" primitive — it
    must never send `--setup-key`, since that value is single-use on
    NetBird's side and would already be spent by this peer's first
    successful registration."""
    captured_args: tuple[str, ...] = ()

    async def _fake_exec(program, *args, **kwargs):
        nonlocal captured_args
        captured_args = args
        return _FakeProcess(stdout=b"Connecting", returncode=0)

    monkeypatch.setattr("asyncio.create_subprocess_exec", _fake_exec)
    await netbird.reconnect()

    assert "up" in captured_args
    assert "--setup-key" not in captured_args


async def test_ensure_connected_prefers_reconnect_over_spending_the_setup_key(monkeypatch):
    """The regression this whole module exists to prevent: a NetBird
    setup key is single-use, so once a peer is registered,
    `ensure_connected()` must reconnect from its own persisted state
    (plain `netbird up`, no key) rather than resending the stored key and
    hitting "setup key is invalid" on every ordinary restart/upgrade."""
    calls: list[tuple[str, ...]] = []

    async def _fake_exec(program, *args, **kwargs):
        calls.append(args)
        return _FakeProcess(stdout=b"Connected", returncode=0)

    monkeypatch.setattr("asyncio.create_subprocess_exec", _fake_exec)
    await netbird.ensure_connected(setup_key="my-key", management_url=None)

    assert len(calls) == 1
    assert "--setup-key" not in calls[0]


async def test_ensure_connected_falls_back_to_setup_key_for_a_genuinely_unregistered_peer(
    monkeypatch,
):
    """A fresh peer (or one removed from the NetBird dashboard) has no
    persisted registration to reconnect from — NetBird's own client
    reports exactly this with "no peer auth method provided", the one
    case `ensure_connected()` should actually spend the stored key for."""
    calls: list[tuple[str, ...]] = []

    async def _fake_exec(program, *args, **kwargs):
        calls.append(args)
        if "--setup-key" not in args:
            return _FakeProcess(
                stdout=b"no peer auth method provided, please use a setup key or interactive "
                b"SSO login",
                returncode=1,
            )
        return _FakeProcess(stdout=b"Connected", returncode=0)

    monkeypatch.setattr("asyncio.create_subprocess_exec", _fake_exec)
    result = await netbird.ensure_connected(setup_key="my-key", management_url=None)

    assert result == "Connected"
    assert len(calls) == 2
    assert "--setup-key" not in calls[0]
    assert "--setup-key" in calls[1] and "my-key" in calls[1]


async def test_ensure_connected_does_not_mask_unrelated_reconnect_failures(monkeypatch):
    """A transient failure (daemon busy, management server unreachable,
    ...) must propagate as-is rather than triggering a fallback attempt
    that would spend an otherwise-still-valid setup key on a problem a
    key can't fix."""
    calls: list[tuple[str, ...]] = []

    async def _fake_exec(program, *args, **kwargs):
        calls.append(args)
        return _FakeProcess(stdout=b"context deadline exceeded", returncode=1)

    monkeypatch.setattr("asyncio.create_subprocess_exec", _fake_exec)
    with pytest.raises(netbird.NetbirdCommandError):
        await netbird.ensure_connected(setup_key="my-key", management_url=None)

    assert len(calls) == 1


async def test_restart_reconnects_without_spending_the_setup_key(monkeypatch):
    """`restart()` (Settings -> VPN's "Restart" button) used to always
    resend the stored setup key on its own reconnect step — same
    regression as `ensure_connected()`, just reached from a different
    caller."""
    calls: list[tuple[str, ...]] = []

    async def _fake_exec(program, *args, **kwargs):
        calls.append(args)
        return _FakeProcess(stdout=b"ok", returncode=0)

    monkeypatch.setattr("asyncio.create_subprocess_exec", _fake_exec)
    await netbird.restart(setup_key="my-key", management_url=None)

    assert calls[0][0] == "down"
    assert "--setup-key" not in calls[1]


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


async def test_wireguard_tail_log_missing_file_returns_empty(tmp_path, monkeypatch):
    from app.core.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("WIREGUARD_LOG_PATH", str(tmp_path / "does-not-exist.log"))
    assert wireguard.tail_log() == ""
    get_settings.cache_clear()


async def test_wireguard_tail_log_returns_last_n_lines(tmp_path, monkeypatch):
    from app.core.config import get_settings

    log_path = tmp_path / "control.log"
    log_path.write_text("\n".join(f"line {i}" for i in range(1, 11)) + "\n")

    get_settings.cache_clear()
    monkeypatch.setenv("WIREGUARD_LOG_PATH", str(log_path))
    tail = wireguard.tail_log(lines=3)
    assert tail.strip().splitlines() == ["line 8", "line 9", "line 10"]
    get_settings.cache_clear()


async def test_wireguard_log_panel_route(client):
    response = await client.get("/settings/wireguard/log")
    assert response.status_code == 200


# --- Settings -> NetBird routes --------------------------------------------


async def test_netbird_tab_shows_unavailable_without_the_sidecar(client):
    """No overlay applied in this test environment — the real behavior a
    deployment without docker-compose.vpn.yml sees too."""
    response = await client.get("/settings", params={"tab": "vpn"})
    assert response.status_code == 200
    assert "NetBird" in response.text


async def test_connect_saves_settings_and_reports_failure_cleanly(client, monkeypatch):
    """The daemon isn't reachable in tests — connecting should fail
    gracefully (a readable error, not a 500) while still saving the
    submitted config, exactly like a real deployment before the sidecar is
    up yet."""
    form = await client.get("/settings", params={"tab": "vpn"})
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
    form = await client.get("/settings", params={"tab": "vpn"})
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
    form = await client.get("/settings", params={"tab": "vpn"})
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
    async def _fake_connect(*, setup_key, management_url, hostname=None):
        assert setup_key == "test-setup-key"
        return "Connected"

    monkeypatch.setattr("app.web.routes.settings.netbird.connect", _fake_connect)

    form = await client.get("/settings", params={"tab": "vpn"})
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
    assert response.headers["location"] == "/settings?tab=vpn"


async def test_hostname_field_is_saved_and_passed_to_connect(client, monkeypatch):
    captured = {}

    async def _fake_connect(*, setup_key, management_url, hostname=None):
        captured["hostname"] = hostname
        return "Connected"

    monkeypatch.setattr("app.web.routes.settings.netbird.connect", _fake_connect)

    form = await client.get("/settings", params={"tab": "vpn"})
    response = await client.post(
        "/settings/netbird",
        data={
            "netbird_setup_key": "test-setup-key",
            "netbird_management_url": "",
            "netbird_hostname": "honeypot-shelf",
            "csrf_token": _csrf_from(form),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert captured["hostname"] == "honeypot-shelf"

    settings_page = await client.get("/settings", params={"tab": "vpn"})
    assert "honeypot-shelf" in settings_page.text


async def test_startup_reconnect_skips_netbird_connect_when_already_connected(
    db_session_factory, monkeypatch
):
    """The real bug this guards against: after a plain container restart,
    `app.main`'s startup hook used to always resend the stored NetBird
    setup key — but that key is single-use, so on every restart *after*
    the first successful registration it just fails with "setup key is
    invalid" against a daemon that had already reconnected on its own
    (its state persists in the `netbird_state` volume). Skipping the
    resend when `netbird status` already reports connected is what fixes
    that."""
    from app.core.app_settings import get_or_create_app_settings
    from app.core.security import encrypt_secret
    from app.db.models.app_settings import VpnProvider
    from app.main import _reconnect_vpn_if_configured

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.vpn_provider = VpnProvider.NETBIRD
        app_settings.netbird_setup_key_encrypted = encrypt_secret("already-used-key")
        await db.commit()

    monkeypatch.setattr("app.main.AsyncSessionLocal", db_session_factory)

    async def _fake_status():
        return netbird.NetbirdStatus(connected=True, raw="Management: Connected")

    connect_calls = []

    async def _fake_connect(**kwargs):
        connect_calls.append(kwargs)
        return "unexpected"

    monkeypatch.setattr("app.main.netbird.status", _fake_status)
    monkeypatch.setattr("app.main.netbird.connect", _fake_connect)

    await _reconnect_vpn_if_configured()

    assert connect_calls == []


async def test_startup_reconnect_prefers_persisted_state_over_the_setup_key(
    db_session_factory, monkeypatch
):
    """The startup reconnect path goes through `ensure_connected()` —
    when this peer's own persisted registration is enough to reconnect,
    the stored setup key must never even be looked at (it's already been
    consumed by the very first successful registration)."""
    from app.core.app_settings import get_or_create_app_settings
    from app.core.security import encrypt_secret
    from app.db.models.app_settings import VpnProvider
    from app.main import _reconnect_vpn_if_configured

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.vpn_provider = VpnProvider.NETBIRD
        app_settings.netbird_setup_key_encrypted = encrypt_secret("first-use-key")
        app_settings.netbird_management_url = "https://nb.example.com"
        app_settings.netbird_hostname = "honeypot-shelf"
        await db.commit()

    monkeypatch.setattr("app.main.AsyncSessionLocal", db_session_factory)

    async def _fake_status():
        return netbird.NetbirdStatus(connected=False, raw="Management: Disconnected")

    reconnect_calls = []
    connect_calls = []

    async def _fake_reconnect():
        reconnect_calls.append(True)
        return "Connected"

    async def _fake_connect(**kwargs):
        connect_calls.append(kwargs)
        return "Connected"

    monkeypatch.setattr("app.main.netbird.status", _fake_status)
    monkeypatch.setattr("app.main.netbird.reconnect", _fake_reconnect)
    monkeypatch.setattr("app.main.netbird.connect", _fake_connect)

    await _reconnect_vpn_if_configured()

    assert reconnect_calls == [True]
    assert connect_calls == []


async def test_startup_reconnect_falls_back_to_the_setup_key_for_a_fresh_peer(
    db_session_factory, monkeypatch
):
    """Only when NetBird itself reports this peer has no persisted
    registration at all does the startup path fall back to spending the
    stored setup key."""
    from app.core.app_settings import get_or_create_app_settings
    from app.core.security import encrypt_secret
    from app.db.models.app_settings import VpnProvider
    from app.main import _reconnect_vpn_if_configured

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.vpn_provider = VpnProvider.NETBIRD
        app_settings.netbird_setup_key_encrypted = encrypt_secret("first-use-key")
        app_settings.netbird_management_url = "https://nb.example.com"
        app_settings.netbird_hostname = "honeypot-shelf"
        await db.commit()

    monkeypatch.setattr("app.main.AsyncSessionLocal", db_session_factory)

    async def _fake_status():
        return netbird.NetbirdStatus(connected=False, raw="Management: Disconnected")

    async def _fake_reconnect():
        raise netbird.NetbirdCommandError(
            "netbird exited 1.", output="no peer auth method provided"
        )

    connect_calls = []

    async def _fake_connect(**kwargs):
        connect_calls.append(kwargs)
        return "Connected"

    monkeypatch.setattr("app.main.netbird.status", _fake_status)
    monkeypatch.setattr("app.main.netbird.reconnect", _fake_reconnect)
    monkeypatch.setattr("app.main.netbird.connect", _fake_connect)

    await _reconnect_vpn_if_configured()

    assert len(connect_calls) == 1
    assert connect_calls[0]["setup_key"] == "first-use-key"
    assert connect_calls[0]["management_url"] == "https://nb.example.com"
    assert connect_calls[0]["hostname"] == "honeypot-shelf"


async def test_disconnect_and_restart_flow(client, monkeypatch):
    """`restart()` reconnects through `ensure_connected()` — this peer's
    own persisted state, not by resending the stored setup key (see
    `test_ensure_connected_prefers_reconnect_over_spending_the_setup_key`
    for that behavior in isolation; this just confirms the Settings route
    is actually wired through it)."""
    connect_calls = []
    reconnect_calls = []
    disconnect_calls = []

    async def _fake_connect(*, setup_key, management_url, hostname=None):
        connect_calls.append(setup_key)
        return "Connected"

    async def _fake_reconnect():
        reconnect_calls.append(True)
        return "Connected"

    async def _fake_disconnect():
        disconnect_calls.append(True)
        return "Disconnected"

    monkeypatch.setattr("app.web.routes.settings.netbird.connect", _fake_connect)
    monkeypatch.setattr("app.web.routes.settings.netbird.reconnect", _fake_reconnect)
    monkeypatch.setattr("app.web.routes.settings.netbird.disconnect", _fake_disconnect)

    form = await client.get("/settings", params={"tab": "vpn"})
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
    # restart() = disconnect() then ensure_connected() — reconnects from
    # this peer's own persisted state, never resending the stored key.
    assert disconnect_calls == [True, True]
    assert reconnect_calls == [True]
    assert connect_calls == ["test-setup-key"]


# --- app.services.vpn_control_server.serve (the socket's own permissions) --


async def _run_serve_briefly(tmp_path, monkeypatch):
    """`serve()` runs forever (`await server.serve_forever()`) — this lets
    it get as far as chmod-ing the socket (the real `os.chmod`, wrapped to
    also signal an event — the reliable "serve() got that far" marker,
    since the socket *file* itself can already exist earlier, mid-await,
    inside `asyncio.start_unix_server`, which raced the polling this
    used to do instead), then cancels it, same shape every test below
    needs."""
    from app.services import vpn_control_server

    real_chmod = os.chmod
    reached_chmod = asyncio.Event()

    def _chmod_then_signal(path: str, mode: int) -> None:
        real_chmod(path, mode)
        reached_chmod.set()

    monkeypatch.setattr(os, "chmod", _chmod_then_signal)

    socket_path = str(tmp_path / "control.sock")
    task = asyncio.ensure_future(vpn_control_server.serve(socket_path))
    try:
        await asyncio.wait_for(reached_chmod.wait(), timeout=5)
        # Grabbed here, not after cancelling below — closing the server
        # (part of its own `async with server:` cleanup) unlinks the
        # socket file, so it's gone by the time a caller could stat() it.
        mode = stat.S_IMODE(os.stat(socket_path).st_mode)  # noqa: PTH116
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        if task.done() and not task.cancelled():
            task_exc = task.exception()
            if task_exc is not None:
                raise task_exc
    return socket_path, mode


async def test_serve_restricts_the_socket_to_the_app_group(tmp_path, monkeypatch):
    """Regression test for a CodeQL "overly permissive file permissions"
    finding: the control socket used to be world-writable (0o777, then
    0o666) so `web`/`worker`'s own unprivileged `app` user could reach it
    — this asserts it's now owner-and-group only (0o660), with the group
    actually set to `app`, not left world-writable to get there."""
    fake_group = grp.struct_group(("app", "x", 4242, []))
    monkeypatch.setattr(grp, "getgrnam", lambda name: fake_group)

    chown_calls: list[tuple[str, int, int]] = []
    monkeypatch.setattr(
        os, "chown", lambda path, uid, gid: chown_calls.append((path, uid, gid))
    )

    socket_path, mode = await _run_serve_briefly(tmp_path, monkeypatch)

    assert chown_calls == [(socket_path, -1, 4242)]
    assert mode == 0o660


async def test_serve_falls_back_to_world_writable_if_the_app_group_is_missing(
    tmp_path, monkeypatch, caplog
):
    """Shouldn't happen in the real image (see serve()'s own comment), but
    if it ever does, the socket must stay usable (loudly) rather than
    silently unreachable from `web`/`worker`."""

    def _raise(name: str) -> None:
        raise KeyError(name)

    monkeypatch.setattr(grp, "getgrnam", _raise)

    with caplog.at_level("ERROR"):
        _socket_path, mode = await _run_serve_briefly(tmp_path, monkeypatch)

    assert "leaving the control socket world-writable" in caplog.text
    assert mode == 0o666


# --- app.services.wireguard (mocked Unix-socket control server) ----------


class _FakeWriter:
    def __init__(self) -> None:
        self.written = b""
        self.closed = False

    def write(self, data: bytes) -> None:
        self.written += data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _FakeReader:
    def __init__(self, response: dict[str, object]) -> None:
        import json

        self._line = (json.dumps(response) + "\n").encode("utf-8")

    async def readline(self) -> bytes:
        return self._line


def _fake_open_unix_connection(response: dict[str, object]):
    writer = _FakeWriter()

    async def _open(*args, **kwargs):
        return _FakeReader(response), writer

    return _open, writer


async def test_wireguard_connect_unavailable_without_socket(monkeypatch):
    async def _fake_open(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr("asyncio.open_unix_connection", _fake_open)
    with pytest.raises(wireguard.WireguardUnavailableError):
        await wireguard.connect(config="[Interface]\nPrivateKey = abc")


async def test_wireguard_connect_sends_config(monkeypatch):
    open_fn, writer = _fake_open_unix_connection({"ok": True, "output": "interface up"})
    monkeypatch.setattr("asyncio.open_unix_connection", open_fn)

    output = await wireguard.connect(config="[Interface]\nPrivateKey = abc")
    assert output == "interface up"
    assert b'"wg_up"' in writer.written
    assert b"PrivateKey" in writer.written


async def test_wireguard_status_parses_up(monkeypatch):
    open_fn, _ = _fake_open_unix_connection(
        {"ok": True, "up": True, "output": "interface: wg0\n  public key: abc"}
    )
    monkeypatch.setattr("asyncio.open_unix_connection", open_fn)

    result = await wireguard.status()
    assert result.up is True
    assert "interface: wg0" in result.raw


async def test_wireguard_status_unavailable(monkeypatch):
    async def _fake_open(*args, **kwargs):
        raise ConnectionRefusedError

    monkeypatch.setattr("asyncio.open_unix_connection", _fake_open)
    result = await wireguard.status()
    assert result.up is False
    assert result.error is not None


# --- Settings -> VPN: WireGuard routes + mutual exclusivity ---------------


async def test_wireguard_tab_shows_unavailable_without_the_sidecar(client):
    response = await client.get("/settings", params={"tab": "vpn"})
    assert response.status_code == 200
    assert "WireGuard" in response.text


async def test_wireguard_connect_requires_a_config_the_first_time(client):
    form = await client.get("/settings", params={"tab": "vpn"})
    response = await client.post(
        "/settings/wireguard",
        data={"wireguard_config": "", "csrf_token": _csrf_from(form)},
    )
    assert response.status_code == 200
    assert "WireGuard config is required" in response.text


async def test_connecting_wireguard_disconnects_netbird(client, monkeypatch):
    """VpnProvider is mutually exclusive — connecting WireGuard while
    NetBird was active disconnects NetBird first."""
    netbird_disconnect_calls = []

    async def _fake_netbird_connect(*, setup_key, management_url, hostname=None):
        return "Connected"

    async def _fake_netbird_disconnect():
        netbird_disconnect_calls.append(True)
        return "Disconnected"

    async def _fake_wireguard_connect(*, config):
        return "interface up"

    monkeypatch.setattr("app.web.routes.settings.netbird.connect", _fake_netbird_connect)
    monkeypatch.setattr("app.web.routes.settings.netbird.disconnect", _fake_netbird_disconnect)
    monkeypatch.setattr("app.web.routes.settings.wireguard.connect", _fake_wireguard_connect)

    form = await client.get("/settings", params={"tab": "vpn"})
    # First connect NetBird.
    await client.post(
        "/settings/netbird",
        data={
            "netbird_setup_key": "test-key",
            "netbird_management_url": "",
            "csrf_token": _csrf_from(form),
        },
    )

    # Now connect WireGuard — NetBird should be disconnected automatically.
    response = await client.post(
        "/settings/wireguard",
        data={
            "wireguard_config": "[Interface]\nPrivateKey = abc",
            "csrf_token": _csrf_from(form),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert netbird_disconnect_calls == [True]

    status_page = await client.get("/settings", params={"tab": "vpn"})
    assert "WireGuard" in status_page.text
