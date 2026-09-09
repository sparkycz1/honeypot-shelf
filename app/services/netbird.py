"""Controls HoneyHive's *own* NetBird connection — not to be confused with
`app.ssh.initialize`'s NetBird setup, which joins a honeypot being
provisioned to your network. This module is about `web`/`worker`
themselves: when a honeypot only has a NetBird address (e.g. it sits
behind a NAT with no SSH port forwarded to it), the SSH management plane
can only reach it if this app's own containers are on that same NetBird
network too.

**Architecture**: the `netbird` client (daemon + WireGuard interface)
cannot run inside `web`/`worker` themselves — creating a WireGuard
interface needs `CAP_NET_ADMIN` and `/dev/net/tun`, capabilities this
app's containers deliberately don't have (see the `Dockerfile`'s non-root
`USER app`). Instead, `docker-compose.vpn.yml` (an optional overlay,
same convention as `docker-compose.caddy.yml`) runs one small privileged
`netbird` sidecar container, and `web`/`worker` join *its* network
namespace (`network_mode: "service:netbird"`) — once the daemon connects,
every honeypot reachable over that NetBird network becomes reachable from
`web`/`worker` too, with no further code changes (a plain SSH connect
already just works once the route exists).

This module only ever talks to the sidecar's daemon over the **`netbird`
CLI** (installed in this image too — see the Dockerfile), pointed at the
daemon's control socket via `--daemon-addr` (a shared volume between this
container and the sidecar, `Settings.netbird_daemon_addr`) — never at the
sidecar container directly (no Docker socket access, deliberately, since
that would be root-equivalent). Without the overlay file, the `netbird`
binary/socket simply aren't there and every function here fails with a
clear "not found" error rather than crashing the app — this feature is
fully optional.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_NETBIRD_BIN = "netbird"

# Substring `netbird status`' human-readable output is expected to contain
# once connected — stable across the CLI's plain-text output format
# (unlike the exact wording of the rest of that output, this line's shape
# has been part of every NetBird release's `status` command).
_MANAGEMENT_CONNECTED_MARKER = "Management: Connected"


class NetbirdUnavailableError(Exception):
    """The `netbird` CLI isn't installed, or its daemon socket isn't
    reachable — most likely `docker-compose.vpn.yml` was never
    applied. Distinct from a command that ran but failed (wrong setup key,
    daemon rejected the connection, ...), which raises `NetbirdCommandError`
    instead so the two show different guidance in the UI."""


class NetbirdCommandError(Exception):
    """`netbird` ran but exited non-zero — `output` is its combined
    stdout/stderr, safe to show to a superadmin (the CLI itself never
    echoes the setup key back)."""

    def __init__(self, message: str, *, output: str) -> None:
        super().__init__(message)
        self.output = output


def _daemon_socket_path(daemon_addr: str) -> str | None:
    """The filesystem path inside a `unix://...`-style `--daemon-addr`, or
    `None` for any other scheme this can't pre-check."""
    prefix = "unix://"
    return daemon_addr.removeprefix(prefix) if daemon_addr.startswith(prefix) else None


async def _run(*args: str) -> str:
    """Runs `netbird <args> --daemon-addr <configured>`, returns combined
    stdout+stderr on success. Never includes `args` itself in a raised
    exception's message — the setup key is one of them for `up`.

    Checks the daemon socket file exists *before* shelling out — without
    the sidecar running, the `netbird` CLI itself doesn't fail fast: its
    own gRPC client retries with backoff for a good ~10 seconds before
    giving up with "context deadline exceeded", regardless of this app's
    own `netbird_command_timeout_seconds` (that's just an outer ceiling on
    top of it). The Settings -> VPN tab calls this on every load and every
    5-second status poll, so that ~10s was very noticeable — a plain
    `os.path.exists` first (a few microseconds) fails exactly as fast as
    `app.services.wireguard`'s own control-socket check already does."""
    settings = get_settings()
    socket_path = _daemon_socket_path(settings.netbird_daemon_addr)
    if socket_path is not None and not await asyncio.to_thread(os.path.exists, socket_path):
        raise NetbirdUnavailableError(
            "Can't reach the NetBird daemon socket — is the vpn sidecar "
            "(docker-compose.vpn.yml) running?"
        )

    full_args = [*args, "--daemon-addr", settings.netbird_daemon_addr]
    try:
        process = await asyncio.create_subprocess_exec(
            _NETBIRD_BIN,
            *full_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError as exc:
        raise NetbirdUnavailableError(
            "The netbird CLI isn't installed in this container — is "
            "docker-compose.vpn.yml applied?"
        ) from exc

    try:
        stdout, _ = await asyncio.wait_for(
            process.communicate(), timeout=settings.netbird_command_timeout_seconds
        )
    except TimeoutError:
        with contextlib.suppress(Exception):
            process.kill()
        raise NetbirdCommandError("Timed out waiting for netbird.", output="") from None

    output = stdout.decode("utf-8", errors="replace").strip()
    if process.returncode != 0:
        if "connect: no such file or directory" in output or "no such file" in output.lower():
            raise NetbirdUnavailableError(
                "Can't reach the netbird daemon socket — is the netbird "
                "sidecar (docker-compose.vpn.yml) running?"
            )
        raise NetbirdCommandError(
            f"netbird exited {process.returncode}.", output=output
        )
    return output


async def connect(*, setup_key: str, management_url: str | None) -> str:
    """`netbird up --setup-key ...` — joins (or rejoins) the network.
    Idempotent: safe to call again to pick up a changed setup key/URL
    without an explicit `disconnect()` first."""
    args = ["up", "--setup-key", setup_key]
    if management_url:
        args += ["--management-url", management_url]
    return await _run(*args)


async def disconnect() -> str:
    return await _run("down")


async def restart(*, setup_key: str, management_url: str | None) -> str:
    """`disconnect()` then `connect()` — a clean reconnect rather than
    just re-running `up` on top of an already-live session, for the same
    reason "restart" means stop-then-start everywhere else in this app
    (e.g. a honeypot's power actions)."""
    with_errors: list[str] = []
    try:
        with_errors.append(await disconnect())
    except NetbirdCommandError as exc:
        # Not already connected is fine — proceed to connect anyway.
        with_errors.append(exc.output)
    with_errors.append(await connect(setup_key=setup_key, management_url=management_url))
    return "\n".join(part for part in with_errors if part)


class NetbirdStatus:
    """Parsed just enough of `netbird status` to drive the Settings page's
    badge — `raw` is shown underneath verbatim for anything more detailed
    an operator wants to see."""

    def __init__(self, *, connected: bool, raw: str, error: str | None = None) -> None:
        self.connected = connected
        self.raw = raw
        self.error = error


async def status() -> NetbirdStatus:
    try:
        raw = await _run("status")
    except NetbirdUnavailableError as exc:
        return NetbirdStatus(connected=False, raw="", error=str(exc))
    except NetbirdCommandError as exc:
        # A non-zero exit before ever having connected (e.g. "daemon is
        # not logged in") is the normal "not connected yet" case, not a
        # real error — show its own output as the (unconnected) status.
        return NetbirdStatus(connected=False, raw=exc.output)
    return NetbirdStatus(connected=_MANAGEMENT_CONNECTED_MARKER in raw, raw=raw)


def tail_log(lines: int = 200) -> str:
    """The sidecar's log file, over the shared volume — see this module's
    docstring. Plain synchronous file I/O (same as every other "read a
    handful of KB from disk" spot in this app) — never SSH, this is local.
    Missing file (sidecar never run, or no overlay applied) isn't an
    error, just an empty/explanatory result."""
    settings = get_settings()
    try:
        with open(settings.netbird_log_path, encoding="utf-8", errors="replace") as f:
            # Fine at this log's realistic size (a NetBird client log, not
            # an OpenCanary firehose) — read it whole rather than seeking
            # from the end, same tradeoff `app.ssh.logs`' file browser makes
            # for a "view file" request.
            all_lines = f.readlines()
    except FileNotFoundError:
        return ""
    except OSError as exc:
        logger.warning("Could not read netbird log at %s: %s", settings.netbird_log_path, exc)
        return ""
    return "".join(all_lines[-lines:])
