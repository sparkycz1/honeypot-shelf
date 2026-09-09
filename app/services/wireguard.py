"""Controls HoneyHive's *own* WireGuard connection — the other,
mutually-exclusive VPN provider alongside `app.services.netbird` (see
`AppSettings.VpnProvider`). HoneyHive doesn't run its own WireGuard
server: it joins an existing one — the same WireGuard server the operator
already runs somewhere reachable — as a plain peer, exactly the
relationship a honeypot has to it too (via Initialize's own WireGuard
option). Settings -> VPN's WireGuard field is a paste-your-peer-config
textarea (a standard `wg-quick` `.conf`, the same file any WireGuard
server admin already hands out per client) — this module never generates
keys or otherwise builds a config itself, it just brings up whatever it's
given.

**Architecture**: same sidecar as NetBird (`docker-compose.vpn.yml`'s
`vpn` service) — creating/configuring a WireGuard interface needs
`CAP_NET_ADMIN`/`/dev/net/tun`, which `web`/`worker` deliberately don't
have. Unlike NetBird, plain `wireguard-tools` has no daemon+CLI split of
its own for `web` to talk to, so the sidecar also runs
`app.services.vpn_control_server` — a small purpose-built stand-in for
one — and this module is its client, talking newline-delimited JSON over
a shared Unix socket (`Settings.vpn_control_addr`) rather than shelling
out to a local CLI the way `app.services.netbird` does. Without the
overlay applied, that socket simply isn't there and every function here
fails with a clear "not found" error rather than crashing the app — same
as NetBird, this feature is fully optional.
"""

from __future__ import annotations

import asyncio
import json
import logging

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class WireguardUnavailableError(Exception):
    """The `vpn` sidecar's control socket isn't reachable — most likely
    `docker-compose.vpn.yml` was never applied, or the sidecar is still
    starting up."""


class WireguardCommandError(Exception):
    """The control server ran the command but it failed (a malformed
    config, `wg-quick` itself rejecting it, ...) — `output` is safe to
    show to a superadmin (nothing here echoes a private key back; the
    error is `wg-quick`'s own, about the config's shape, not its
    contents)."""

    def __init__(self, message: str, *, output: str) -> None:
        super().__init__(message)
        self.output = output


async def _send(request: dict[str, object]) -> dict[str, object]:
    settings = get_settings()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(settings.vpn_control_addr),
            timeout=settings.vpn_command_timeout_seconds,
        )
    except (FileNotFoundError, ConnectionRefusedError, OSError) as exc:
        raise WireguardUnavailableError(
            "Can't reach the VPN control socket — is the vpn sidecar "
            "(docker-compose.vpn.yml) running?"
        ) from exc

    try:
        writer.write((json.dumps(request) + "\n").encode("utf-8"))
        await writer.drain()
        line = await asyncio.wait_for(
            reader.readline(), timeout=settings.vpn_command_timeout_seconds
        )
    except TimeoutError as exc:
        raise WireguardCommandError(
            "Timed out waiting for the VPN control server.", output=""
        ) from exc
    finally:
        writer.close()

    if not line:
        raise WireguardCommandError("The VPN control server closed the connection.", output="")
    response: dict[str, object] = json.loads(line.decode("utf-8"))
    if not response.get("ok"):
        raise WireguardCommandError(
            "wg-quick reported a failure.", output=str(response.get("output", ""))
        )
    return response


async def connect(*, config: str) -> str:
    response = await _send({"cmd": "wg_up", "config": config})
    return str(response.get("output", ""))


async def disconnect() -> str:
    response = await _send({"cmd": "wg_down"})
    return str(response.get("output", ""))


async def restart(*, config: str) -> str:
    """Same "clean disconnect then reconnect" shape as
    `app.services.netbird.restart` — `wg_up` is already idempotent
    (`vpn_control_server` brings any previous session down first), so this
    mostly exists for consistency with NetBird's own restart button."""
    with_errors: list[str] = []
    try:
        with_errors.append(await disconnect())
    except WireguardCommandError as exc:
        with_errors.append(exc.output)
    with_errors.append(await connect(config=config))
    return "\n".join(part for part in with_errors if part)


class WireguardStatus:
    """Parsed just enough of `wg show` to drive the Settings page's badge.

    Deliberately labeled "active", not "connected", in the UI — unlike
    NetBird (which has a coordination server confirming the session),
    plain WireGuard gives no independent confirmation the peer on the
    other end is actually reachable, only that the local interface and
    its configured routes exist. See wiki/Architecture.md."""

    def __init__(self, *, up: bool, raw: str, error: str | None = None) -> None:
        self.up = up
        self.raw = raw
        self.error = error


async def status() -> WireguardStatus:
    try:
        response = await _send({"cmd": "wg_status"})
    except WireguardUnavailableError as exc:
        return WireguardStatus(up=False, raw="", error=str(exc))
    except WireguardCommandError as exc:
        return WireguardStatus(up=False, raw=exc.output, error=str(exc))
    return WireguardStatus(up=bool(response.get("up")), raw=str(response.get("output", "")))


def tail_log(lines: int = 200) -> str:
    """The `vpn_control_server`'s own log file, over the shared volume —
    see `app.services.vpn_control_server._configure_logging`. Plain
    synchronous file I/O, same as `app.services.netbird.tail_log`; missing
    file (sidecar never run, or no overlay applied) isn't an error, just
    an empty/explanatory result."""
    settings = get_settings()
    try:
        with open(settings.wireguard_log_path, encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
    except FileNotFoundError:
        return ""
    except OSError as exc:
        logger.warning(
            "Could not read WireGuard control log at %s: %s", settings.wireguard_log_path, exc
        )
        return ""
    return "".join(all_lines[-lines:])
