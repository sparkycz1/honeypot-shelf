"""A tiny privileged control server for WireGuard, run inside the `vpn`
sidecar container (see `docker-compose.vpn.yml`) as
`python -m app.services.vpn_control_server`.

**Why this exists at all**: NetBird ships a daemon+CLI split for free
(`netbird service run` + `netbird up/down/status` as a separate client
talking to it over a socket) — exactly the shape needed to let `web`
(unprivileged) control something the sidecar (privileged, `CAP_NET_ADMIN`
+ `/dev/net/tun`) does. Plain `wireguard-tools` has no such split —
`wg-quick up`/`wg show` just run directly as one-shot commands, assuming
the caller already has `CAP_NET_ADMIN` itself, which `web` deliberately
doesn't (see the `Dockerfile`'s non-root `USER app`). This is a
purpose-built stand-in for that daemon/CLI split: a plain asyncio Unix
socket server, one JSON object per line in, one JSON object per line out,
one request per connection (no session/keep-alive — simplest possible
protocol for three commands). `app.services.wireguard` is the client side,
running in `web`.

Protocol (all requests/responses are single JSON lines):

    -> {"cmd": "wg_up", "config": "<a full wg-quick .conf, verbatim>"}
    -> {"cmd": "wg_down"}
    -> {"cmd": "wg_status"}
    <- {"ok": true|false, "output": "...", "up": true|false}  ("up" on wg_status only)

Never runs any part of this inside `web`/`worker` themselves — see this
module's own privilege requirements above, and
`app.services.netbird`/`wireguard`'s module docstrings for the shared
"why a sidecar" reasoning.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import stat
from pathlib import Path

from app.core.config import get_settings

logger = logging.getLogger(__name__)

WG_INTERFACE = "wg0"
WG_CONFIG_PATH = "/etc/wireguard/wg0.conf"


async def _run_command(*args: str) -> tuple[bool, str]:
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    stdout, _ = await process.communicate()
    output = stdout.decode("utf-8", errors="replace").strip()
    return process.returncode == 0, output


async def _wg_up(config: str) -> dict[str, object]:
    logger.info("wg_up requested")
    if not config.strip():
        logger.warning("wg_up rejected: no config given")
        return {"ok": False, "output": "No WireGuard config given."}

    # Plain os.* here, not pathlib — pathlib's blocking file methods are
    # flagged (ASYNC240) inside an `async def`; these are one-time,
    # microsecond, local-filesystem calls at connect time, not worth a
    # run_in_executor hop for.
    os.makedirs("/etc/wireguard", exist_ok=True)  # noqa: PTH103
    # Idempotent — bring any previous session down first (ignored if it
    # was never up) so re-connecting with an edited config doesn't just
    # layer a second interface/route set on top of the old one.
    await _run_command("wg-quick", "down", WG_INTERFACE)

    fd = os.open(WG_CONFIG_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    try:
        os.write(fd, config.encode("utf-8"))
    finally:
        os.close(fd)

    ok, output = await _run_command("wg-quick", "up", WG_INTERFACE)
    logger.info("wg_up %s: %s", "succeeded" if ok else "failed", output)
    return {"ok": ok, "output": output}


_ALREADY_DOWN_MARKERS = ("is not a WireGuard interface", "does not exist")


async def _wg_down() -> dict[str, object]:
    logger.info("wg_down requested")
    ok, output = await _run_command("wg-quick", "down", WG_INTERFACE)
    if not ok and any(marker in output for marker in _ALREADY_DOWN_MARKERS):
        # Already down, or never connected at all (no config file yet) —
        # same "not connected is fine" tolerance `app.services.netbird.
        # restart` applies to NetBird's own `down`.
        logger.info("wg_down: already down")
        return {"ok": True, "output": "Already down."}
    logger.info("wg_down %s: %s", "succeeded" if ok else "failed", output)
    return {"ok": ok, "output": output}


async def _wg_status() -> dict[str, object]:
    ok, output = await _run_command("wg", "show", WG_INTERFACE)
    if not ok:
        return {"ok": True, "up": False, "output": ""}
    return {"ok": True, "up": True, "output": output}


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        line = await reader.readline()
        if not line:
            return
        request = json.loads(line.decode("utf-8"))
        cmd = request.get("cmd")
        if cmd == "wg_up":
            response = await _wg_up(str(request.get("config", "")))
        elif cmd == "wg_down":
            response = await _wg_down()
        elif cmd == "wg_status":
            response = await _wg_status()
        else:
            response = {"ok": False, "output": f"Unknown command {cmd!r}."}
    except Exception as exc:
        logger.exception("vpn_control_server: request failed")
        response = {"ok": False, "output": f"Internal error: {exc}"}
    finally:
        try:
            writer.write((json.dumps(response) + "\n").encode("utf-8"))
            await writer.drain()
        except Exception:
            logger.debug("vpn_control_server: couldn't write response", exc_info=True)
        writer.close()


async def serve(socket_path: str | None = None) -> None:
    socket_path = socket_path or get_settings().vpn_control_addr
    # Plain os.*, not pathlib — see _wg_up's own comment on ASYNC240;
    # this whole function is async, but every call here is a one-time,
    # startup-only, local-filesystem operation.
    os.makedirs(os.path.dirname(socket_path), exist_ok=True)  # noqa: PTH103, PTH120
    with contextlib.suppress(FileNotFoundError):
        os.remove(socket_path)  # noqa: PTH107
    server = await asyncio.start_unix_server(_handle, path=socket_path)
    # World-writable: `web`/`worker` connect as their own unprivileged
    # `app` user, not root — this socket is the one deliberate exception,
    # same reasoning as any other narrow local-only control surface (it's
    # only ever reachable from inside this container's shared network/IPC
    # namespace set, never from the network).
    os.chmod(socket_path, 0o777)  # noqa: S103, PTH101 - see comment above
    logger.info("vpn_control_server listening on %s", socket_path)
    async with server:
        await server.serve_forever()


def _configure_logging() -> None:
    """Logs to stderr (`docker compose logs vpn`) *and* to
    `Settings.wireguard_log_path`, on a shared volume `web` can read — see
    `app.services.wireguard.tail_log`. Plain `wireguard-tools` keeps no
    log of its own to expose this way, unlike NetBird's client log."""
    log_path = get_settings().wireguard_log_path
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logging.basicConfig(level=logging.INFO, handlers=[stream_handler, file_handler])


if __name__ == "__main__":
    _configure_logging()
    asyncio.run(serve())
