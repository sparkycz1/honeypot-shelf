"""Read whatever's new in OpenCanary's own log since the last poll — the
Activity tab (`app.web.routes.honeypots`,
`app.tasks.jobs.poll_honeypot_canary_log`). Read-only, no root needed,
same convention as `app.ssh.monitoring`.

Incremental by byte offset (`Honeypot.opencanary_log_offset`) rather than
re-reading the whole file every poll — cheap even on a long-lived honeypot
with a large log, and it means a poll never re-parses (and re-counts) a
line it already saw. The file's size is fetched first so a shrunk file
(log rotated/truncated outside this app) is detected and read from byte 0
again, instead of `tail -c +N` on a now-too-large offset silently
returning nothing forever.

Only *complete* lines (ending in `\\n`) are parsed and counted toward the
new offset — a line still being written by OpenCanary at the moment this
polls is left for the next poll rather than parsed half-written and lost.
"""

from __future__ import annotations

import json
import shlex
from typing import Any, NamedTuple

from app.db.models.honeypot import Honeypot
from app.ssh.client import open_connection
from app.ssh.logs import HONEYPOT_LOG_PATH

_MARKER = "===READ==="


def build_read_command(*, path: str, offset: int) -> str:
    """Emits the new bytes since `offset` (or since byte 0 if the file has
    shrunk below `offset`), followed by a marker line reporting the byte
    offset that read actually *started* from — the caller needs that to
    compute the next offset, since a rotated file starts from 0 regardless
    of what was stored. `tail -c +N` is 1-indexed, hence the `+1`."""
    quoted = shlex.quote(path)
    return (
        f'sz=$(stat -c%s {quoted} 2>/dev/null || echo 0); '
        f'if [ "$sz" -lt {int(offset)} ]; then start=0; else start={int(offset)}; fi; '
        f'tail -c +$((start+1)) {quoted} 2>/dev/null; '
        f'printf "\\n{_MARKER} %s\\n" "$start"'
    )


class LogPollResult(NamedTuple):
    events: list[dict[str, Any]]
    new_offset: int


def parse_read_output(raw: str) -> LogPollResult:
    """Split `build_read_command`'s output into parsed JSON events (one per
    complete OpenCanary log line — a malformed/non-JSON line is silently
    skipped, same tolerance `app.web.routes.ingest` already has for
    whatever a forwarder sends) and the offset the *next* poll should start
    from."""
    marker_prefix = f"\n{_MARKER} "
    marker_index = raw.rfind(marker_prefix)
    if marker_index == -1:
        # No marker at all — the command itself didn't produce the expected
        # output (e.g. the connection dropped mid-run). Nothing parsed,
        # offset unknowable here — caller keeps the honeypot's existing one.
        return LogPollResult(events=[], new_offset=-1)

    body = raw[:marker_index]
    start_text = raw[marker_index + len(marker_prefix) :].strip()
    start = int(start_text) if start_text.isdigit() else 0

    events: list[dict[str, Any]] = []
    consumed = 0
    for line in body.splitlines(keepends=True):
        if not line.endswith("\n"):
            # The last, incomplete line at EOF — OpenCanary may still be
            # mid-write. Leave it for the next poll: don't count its bytes
            # toward `consumed`, don't try to parse it.
            break
        consumed += len(line.encode("utf-8"))
        stripped = line.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            events.append(parsed)

    return LogPollResult(events=events, new_offset=start + consumed)


async def poll_log(
    honeypot: Honeypot,
    secret: str | None,
    timeout_seconds: int,
    *,
    path: str = HONEYPOT_LOG_PATH,
) -> LogPollResult:
    """Connect to a honeypot and return whatever new OpenCanary log lines
    parsed as JSON, plus the offset to store for next time (`-1` if the
    read itself failed to produce the expected marker — the caller should
    leave `Honeypot.opencanary_log_offset` untouched in that case). Requires
    a pinned host key."""
    command = build_read_command(path=path, offset=honeypot.opencanary_log_offset)
    async with await open_connection(honeypot, secret, timeout_seconds) as conn:
        result = await conn.run(command, check=False, timeout=timeout_seconds)
    stdout = result.stdout or ""
    raw = stdout if isinstance(stdout, str) else stdout.decode()
    return parse_read_output(raw)
