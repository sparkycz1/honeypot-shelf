# 🍯 Honeypot Onboarding

How a Raspberry Pi running [OpenCanary](https://github.com/thinkst/opencanary)
starts reporting events to HoneyHive. This page is about the **HoneyHive
side of the wire protocol** — it doesn't cover imaging the Pi, hardening
it, or picking which OpenCanary modules to enable; that's the team's own
internal deployment runbook, kept elsewhere on purpose (it has
site-specific and credential material that doesn't belong in this repo).

## The gap this bridges

OpenCanary has no built-in "POST events to a URL" output — its `logger`
config only writes to a local file, syslog, or a handful of other sinks
(see [OpenCanary's own docs](https://github.com/thinkst/opencanary/wiki)).
HoneyHive's ingest endpoint therefore expects a small forwarder running
*on* (or reachable from) the Pi that reads OpenCanary's own JSON log
output and re-POSTs each event.

## `POST /api/ingest/{honeypot_id}/events`

- **Auth**: `Authorization: Bearer <token>` — either the shared
  `INGEST_TOKEN` (from this HoneyHive instance's `.env`; simplest to start
  with, revoke/rotate it for every honeypot at once if it ever leaks), or
  a token scoped to one `Honeypot` row (`Honeypot.ingest_token_hash` — the
  model exists; there's no UI to generate one yet, see
  [Home.md](Home.md)'s open questions).
- **`honeypot_id`**: this honeypot's HoneyHive-assigned UUID (from the
  `Honeypot` row created for it — see [Installation](Installation.md) for
  how to create one today).
- **Body**: OpenCanary's own JSON event object, close to verbatim —
  `logtype`, `local_time`, `src_host`, `src_port`, `dst_host`, `dst_port`,
  `node_id`, and whatever `logdata` the triggering module produced. The
  whole payload is kept (`HoneypotEvent.raw`); a handful of fields are
  additionally promoted to real columns for filtering (see
  [Architecture.md](Architecture.md#-honeypot-data-model)).
- **Response**: `201` with `{"status": "accepted", "event_id": "..."}` on
  success; `401` for a missing/invalid token, `404` for an unknown
  `honeypot_id`.

Example, for testing:

```bash
curl -X POST "https://honeyhive.example.com/api/ingest/<honeypot-uuid>/events" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
        "logtype": "SSH_LOGIN_ATTEMPT",
        "local_time": "2026-09-07 12:34:56.789000",
        "src_host": "203.0.113.7",
        "src_port": 51422,
        "dst_host": "10.0.0.5",
        "dst_port": 22222,
        "node_id": "example-honey1",
        "logdata": {"USERNAME": "root", "PASSWORD": "toor"}
      }'
```

## Shape of a forwarder

The simplest option: point OpenCanary's `logger` config at a local file (or
a named pipe), and run a small `systemd` unit that tails it and re-POSTs
each JSON line — a few dozen lines of Python (`requests`, or even `curl` in
a loop) is enough; it doesn't need to be more sophisticated than "read a
line, POST it, move on," since HoneyHive is the system of record and a
dropped/retried event is harmless (no idempotency key is required — a
duplicate just shows up as two rows). Batch the sync steps yourself if
volume ever makes one-`curl`-per-event too chatty on a slow uplink.

Two things worth being deliberate about when writing that forwarder,
regardless of language:

- **Don't block OpenCanary itself on network flakiness.** The forwarder
  should tail/consume independently of OpenCanary's own writer — a Pi
  behind a flaky VPN link shouldn't back OpenCanary's own logging up.
- **Retry, but don't retry forever in memory.** A brief network blip
  should retry; a sustained outage should let events accumulate on disk
  (the log file OpenCanary already wrote) rather than in an
  unbounded in-process queue.
