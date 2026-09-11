# 🍯 Honeypot Onboarding

How a Raspberry Pi running [OpenCanary](https://github.com/thinkst/opencanary)
starts reporting events to Honeypot Shelf. This page is about the **Honeypot Shelf
side of the wire protocol** — it doesn't cover imaging the Pi, hardening
it, or picking which OpenCanary modules to enable; that's the team's own
internal deployment runbook, kept elsewhere on purpose (it has
site-specific and credential material that doesn't belong in this repo).

## The gap this bridges — and the alternative that needs no forwarder

OpenCanary has no built-in "POST events to a URL" output — its `logger`
config only writes to a local file, syslog, or a handful of other sinks
(see [OpenCanary's own docs](https://github.com/thinkst/opencanary/wiki)).
Honeypot Shelf's ingest endpoint below is one way to bridge that: a small
forwarder running *on* (or reachable from) the Pi that reads OpenCanary's
own JSON log output and re-POSTs each event.

**Setting up a forwarder is optional, not required, for events to show
up in Honeypot Shelf.** Once a honeypot's host key is pinned, Honeypot Shelf itself
also reads whatever's new in OpenCanary's own log over the same SSH
management connection every other periodic sweep uses — no forwarder, no
extra config on the Pi at all. See that honeypot's own **Activity** tab,
and [Architecture.md](Architecture.md#-honeypot-data-model)'s "How events
actually arrive" section for how the two mechanisms relate
(`HoneypotEvent.source` records which one produced each row). The
push-based endpoint below is still worth setting up if you want events to
land with less latency than the poll interval, or from a honeypot
Honeypot Shelf doesn't otherwise manage over SSH.

## `POST /api/ingest/{honeypot_id}/events`

- **Auth**: `Authorization: Bearer <token>` — the shared `INGEST_TOKEN`
  (from this Honeypot Shelf instance's `.env`; revoke/rotate it for every
  honeypot at once if it ever leaks).
- **`honeypot_id`**: this honeypot's Honeypot Shelf-assigned UUID (from the
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
line, POST it, move on," since Honeypot Shelf is the system of record and a
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
