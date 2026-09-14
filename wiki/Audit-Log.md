# 📝 Audit Log

*Who did what, to which honeypot, and whether it actually worked — superadmin-only, and it never forgets on purpose.*

## What gets recorded

Every route or background job that mutates something — or that refuses
to because a safeguard tripped (a typed confirmation that didn't match,
a missing pinned host key, a bad self-registration token, a failed or
locked-out login) — writes one `AuditLogEntry`: actor, action, outcome,
source IP, and a plain-language summary. A background job (the
scheduler, a retention purge) logs under a fixed actor label instead of
a user, since it has no request to read one from.

## Tamper-evident by construction

Every entry is hash-chained: `entry_hash` covers this entry's own
fields plus the previous entry's `entry_hash`, so altering or deleting
an entry breaks the chain from that point on. Concurrent writers (the
web app and every Celery worker child can all log at once) serialize
through a single locked row for the duration of one entry's write, so
two concurrent entries can never both link to the same previous hash.

**Settings → Security → "Verify chain"** walks the whole table and
reports the first broken link, if any — a proactive integrity check,
not something that only fires when someone goes looking.

Logging commits independently of whatever the caller is doing, *after*
its own commit — a failed audit write can never roll back the action it
describes, and a rejected/blocked action still gets its own record even
though nothing else was worth committing.

## Retention and export

Kept `audit_log_retention_days` (Settings → Checks & retention, default
90) before the daily purge job deletes old entries — `None` means keep
forever. Exportable as CSV or JSON (`/audit/export`) for archival or
compliance, with the same spreadsheet-formula-injection guard the REST
API's own event export uses (a leading `=`/`+`/`-`/`@` gets a defusing
prefix, since a raw one opens as a live formula in Excel/Sheets).

## Forwarding to your own SIEM

A separate, optional target (Settings → Integrations,
`app.audit_syslog`) mirrors every entry to a syslog server over UDP/TCP/
TCP-over-TLS as it's written — best-effort, a delivery failure is
logged and swallowed, never blocking the write it's mirroring. This is
the **global, audit-only** target — never a honeypot alert; those have
their own three targets entirely, see
[Honeypot Management](Honeypot-Management.md#three-syslog-targets-deliberately-never-mixed).

**Wazuh users**: `wazuh/honeypotshelf_rules/decoders.xml` (repo root)
ships a ready-made decoder + rule set (id range `107000`-`107099`) for
both this feed and the honeypot-alert one — covers every audit action
this app emits and every OpenCanary module, plus brute-force
correlation rules for repeated failed logins. See the file's own header
comment for how to wire it into a Wazuh manager.
