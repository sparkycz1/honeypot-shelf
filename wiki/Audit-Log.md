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

The Audit log page itself live-refreshes over WebSocket the moment a new
entry is written — no need to reload to see something that just
happened. See [Honeypot Management's "Live updates over
WebSocket"](Honeypot-Management.md#small-but-worth-knowing) for how that
mechanism works across the app.

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

**Wazuh users**: `wazuh/honeypotshelf_decoders.xml` +
`wazuh/honeypotshelf_rules.xml` (repo root) ship a ready-made decoder +
rule set (id range `107000`-`107099`) for both this feed and the
honeypot-alert one — covers every audit action this app emits and
every OpenCanary module, plus brute-force correlation rules for
repeated failed logins. Both files are plain XML with no comments (some
Wazuh manager versions' own upload/file-editor path chokes on comments
and non-ASCII characters), so the install steps live here instead:

1. Copy `honeypotshelf_decoders.xml` to `/var/ossec/etc/decoders/` and
   `honeypotshelf_rules.xml` to `/var/ossec/etc/rules/` — or point a
   `<decoder_dir>`/`<rule_dir>` pair in `ossec.conf`'s `<ruleset>` block
   at wherever you keep this `wazuh` folder instead:
   ```xml
   <ruleset>
     <decoder_dir>etc/decoders</decoder_dir>
     <rule_dir>etc/rules</rule_dir>
     ...
     <decoder_dir>/path/to/wazuh</decoder_dir>
     <rule_dir>/path/to/wazuh</rule_dir>
   </ruleset>
   ```
2. Point Honeypot Shelf's syslog target(s) at this manager (or an
   intermediate syslog-ng/rsyslog relay forwarding to it) — Settings →
   Integrations for the global audit target, each Company's own page
   and/or "All honeypots" → Integrations for alerts.
3. `/var/ossec/bin/wazuh-control restart` (or just restart
   `wazuh-manager`) to load both files.
4. Verify with `/var/ossec/bin/wazuh-logtest` against a captured line
   before relying on it in production, as always.

The rules file matches on the `<decoded_as>` names the decoders produce
(`honeypotshelf-audit` / `honeypotshelf-honeypot-alert`) and on the
`data.*` fields both decoders expose from each feed's JSON body via
`JSON_Decoder` — every top-level key in the payload (`event`, `id`,
`timestamp`, `action`, `actor`, `ip`, `outcome`, `target_type`,
`target_id`, `target_label`, `summary`, `details` for the audit feed;
`event`, `id`, `timestamp`, `companies`, `honeypot`, `honeypot_ip`,
`type` — OpenCanary's own numeric logtype id, as a string — `label`,
`src_ip`, `src_port`, `dst_port`, `source`, `raw` for the honeypot-alert
feed).
