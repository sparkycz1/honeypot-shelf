"""Runtime, user-editable application settings — as opposed to
`app.core.config.Settings`, which comes from the environment and needs a
restart to change. This is a singleton table (one row, fixed id), edited
from the **Settings** page.

Deliberately a separate table/mechanism from `app.core.config.Settings`
rather than, say, letting the Settings page rewrite `.env`: the two have
different lifecycles (env config is infrastructure, decided at deploy
time; this is app behavior, decided by whoever's operating it day to day)
and different trust models.

Also holds the LDAP and OIDC configuration used for user login (see
`app.auth.ldap` / `app.auth.oidc`) and the syslog forwarding configuration
(see `app.audit_syslog`) — deliberately settings-page config, not
environment variables, same reasoning as retention: these are things
whoever's operating the app day to day turns on/off and tunes, not
deploy-time infrastructure. Secrets in here (`ldap_bind_password_encrypted`,
`oidc_client_secret_encrypted`) are encrypted at rest with
`app.core.security` (the same key protecting a honeypot's own stored
password/private key).
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import Boolean, Integer, LargeBinary, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.pg_enum import pg_enum
from app.services.syslog_transport import DEFAULT_SYSLOG_PORT, SyslogProtocol

SINGLETON_ID = 1

# Sensible default for a typical OpenLDAP directory — Active Directory
# deployments commonly need "(sAMAccountName={username})" instead. `{username}`
# is filter-escaped before substitution (see app.auth.ldap).
DEFAULT_LDAP_USER_SEARCH_FILTER = "(uid={username})"
DEFAULT_OIDC_USERNAME_CLAIM = "email"
DEFAULT_OIDC_SCOPES = "openid email profile"


class SmtpEncryption(enum.StrEnum):
    """Transport security for `app.services.smtp` (config only for now —
    see that module's own docstring). `NONE` is plaintext, for an
    internal/trusted relay only; `STARTTLS` upgrades a plain connection
    (the common case, port 587); `SSL_TLS` connects already-encrypted
    from the start (the older convention, typically port 465)."""

    NONE = "none"
    STARTTLS = "starttls"
    SSL_TLS = "ssl_tls"


DEFAULT_SMTP_PORT = 587


class VpnProvider(enum.StrEnum):
    """Which of the two VPN options (if either) Honeypot Shelf's own SSH
    management plane is currently joined to — see
    `app.services.netbird`/`app.services.wireguard` and wiki/Architecture.md's
    "VPN connectivity" section. Mutually exclusive by construction: this
    column is only ever set by a successful `connect()` (to that provider)
    or `disconnect()` (back to NONE) — never edited directly, so it can
    never point at a provider that isn't actually the one last connected."""

    NONE = "none"
    NETBIRD = "netbird"
    WIREGUARD = "wireguard"


class AppSettings(Base):
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(primary_key=True)

    # --- Background checks (moved here from environment variables per
    # explicit instruction — was `app.core.config.Settings`, needing a
    # restart to change; ported from an identical debcontrol change).
    # Defaults match the old env-var defaults, so an upgrading instance
    # behaves identically until an admin changes one from the new
    # Settings → Checks & retention tab. ---
    #
    # How long (seconds) a single SSH connection attempt is given before
    # giving up (app.ssh.connection). Read fresh from this table at the top
    # of every Celery task body that opens an SSH connection (app.tasks.
    # jobs), so a change here takes effect on the very next scheduled check
    # or "run now" click — no restart needed. (Celery's own hard per-task
    # time limit, a process-safety kill switch rather than this
    # operator-facing timeout, is a separate fixed constant — see
    # `app.tasks.jobs._SSH_TASK_TIME_LIMIT_SECONDS`.)
    ssh_connect_timeout: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    # Max wall-clock time given to one apt/flatpak/snap update run — distinct
    # from ssh_connect_timeout, which only bounds establishing the
    # connection itself. Same "read fresh, no restart" contract; see
    # `app.tasks.jobs._UPDATE_TASK_TIME_LIMIT_SECONDS` for the matching
    # fixed Celery task time limit.
    update_timeout_seconds: Mapped[int] = mapped_column(Integer, default=1800, nullable=False)
    # How often (seconds) Celery Beat schedules a refresh of OS/kernel/CPU/
    # RAM/disk facts (and installed packages, and update availability) for
    # every honeypot with a pinned host key. Beat re-reads this only at its
    # own process start (see app.tasks.celery_app) — same "restart to pick
    # up a change" contract this had back when it was
    # FACTS_REFRESH_INTERVAL_SECONDS in .env.
    facts_refresh_interval_seconds: Mapped[int] = mapped_column(
        Integer, default=600, nullable=False
    )
    # How often (seconds) the "is it alive" status badge's reachability
    # sweep (a plain TCP connect, no authentication) runs for every
    # honeypot. Same Beat-restart caveat as above.
    reachability_check_interval_seconds: Mapped[int] = mapped_column(
        Integer, default=60, nullable=False
    )
    # How many honeypots the reachability sweep checks concurrently — a
    # semaphore, not a thread/process count. Read fresh on every sweep
    # (app.tasks.jobs.ping_all_honeypots), so this one *does* take effect
    # immediately, unlike the interval fields.
    reachability_check_concurrency: Mapped[int] = mapped_column(
        Integer, default=20, nullable=False
    )
    # How often (seconds) the Monitoring tab's CPU/RAM/disk-usage sample is
    # taken for every honeypot. Same Beat-restart caveat as the intervals
    # above.
    monitoring_interval_seconds: Mapped[int] = mapped_column(
        Integer, default=120, nullable=False
    )
    # How often (seconds) this app SSH-polls every honeypot's own OpenCanary
    # log for new alerts (app.ssh.canary_activity) — the only way an event
    # is ingested (see app.services.honeypot_events). Same Beat-restart
    # caveat; overridable per honeypot regardless
    # (Honeypot.opencanary_log_poll_interval_seconds).
    opencanary_log_poll_interval_seconds: Mapped[int] = mapped_column(
        Integer, default=120, nullable=False
    )

    # How many days of audit_log_entries to keep before the daily purge job
    # (app.tasks.jobs.purge_old_audit_log_entries) deletes them. Defaults to
    # 90 (explicit product decision, matching every other retention setting
    # in this app — see EVENT_RETENTION_DAYS's own default). NULL still
    # means "keep forever" — still available, just not the default; set it
    # from Settings if audit history should never be pruned automatically.
    audit_log_retention_days: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=90
    )

    # Same idea, for the daily per-company event-count snapshot row used by
    # the Dashboard's trend chart (app.tasks.jobs.record_company_snapshot /
    # purge_old_company_snapshots). Defaults to a bounded window (90 days)
    # rather than "keep forever" — it's a lightweight, derived trend, not a
    # compliance/audit record. NULL still means "keep forever."
    dashboard_trends_retention_days: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=90
    )

    # Same idea again, for `HoneypotUpdateRun` rows (app.tasks.jobs.
    # purge_old_honeypot_update_runs) — each one can hold up to ~200KB of
    # apt output. The actual audit-worthy fact — *that* an update was
    # triggered, by whom — is the separate `honeypot.updates.run` audit log
    # entry recorded at trigger time and unaffected by this; what gets
    # purged here is only the stored run record and its raw output.
    # Defaults to a bounded window (90 days), same reasoning as
    # dashboard_trends_retention_days. NULL still means "keep forever."
    honeypot_update_run_retention_days: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=90
    )

    # Same idea again, for `HoneypotMonitoringSample`/`HoneypotReachabilitySample`
    # rows (app.tasks.jobs.purge_old_monitoring_samples) — a row is taken
    # every `MONITORING_INTERVAL_SECONDS` for every honeypot with a pinned
    # host key, so this is the one retention setting most likely to matter
    # for table size at fleet scale. Defaults to a bounded window (90 days)
    # for the same "operational trend data, not a compliance record"
    # reasoning as the two above. NULL still means "keep forever."
    # Overridable per honeypot — see `Honeypot.monitoring_history_retention_days`.
    monitoring_history_retention_days: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=90
    )

    # --- LDAP login (app.auth.ldap) ---
    ldap_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ldap_server_uri: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ldap_use_starttls: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Service/bind account used to search for the user's DN — the user's own
    # credentials are only ever used for the final bind-as-them check (see
    # app.auth.ldap.authenticate).
    ldap_bind_dn: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ldap_bind_password_encrypted: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True
    )
    ldap_user_search_base: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ldap_user_search_filter: Mapped[str] = mapped_column(
        String(255), default=DEFAULT_LDAP_USER_SEARCH_FILTER, nullable=False
    )
    ldap_connect_timeout_seconds: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    # Verify the directory's TLS certificate against the system CA bundle
    # for `ldaps://`/STARTTLS — on by default. Turning it off accepts any
    # certificate (self-signed, expired, wrong hostname) with no chain-of-
    # trust check at all, an explicit opt-out for a directory whose
    # certificate an admin already knows isn't (or can't easily be made)
    # verifiable, not a default anyone should want. See app.auth.ldap.
    ldap_tls_verify: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # --- OIDC login (app.auth.oidc) ---
    oidc_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    oidc_issuer_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    oidc_client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    oidc_client_secret_encrypted: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True
    )
    # Which ID-token claim is compared against a user's `username` to decide
    # which Honeypot Shelf account just logged in — see User.username. Configurable
    # since it varies by provider.
    oidc_username_claim: Mapped[str] = mapped_column(
        String(100), default=DEFAULT_OIDC_USERNAME_CLAIM, nullable=False
    )
    oidc_scopes: Mapped[str] = mapped_column(
        String(255), default=DEFAULT_OIDC_SCOPES, nullable=False
    )
    # Shown on the login button ("Log in with {name}") instead of the
    # generic "OIDC" — purely cosmetic, e.g. "Entra ID"/"Authentik"/"Google
    # Workspace". Blank (the default) falls back to the generic label; see
    # login.html.
    oidc_provider_name: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # --- VPN for Honeypot Shelf itself (app.services.netbird/wireguard,
    # Settings -> VPN) — a different thing from the NetBird setup key
    # entered on an Initialize run (that joins the *honeypot* to your
    # network; this joins *Honeypot Shelf's own SSH-management-plane
    # containers*, so a honeypot that's only reachable over a VPN — e.g.
    # sitting behind a NAT with no forwarded port — still works with
    # everything else in this app). Unlike the Initialize one, this
    # genuinely needs to persist: it has to survive a container restart
    # and reconnect on its own (see `app.main`'s lifespan), so storing it
    # here (secrets encrypted, same as the LDAP/OIDC secrets above) is the
    # right call this time, not a repeat of the mistake the once-dropped
    # `netbird_management_url` column was cleaned up for — that one stored
    # a value nothing but Initialize's one-time form ever needed.
    #
    # `vpn_provider` is the single source of truth for "which one (if
    # either) is active" — mutually exclusive, see `VpnProvider`'s own
    # docstring. Both providers' config stays saved even while the other
    # is active (or neither is), so switching back doesn't need
    # re-entering it — only NetBird's setup key is genuinely one-shot in
    # the sense of not being re-displayed once saved. ---
    vpn_provider: Mapped[VpnProvider] = mapped_column(
        pg_enum(VpnProvider, name="vpn_provider"), default=VpnProvider.NONE, nullable=False
    )
    netbird_management_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    netbird_setup_key_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # `netbird up --hostname ...` — otherwise NetBird registers this
    # container under its bare Docker hostname (the container ID/name,
    # meaningless in the NetBird dashboard's peer list). Only takes effect
    # the moment this peer *first* registers with the management server;
    # changing it later and reconnecting does not rename an
    # already-registered peer — see app.services.netbird.connect's own
    # docstring, and the hint next to this field on Settings -> VPN.
    netbird_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # The whole pasted wg-quick `.conf` Honeypot Shelf itself is a peer with —
    # see wiki/Architecture.md's "VPN connectivity" section for why this is
    # one opaque encrypted blob rather than separate private-key/peer/
    # endpoint/allowed-ips fields: it's the exact file a WireGuard server
    # admin already hands out per client, nothing here needs to parse it
    # beyond handing it to `wg-quick` verbatim.
    wireguard_config_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # --- Syslog forwarding of audit log entries (app.audit_syslog), e.g. to
    # a SIEM such as Wazuh. Best-effort/fire-and-forget: the DB row is always
    # the source of truth, this is only ever a live mirror of it. ---
    syslog_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    syslog_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    syslog_port: Mapped[int] = mapped_column(Integer, default=DEFAULT_SYSLOG_PORT, nullable=False)
    syslog_protocol: Mapped[SyslogProtocol] = mapped_column(
        pg_enum(SyslogProtocol, name="syslog_protocol"),
        default=SyslogProtocol.UDP,
        nullable=False,
    )

    # --- SMTP relay for outbound email notifications — see
    # `app.services.notifications` for what actually sends through this
    # (Notifications: self-service, named rules — `app.db.models.
    # notification_rule.NotificationRule`). Same encrypted-secret
    # convention as `ldap_bind_password_encrypted`/
    # `oidc_client_secret_encrypted` above. ---
    smtp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    smtp_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    smtp_port: Mapped[int] = mapped_column(Integer, default=DEFAULT_SMTP_PORT, nullable=False)
    smtp_encryption: Mapped[SmtpEncryption] = mapped_column(
        pg_enum(SmtpEncryption, name="smtp_encryption"),
        default=SmtpEncryption.STARTTLS,
        nullable=False,
    )
    smtp_username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    smtp_password_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Envelope/header From — most relays (and SPF/DKIM-checking recipients)
    # reject a send whose From doesn't match an address the relay account
    # is actually allowed to send as, so this is its own field rather than
    # reusing `smtp_username`.
    smtp_from_address: Mapped[str | None] = mapped_column(String(255), nullable=True)
    smtp_from_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # How many days of `NotificationLog` rows (every send attempt, real or
    # "Send test") to keep before the daily purge job deletes them — same
    # "bounded operational history, not a compliance record" reasoning and
    # default as every other retention setting here (see
    # `dashboard_trends_retention_days`). NULL means "keep forever."
    notification_log_retention_days: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=90
    )

    # --- Fleet-wide honeypot-alert syslog target — the "All honeypots"
    # page's own Integrations tab (app/web/routes/companies.py). Every
    # honeypot's alert forwards here *in addition to* its own company's
    # target (Company.syslog_*, app.services.honeypot_event_syslog) if
    # both are configured — a central overarching SIEM alongside each
    # tenant's own, not a replacement for either. Lives here rather than
    # on a `Company` row since "All honeypots" isn't backed by one at all
    # (see `all_honeypots_company`'s own docstring). Same shape/transport
    # as both other syslog targets (app.services.syslog_transport). ---
    fleet_alert_syslog_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    fleet_alert_syslog_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    fleet_alert_syslog_port: Mapped[int] = mapped_column(
        Integer, default=DEFAULT_SYSLOG_PORT, nullable=False
    )
    fleet_alert_syslog_protocol: Mapped[SyslogProtocol] = mapped_column(
        pg_enum(SyslogProtocol, name="syslog_protocol"),
        default=SyslogProtocol.UDP,
        nullable=False,
    )

    # --- GeoIP lookups (Settings -> GeoIP; app.services.geoip) — resolves a
    # public source IP to a country/city/lat-long for the Map page and the
    # audit log, from a MaxMind-DB-format (.mmdb) database this app
    # downloads itself, never bundles. Deliberately just a URL, not
    # MaxMind-specific config (account id, edition, ...): paste any URL that
    # serves a .mmdb, gzipped or not — a MaxMind GeoLite2 "permalink" (which
    # already embeds your license key) or another provider's own City-level
    # download, e.g. DB-IP Lite. Same encrypted-at-rest convention as every
    # other URL/credential above, since a MaxMind permalink embeds a license
    # key. `backup_url` is only ever tried if `primary_url` fails outright
    # (network error, bad response, unparseable file) — never load-balanced
    # between the two. The downloaded bytes themselves live in
    # `GeoipDatabase`, not here — this table is read on essentially every
    # request (`get_or_create_app_settings`), so a multi-megabyte blob here
    # would be a real cost paid by every caller, not just GeoIP lookups. ---
    geoip_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    geoip_primary_url_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    geoip_backup_url_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # How often (hours) the download job re-fetches the database — MaxMind
    # itself only refreshes GeoLite2 a couple of times a week, so the
    # default is weekly, not one of the minutes/seconds-scale intervals on
    # the Checks & retention tab.
    geoip_refresh_interval_hours: Mapped[int] = mapped_column(
        Integer, default=168, nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"AppSettings(audit_log_retention_days={self.audit_log_retention_days!r})"
