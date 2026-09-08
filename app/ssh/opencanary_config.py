"""Editing a honeypot's own `opencanary.conf` over SSH — the Honeypot
Config tab's module editor.

**Deliberately no HoneyHive-side persistence** — every load is a fresh
`cat` of the file over SSH, and saving writes it straight back, the same
"the honeypot's own state is the only copy of the truth" philosophy the
Logs/Status tabs already use (see their own module docstrings). A cached
copy in this app's DB would need to be kept in sync by hand and could
silently drift from reality the moment someone edits the file directly
(e.g. over the Terminal tab) — not worth it for a form that's read
on-demand, not polled.

`OPENCANARY_MODULES` describes every module in OpenCanary's own default
config (https://github.com/thinkst/opencanary/blob/master/data/.opencanary.conf)
except two deliberately left untouched by this editor:

- `logger` — this app's own Initialize already repoints its file handler
  at the `/mnt/tmpfs` ramdisk (see `app.ssh.initialize`); re-exposing the
  whole logging/formatter tree here would be a lot of surface for
  something nobody needs to touch per-honeypot.
- `telnet.honeycreds` — a list of fake credential hashes, not a simple
  scalar/list-of-scalars field this generic form model can represent;
  left exactly as `--copyconfig` shipped it (or whatever a previous save
  already had) on every write.

Both keys are preserved as-is by `apply_form_to_config` (merged from the
freshly-read config, never touched by the submitted form) — a save here
never has any effect on either.

Two systemd services are toggled based on the saved config, beyond
`opencanary` itself (always restarted so any change takes effect):
Samba's own `smbd`/`nmbd`, enabled+started when `smb.enabled` is true and
disabled+stopped otherwise — see `app.ssh.initialize`'s module docstring
for why they start disabled (prepared, not live) even though Samba
itself is installed by Initialize.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from typing import Any, Literal

FieldType = Literal["bool", "int", "str", "list"]

OPENCANARY_CONFIG_PATH = "/etc/opencanaryd/opencanary.conf"

# Keys this editor never reads into a form field or writes back — merged
# through unchanged from whatever's already in the file. See module
# docstring.
_UNMANAGED_KEYS = ("logger", "telnet.honeycreds")


@dataclass(frozen=True)
class ConfigField:
    key: str  # dotted opencanary.conf key, e.g. "ftp.port"
    label_key: str  # i18n key for this field's label
    type: FieldType
    default: Any = None
    hint_key: str | None = None  # i18n key for an optional inline hint


@dataclass(frozen=True)
class ConfigModule:
    key: str  # short slug, e.g. "ftp" — used in HTML ids/i18n keys
    name_key: str  # i18n key for the module's display name
    enabled_key: str | None  # dotted key, e.g. "ftp.enabled"; None = always-on section
    fields: list[ConfigField] = field(default_factory=list)
    hint_key: str | None = None  # i18n key for an optional module-level hint


# Order matters: rendered top to bottom, roughly the order the upstream
# default config itself uses, grouped as the fetch/read of that file
# groups them.
OPENCANARY_MODULES: list[ConfigModule] = [
    ConfigModule(
        key="general",
        name_key="honeypots.config.module.general",
        enabled_key=None,
        fields=[
            ConfigField("device.node_id", "honeypots.config.field.node_id", "str"),
            ConfigField(
                "ip.ignorelist",
                "honeypots.config.field.ip_ignorelist",
                "list",
                hint_key="honeypots.config.field.ip_ignorelist_hint",
            ),
            ConfigField(
                "logtype.ignorelist",
                "honeypots.config.field.logtype_ignorelist",
                "list",
            ),
        ],
    ),
    ConfigModule(
        key="ftp",
        name_key="honeypots.config.module.ftp",
        enabled_key="ftp.enabled",
        fields=[
            ConfigField("ftp.port", "honeypots.config.field.port", "int", default=21),
            ConfigField("ftp.banner", "honeypots.config.field.banner", "str"),
            ConfigField(
                "ftp.log_auth_attempt_initiated",
                "honeypots.config.field.log_auth_attempt_initiated",
                "bool",
            ),
        ],
    ),
    ConfigModule(
        key="http",
        name_key="honeypots.config.module.http",
        enabled_key="http.enabled",
        fields=[
            ConfigField("http.port", "honeypots.config.field.port", "int", default=80),
            ConfigField("http.banner", "honeypots.config.field.banner", "str"),
            ConfigField("http.skin", "honeypots.config.field.skin", "str", default="nasLogin"),
            ConfigField(
                "http.log_unimplemented_method_requests",
                "honeypots.config.field.log_unimplemented_method_requests",
                "bool",
            ),
            ConfigField(
                "http.log_redirect_request", "honeypots.config.field.log_redirect_request", "bool"
            ),
        ],
        hint_key="honeypots.config.module.http_hint",
    ),
    ConfigModule(
        key="https",
        name_key="honeypots.config.module.https",
        enabled_key="https.enabled",
        fields=[
            ConfigField("https.port", "honeypots.config.field.port", "int", default=443),
            ConfigField("https.skin", "honeypots.config.field.skin", "str", default="nasLogin"),
            ConfigField(
                "https.certificate", "honeypots.config.field.certificate_path", "str"
            ),
            ConfigField("https.key", "honeypots.config.field.key_path", "str"),
        ],
    ),
    ConfigModule(
        key="httpproxy",
        name_key="honeypots.config.module.httpproxy",
        enabled_key="httpproxy.enabled",
        fields=[
            ConfigField("httpproxy.port", "honeypots.config.field.port", "int", default=8080),
            ConfigField("httpproxy.skin", "honeypots.config.field.skin", "str", default="squid"),
        ],
    ),
    ConfigModule(
        key="ssh",
        name_key="honeypots.config.module.ssh",
        enabled_key="ssh.enabled",
        fields=[
            ConfigField("ssh.port", "honeypots.config.field.port", "int", default=22),
            ConfigField("ssh.version", "honeypots.config.field.banner", "str"),
        ],
        hint_key="honeypots.config.module.ssh_hint",
    ),
    ConfigModule(
        key="telnet",
        name_key="honeypots.config.module.telnet",
        enabled_key="telnet.enabled",
        fields=[
            ConfigField("telnet.port", "honeypots.config.field.port", "int", default=23),
            ConfigField("telnet.banner", "honeypots.config.field.banner", "str"),
            ConfigField(
                "telnet.log_tcp_connection", "honeypots.config.field.log_tcp_connection", "bool"
            ),
        ],
        hint_key="honeypots.config.module.telnet_hint",
    ),
    ConfigModule(
        key="mysql",
        name_key="honeypots.config.module.mysql",
        enabled_key="mysql.enabled",
        fields=[
            ConfigField("mysql.port", "honeypots.config.field.port", "int", default=3306),
            ConfigField("mysql.banner", "honeypots.config.field.version", "str"),
            ConfigField(
                "mysql.log_connection_made", "honeypots.config.field.log_connection_made", "bool"
            ),
        ],
    ),
    ConfigModule(
        key="mssql",
        name_key="honeypots.config.module.mssql",
        enabled_key="mssql.enabled",
        fields=[
            ConfigField("mssql.port", "honeypots.config.field.port", "int", default=1433),
            ConfigField("mssql.version", "honeypots.config.field.version", "str", default="2012"),
        ],
    ),
    ConfigModule(
        key="mongodb",
        name_key="honeypots.config.module.mongodb",
        enabled_key="mongodb.enabled",
        fields=[
            ConfigField("mongodb.port", "honeypots.config.field.port", "int", default=27017),
            ConfigField("mongodb.version", "honeypots.config.field.version", "str"),
        ],
    ),
    ConfigModule(
        key="redis",
        name_key="honeypots.config.module.redis",
        enabled_key="redis.enabled",
        fields=[ConfigField("redis.port", "honeypots.config.field.port", "int", default=6379)],
    ),
    ConfigModule(
        key="rdp",
        name_key="honeypots.config.module.rdp",
        enabled_key="rdp.enabled",
        fields=[ConfigField("rdp.port", "honeypots.config.field.port", "int", default=3389)],
    ),
    ConfigModule(
        key="vnc",
        name_key="honeypots.config.module.vnc",
        enabled_key="vnc.enabled",
        fields=[ConfigField("vnc.port", "honeypots.config.field.port", "int", default=5000)],
    ),
    ConfigModule(
        key="sip",
        name_key="honeypots.config.module.sip",
        enabled_key="sip.enabled",
        fields=[ConfigField("sip.port", "honeypots.config.field.port", "int", default=5060)],
    ),
    ConfigModule(
        key="snmp",
        name_key="honeypots.config.module.snmp",
        enabled_key="snmp.enabled",
        fields=[ConfigField("snmp.port", "honeypots.config.field.port", "int", default=161)],
    ),
    ConfigModule(
        key="ntp",
        name_key="honeypots.config.module.ntp",
        enabled_key="ntp.enabled",
        fields=[ConfigField("ntp.port", "honeypots.config.field.port", "int", default=123)],
    ),
    ConfigModule(
        key="tftp",
        name_key="honeypots.config.module.tftp",
        enabled_key="tftp.enabled",
        fields=[ConfigField("tftp.port", "honeypots.config.field.port", "int", default=69)],
    ),
    ConfigModule(
        key="git",
        name_key="honeypots.config.module.git",
        enabled_key="git.enabled",
        fields=[ConfigField("git.port", "honeypots.config.field.port", "int", default=9418)],
    ),
    ConfigModule(
        key="llmnr",
        name_key="honeypots.config.module.llmnr",
        enabled_key="llmnr.enabled",
        fields=[
            ConfigField("llmnr.port", "honeypots.config.field.port", "int", default=5355),
            ConfigField("llmnr.hostname", "honeypots.config.field.hostname", "str"),
            ConfigField(
                "llmnr.query_interval", "honeypots.config.field.llmnr_query_interval", "int",
                default=60,
            ),
            ConfigField(
                "llmnr.query_splay", "honeypots.config.field.llmnr_query_splay", "int", default=5
            ),
        ],
    ),
    ConfigModule(
        key="tcpbanner",
        name_key="honeypots.config.module.tcpbanner",
        enabled_key="tcpbanner_1.enabled",
        fields=[
            ConfigField(
                "tcpbanner_1.port", "honeypots.config.field.port", "int", default=8001
            ),
            ConfigField(
                "tcpbanner_1.initbanner", "honeypots.config.field.tcpbanner_initbanner", "str"
            ),
            ConfigField(
                "tcpbanner_1.datareceivedbanner",
                "honeypots.config.field.tcpbanner_datareceivedbanner",
                "str",
            ),
        ],
        hint_key="honeypots.config.module.tcpbanner_hint",
    ),
    ConfigModule(
        key="portscan",
        name_key="honeypots.config.module.portscan",
        enabled_key="portscan.enabled",
        fields=[
            ConfigField(
                "portscan.ignore_localhost",
                "honeypots.config.field.portscan_ignore_localhost",
                "bool",
            ),
            ConfigField(
                "portscan.synrate", "honeypots.config.field.portscan_synrate", "int", default=5
            ),
            ConfigField(
                "portscan.nmaposrate",
                "honeypots.config.field.portscan_nmaposrate",
                "int",
                default=5,
            ),
            ConfigField(
                "portscan.lorate", "honeypots.config.field.portscan_lorate", "int", default=3
            ),
            ConfigField(
                "portscan.ignore_ports", "honeypots.config.field.portscan_ignore_ports", "list"
            ),
        ],
        hint_key="honeypots.config.module.portscan_hint",
    ),
    ConfigModule(
        key="smb",
        name_key="honeypots.config.module.smb",
        enabled_key="smb.enabled",
        fields=[],
        hint_key="honeypots.config.module.smb_hint",
    ),
]


def _get_nested(config: dict[str, Any], key: str) -> Any:
    return config.get(key)


def _set_nested(config: dict[str, Any], key: str, value: Any) -> None:
    config[key] = value


def parse_config(raw: str) -> dict[str, Any]:
    """The config is a flat JSON object keyed by dotted strings
    (`"ftp.port"`, not nested `{"ftp": {"port": ...}}`) — OpenCanary's own
    format, not this app's choice. Raises `json.JSONDecodeError` on
    malformed content (surfaced to the operator as an error, not silently
    swallowed — a broken config on disk needs to be seen)."""
    return dict(json.loads(raw))


def field_value(config: dict[str, Any], field_def: ConfigField) -> Any:
    raw = _get_nested(config, field_def.key)
    if raw is None:
        return field_def.default if field_def.type != "list" else []
    if field_def.type == "list" and isinstance(raw, list):
        return ", ".join(str(v) for v in raw)
    return raw


def module_enabled(config: dict[str, Any], module: ConfigModule) -> bool:
    if module.enabled_key is None:
        return True
    return bool(_get_nested(config, module.enabled_key))


def apply_form_to_config(
    config: dict[str, Any], form: dict[str, str]
) -> dict[str, Any]:
    """Merges submitted form values into `config` (a copy — the input is
    never mutated), preserving every key this editor doesn't manage
    (`_UNMANAGED_KEYS`, and any other key a hand-edit or a newer
    OpenCanary version added that this schema doesn't know about) exactly
    as read. A checkbox absent from `form` means "unchecked", the normal
    HTML forms convention — every boolean field is set explicitly either
    way, never left at its old value by omission."""
    updated = dict(config)
    for module in OPENCANARY_MODULES:
        if module.enabled_key is not None:
            updated[module.enabled_key] = module.enabled_key in form
        for field_def in module.fields:
            raw = form.get(field_def.key)
            if field_def.type == "bool":
                updated[field_def.key] = field_def.key in form
            elif field_def.type == "int":
                if raw is not None and raw.strip():
                    try:
                        updated[field_def.key] = int(raw.strip())
                    except ValueError:
                        pass  # leave the existing value — caller validates before this
            elif field_def.type == "list":
                items = [p.strip() for p in (raw or "").split(",") if p.strip()]
                updated[field_def.key] = items
            else:  # str
                if raw is not None:
                    updated[field_def.key] = raw
    return updated


def build_read_command() -> str:
    """`sudo -n` first (root-owned, common after `--copyconfig` ran under
    Initialize's own root/sudo script), falling back to a plain read for
    an already-root connection or a world-readable file — same fallback
    shape `app.ssh.readonly`/`app.ssh.power` use for everything else."""
    cmd = f"cat {shlex.quote(OPENCANARY_CONFIG_PATH)}"
    return f"(sudo -n {cmd} 2>/dev/null || {cmd})"


def build_write_command(config: dict[str, Any]) -> str:
    """Writes the full config back (pretty-printed, matching `--copyconfig`'s
    own style closely enough to stay diffable by hand), restarts
    `opencanary` so the change takes effect, and enables/disables+starts/
    stops Samba's `smbd`/`nmbd` to match `smb.enabled` — see module
    docstring for why only these two services need explicit handling.

    Same temp-file-then-`sudo`-it shape `app.ssh.initialize.wrap_for_sudo`
    documents in full: the config (and the small script applying it) is
    first written to `/tmp` as the unprivileged login user, then run once
    under `sudo -n`, falling back to a plain run for an already-root
    connection — never a heredoc piped straight into `sudo`, which would
    either lose its content (sudo failing before exec'ing the reader) or
    fight a piped password for the same stdin.
    """
    payload = json.dumps(config, indent=4)
    config_marker = "HONEYHIVE_OPENCANARY_CONFIG"
    config_path = "/tmp/.honeyhive-opencanary.conf"  # noqa: S108 - written then removed below
    script_path = "/tmp/.honeyhive-opencanary-apply.sh"  # noqa: S108 - written then removed below

    service_lines = "systemctl enable --now smbd nmbd" if config.get("smb.enabled") else (
        "systemctl disable --now smbd nmbd"
    )
    script = (
        f"set -e\n"
        f"mv {shlex.quote(config_path)} {shlex.quote(OPENCANARY_CONFIG_PATH)}\n"
        f"systemctl restart opencanary\n"
        f"{service_lines} || true\n"
    )

    write_config = (
        f"cat > {shlex.quote(config_path)} <<'{config_marker}'\n{payload}\n{config_marker}\n"
    )
    script_marker = "HONEYHIVE_OPENCANARY_APPLY"
    write_script = (
        f"cat > {shlex.quote(script_path)} <<'{script_marker}'\n{script}{script_marker}\n"
    )

    run = (
        f"sudo -n bash {shlex.quote(script_path)} 2>/dev/null "
        f"|| bash {shlex.quote(script_path)}"
    )
    cleanup = f"rm -f {shlex.quote(config_path)} {shlex.quote(script_path)}"
    return f"{write_config}{write_script}{run}; status=$?; {cleanup}; exit $status"
