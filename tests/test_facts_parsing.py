"""`app.ssh.facts.parse_facts_output`'s two cross-distro additions:
`supports_readonly_root` (raspi-config, live-detected on every facts
refresh rather than only at Initialize — see `app.ssh.platform_detect`'s
module docstring for why) and `opencanary_log_path` (read back from
OpenCanary's own config, not guessed)."""

from __future__ import annotations

from app.ssh.facts import parse_facts_output


def _raw(raspi_config: str, opencanary_log: str) -> str:
    return (
        "===HOSTNAME===\nacme-honey1\n"
        "===OS===\nDebian GNU/Linux 13 (trixie)\n"
        "===OS_ID===\ndebian\n"
        "===KERNEL===\n6.12.0\n"
        "===KERNEL_LATEST===\n\n"
        "===ARCH===\naarch64\n"
        "===CPU===\n4\n"
        "===CPU_MODEL===\n\n"
        "===RAM_KB===\n\n"
        "===RAM_SPEED===\n\n"
        "===DISKS===\n\n"
        "===UPTIME===\n\n"
        "===PROCESSES===\n\n"
        "===FILESYSTEMS===\n\n"
        "===NETWORK===\n\n"
        f"===RASPI_CONFIG===\n{raspi_config}\n"
        f"===OPENCANARY_LOG===\n{opencanary_log}\n"
    )


def test_supports_readonly_root_true_when_raspi_config_present():
    facts = parse_facts_output(_raw("yes", ""))
    assert facts["supports_readonly_root"] is True


def test_supports_readonly_root_false_when_raspi_config_absent():
    facts = parse_facts_output(_raw("no", ""))
    assert facts["supports_readonly_root"] is False


def test_opencanary_log_path_read_back_from_the_configured_path():
    facts = parse_facts_output(_raw("no", "/var/log/opencanary/opencanary.log"))
    assert facts["opencanary_log_path"] == "/var/log/opencanary/opencanary.log"


def test_opencanary_log_path_none_when_config_unreadable():
    """OpenCanary not installed/configured yet - the python3 probe prints
    nothing (its stderr is suppressed) - must be None (leave the
    honeypot's existing value alone), never an empty-string path."""
    facts = parse_facts_output(_raw("no", ""))
    assert facts["opencanary_log_path"] is None


def test_opencanary_log_path_rejects_a_non_absolute_value():
    """A garbled/truncated read must never become a bogus path a future
    poll tries to `tail` - only a value starting with "/" is trusted."""
    facts = parse_facts_output(_raw("no", "not-a-real-path"))
    assert facts["opencanary_log_path"] is None
