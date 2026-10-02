"""The Logs tab's journal filters — unit, boot, priority, and "hide this
app's own SSH sessions" — plus priority-colored lines. Ported from
debcontrol's `app.ssh.logs` / `app.web.log_lines`."""

from __future__ import annotations

import json

from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.ssh import logs as ssh_logs
from app.web.log_lines import journal_log_lines, parse_log_lines
from tests.conftest import create_company


def test_journal_command_unit_boot_priority_and_structured_output():
    command = ssh_logs.build_journal_command(
        lines=100,
        search="",
        since="",
        until="",
        priority="warning",
        unit="opencanary.service",
        boot="-1",
        structured=True,
    )
    assert "-u opencanary.service" in command and "-b -1" in command and "-p warning" in command
    assert "-o json" in command and command.startswith('echo "@@SELF')


def test_journal_command_drops_unsafe_filters():
    bad = ssh_logs.build_journal_command(
        lines=10, search="", since="", until="", priority="nope", unit="x; rm -rf /", boot="7"
    )
    assert bad == "journalctl --no-pager -n 10"


def test_normalizers():
    assert ssh_logs.normalize_boot("0") == "0"
    assert ssh_logs.normalize_boot("-20") == "-20"
    assert ssh_logs.normalize_boot("-21") == ""
    assert ssh_logs.normalize_boot("1") == ""
    assert ssh_logs.normalize_unit("getty@tty1.service") == "getty@tty1.service"
    assert ssh_logs.normalize_unit("a b") == ""
    assert ssh_logs.normalize_priority(" ERR ") == "err"


def _entry(**fields: str) -> str:
    return json.dumps({"__REALTIME_TIMESTAMP": "1700000000000000", **fields})


def _own_session_journal() -> str:
    return "\n".join(
        [
            "@@SELF 1000 172.18.0.5",
            _entry(
                SYSLOG_IDENTIFIER="sshd",
                _PID="100",
                MESSAGE="Accepted publickey for honeypotshelf from 172.18.0.5 port 4242 ssh2",
            ),
            _entry(
                SYSLOG_IDENTIFIER="sshd",
                _PID="100",
                MESSAGE="pam_unix(sshd:session): session opened for user honeypotshelf",
            ),
            _entry(
                SYSLOG_IDENTIFIER="systemd-logind",
                _PID="1",
                SESSION_ID="7",
                LEADER="100",
                MESSAGE="New session 7 of user honeypotshelf.",
            ),
            _entry(
                SYSLOG_IDENTIFIER="systemd",
                _PID="1",
                UNIT="session-7.scope",
                MESSAGE="Started session-7.scope.",
            ),
            _entry(
                SYSLOG_IDENTIFIER="systemd",
                _PID="1",
                UNIT="user@1000.service",
                MESSAGE="Started user@1000.service.",
            ),
            _entry(
                SYSLOG_IDENTIFIER="sudo",
                _PID="300",
                MESSAGE="honeypotshelf : PWD=/ ; USER=root ; COMMAND=/usr/bin/apt-get update",
            ),
            _entry(
                SYSLOG_IDENTIFIER="sshd",
                _PID="200",
                MESSAGE="Failed password for root from 203.0.113.9 port 5000 ssh2",
            ),
            _entry(SYSLOG_IDENTIFIER="kernel", PRIORITY="3", MESSAGE="disk error"),
            "not json at all",
        ]
    )


def test_own_sessions_are_hidden_from_the_journal():
    entries, uid, address = ssh_logs.parse_journal_json(_own_session_journal())
    assert (uid, address) == ("1000", "172.18.0.5")

    kept, hidden = ssh_logs.filter_own_sessions(
        entries, own_uid=uid, own_address=address, username="honeypotshelf"
    )

    assert hidden == 6
    assert [e.message for e in kept] == [
        "Failed password for root from 203.0.113.9 port 5000 ssh2",
        "disk error",
    ]
    assert kept[1].priority == 3


def test_nothing_is_hidden_without_a_known_address():
    entries, uid, _ = ssh_logs.parse_journal_json(_own_session_journal())
    kept, hidden = ssh_logs.filter_own_sessions(
        entries, own_uid=uid, own_address=None, username="honeypotshelf"
    )
    assert hidden == 0 and len(kept) == len(entries)


def test_lines_are_colored_by_priority_or_keyword():
    lines = journal_log_lines(
        [{"text": "a disk error", "priority": 3}, {"text": "fine", "priority": 6}], "disk"
    )
    assert [line.level for line in lines] == ["error", None]
    assert lines[0].segments == [("a ", False), ("disk", True), (" error", False)]
    assert [line.level for line in parse_log_lines("ok\nWARNING: low\n")] == [None, "warn"]


async def _pinned_honeypot(db_session_factory) -> Honeypot:
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, company.id)],
            name="acme-honey1",
            ip_address="192.0.2.10",
            port=22,
            username="honeypotshelf",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fake-fingerprint-for-tests",
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
    return honeypot


async def test_logs_tab_passes_filters_and_renders_colored_lines(
    client, db_session_factory, celery_calls
):
    honeypot = await _pinned_honeypot(db_session_factory)
    celery_calls.result_for["app.tasks.jobs.view_honeypot_journal"] = {
        "ok": True,
        "output": "2026-10-02 10:00:00 h kernel: disk error",
        "entries": [{"text": "2026-10-02 10:00:00 h kernel: disk error", "priority": 3}],
        "hidden": 4,
    }

    response = await client.get(
        f"/honeypots/{honeypot.id}/logs",
        params={"unit": "opencanary.service", "boot": "-1", "priority": "err", "hide_own": "1"},
    )

    assert response.status_code == 200
    assert 'class="log-line log-error"' in response.text
    assert "4 lines of this app&#39;s own logins hidden" in response.text
    call = next(c for c in celery_calls if c[0] == "app.tasks.jobs.view_honeypot_journal")
    assert call[2]["unit"] == "opencanary.service"
    assert call[2]["boot"] == "-1"
    assert call[2]["priority"] == "err"
    assert call[2]["hide_own"] is True


async def test_logs_tab_ignores_unsafe_filters(client, db_session_factory, celery_calls):
    honeypot = await _pinned_honeypot(db_session_factory)

    await client.get(
        f"/honeypots/{honeypot.id}/logs", params={"unit": "x;id", "boot": "5", "priority": "x"}
    )

    call = next(c for c in celery_calls if c[0] == "app.tasks.jobs.view_honeypot_journal")
    assert (call[2]["unit"], call[2]["boot"], call[2]["priority"]) == ("", "", "")
    assert call[2]["hide_own"] is False
