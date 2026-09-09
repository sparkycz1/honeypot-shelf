"""`app.ssh.canary_activity` — the shell command that incrementally reads
OpenCanary's log, and parsing its output back into events + a new offset."""

from __future__ import annotations

import json

from app.ssh.canary_activity import build_read_command, parse_read_output


def test_build_read_command_quotes_the_path_and_embeds_the_offset():
    command = build_read_command(path="/mnt/tmpfs/opencanary.log", offset=42)
    assert "/mnt/tmpfs/opencanary.log" in command
    assert "42" in command
    assert "tail -c +$((start+1))" in command


def test_parse_read_output_returns_no_events_and_unchanged_offset_when_marker_missing():
    result = parse_read_output("garbage, no marker line at all")
    assert result.events == []
    assert result.new_offset == -1


def test_parse_read_output_parses_complete_json_lines():
    line1 = json.dumps({"logtype": "4002", "src_host": "1.2.3.4"})
    line2 = json.dumps({"logtype": "3000", "src_host": "5.6.7.8"})
    raw = f"{line1}\n{line2}\n\n===READ=== 0\n"

    result = parse_read_output(raw)

    assert len(result.events) == 2
    assert result.events[0]["logtype"] == "4002"
    assert result.events[1]["src_host"] == "5.6.7.8"
    assert result.new_offset == len((line1 + "\n" + line2 + "\n").encode("utf-8"))


def test_parse_read_output_leaves_an_incomplete_trailing_line_for_next_time():
    complete = json.dumps({"logtype": "4002"})
    # Real command output has exactly one "\n" between the file content and
    # the marker (from `printf "\n===READ=== ..."`) — an incomplete last
    # line (OpenCanary still mid-write) means the content itself doesn't
    # end in its own newline, so that single "\n" is the marker's, not the
    # content's.
    raw = f"{complete}\n{{'still writing this on" + "\n===READ=== 100\n"

    result = parse_read_output(raw)

    assert len(result.events) == 1
    # Only the complete line's bytes counted — the incomplete tail is
    # neither parsed nor counted toward the new offset.
    assert result.new_offset == 100 + len((complete + "\n").encode("utf-8"))


def test_parse_read_output_skips_malformed_lines_without_raising():
    raw = "not json at all\n" + json.dumps({"logtype": "4002"}) + "\n\n===READ=== 0\n"

    result = parse_read_output(raw)

    assert len(result.events) == 1
    assert result.events[0]["logtype"] == "4002"


def test_parse_read_output_uses_the_reported_start_as_offset_base():
    raw = json.dumps({"logtype": "1"}) + "\n\n===READ=== 500\n"

    result = parse_read_output(raw)

    line_bytes = len((json.dumps({"logtype": "1"}) + "\n").encode("utf-8"))
    assert result.new_offset == 500 + line_bytes
