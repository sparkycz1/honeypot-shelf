"""`app.ssh.facts.FACTS_COMMAND`'s CPU model probe — regression guard for a
real bug found live on a Raspberry Pi (aarch64) honeypot: `/proc/cpuinfo`'s
`model name` field is x86-only, so `cpu_model` came back empty on every ARM
device. Fixed by preferring `lscpu`'s own `Model name:` line, which exists
on both architectures — but modern util-linux nests it under `Vendor ID:`
in its tree-style output (two leading spaces), so the extraction must not
anchor straight to column 1. These tests run the *actual* shell fragment
(not a Python re-implementation of what it's supposed to do) via a real
`bash -c`, against a fake `lscpu` on `PATH`, the same "reproduce it for
real" standard the mlocate/gpg Initialize fixes used.
"""

from __future__ import annotations

import os
import stat
import subprocess

from app.ssh.facts import FACTS_COMMAND, _split_sections

# Real output pasted from an actual Raspberry Pi 4 (Cortex-A72) honeypot —
# `Model name:` is nested two spaces under `Vendor ID:`.
_ARM_LSCPU_OUTPUT = """\
Architecture:                aarch64
  CPU op-mode(s):            32-bit, 64-bit
  Byte Order:                Little Endian
CPU(s):                      4
  On-line CPU(s) list:       0-3
Vendor ID:                   ARM
  Model name:                Cortex-A72
    Model:                   3
    Thread(s) per core:      1
"""

_X86_LSCPU_OUTPUT = """\
Architecture:            x86_64
Vendor ID:               GenuineIntel
Model name:               Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz
"""


def _run_facts_command_with_fake_lscpu(tmp_path, lscpu_output: str) -> str:
    """Runs the real `FACTS_COMMAND` under `bash -c`, with a fake `lscpu`
    shell script prepended to `PATH` so no real hardware/tool is needed.
    Returns the raw CPU_MODEL section's contents."""
    fake_lscpu = tmp_path / "lscpu"
    fake_lscpu.write_text(f"#!/bin/sh\ncat <<'EOF'\n{lscpu_output}EOF\n")
    fake_lscpu.chmod(fake_lscpu.stat().st_mode | stat.S_IEXEC)

    env = dict(os.environ)
    env["PATH"] = f"{tmp_path}:{env.get('PATH', '')}"

    result = subprocess.run(  # noqa: S603 - fixed args, no user input
        ["bash", "-c", FACTS_COMMAND],  # noqa: S607 - bash resolved via PATH on purpose
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )
    sections = _split_sections(result.stdout)
    return sections.get("CPU_MODEL", "")


def test_cpu_model_extracted_from_arm_style_nested_lscpu_output(tmp_path):
    assert _run_facts_command_with_fake_lscpu(tmp_path, _ARM_LSCPU_OUTPUT) == "Cortex-A72"


def test_cpu_model_extracted_from_flat_x86_style_lscpu_output(tmp_path):
    assert (
        _run_facts_command_with_fake_lscpu(tmp_path, _X86_LSCPU_OUTPUT)
        == "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz"
    )
