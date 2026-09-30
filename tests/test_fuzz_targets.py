"""Every fuzz target (`fuzz/targets.py`) run over a fixed seed corpus plus a
few hundred deterministic pseudo-random inputs — so a contract a target
checks can't regress unnoticed between the coverage-guided runs in
`.github/workflows/fuzz.yml`, and so the targets run on every OS (Atheris
itself is Linux-only). An input the fuzzer once crashed on belongs in
`_SEEDS` once it's fixed."""

from __future__ import annotations

import random
import re
from collections.abc import Callable
from pathlib import Path

import pytest

from fuzz.targets import TARGETS

_TOKENS = [
    "\n", "\t", " ", ":", "=", ",", ";", "|", "/", "\\", "[", "]", "{", "}", '"', "'",
    "-", ".", "0", "1", "99999", "-1", "nan", "inf", "%", "@", "http://", "https://",
    "//", "?", "#", "::", "\x00", "\x7f", "é", chr(0x2028), "null", "[]", "{}", "- ",
    "&a", "*a", "!!python/object", "---", "kB", "MiB", "running", "OK", "CVE-2024-1",
    "===READ===", '{"logtype":', '"src_port":', '"src_host":', '"logdata":', "12345678901",
]

# Inputs that once broke a target, kept so they can't come back.
_POLL_END = b"\n\n===READ=== 0\n"
_SEEDS: list[bytes] = [
    b"",
    # A redirect target browsers read as `//evil.example`.
    b"/\evil.example",
    b"/\t/evil.example",
    # OpenCanary log lines a compromised honeypot could write: an oversized
    # logtype, an out-of-range port, a non-string source, a non-object
    # logdata, and one nested far too deep for the JSON parser.
    b'{"logtype": "' + b"x" * 200 + b'"}' + _POLL_END,
    b'{"src_port": 99999999999, "dst_port": -5}' + _POLL_END,
    b'{"src_host": 12}' + _POLL_END,
    b'{"src_host": "' + b"a" * 100 + b'"}' + _POLL_END,
    b'{"logdata": "str"}' + _POLL_END,
    b"[" * 5000 + _POLL_END,
    # An opencanary.conf that is valid JSON but not an object, or too deep.
    b"true",
    b"[1]",
    b"[" * 5000,
    # A pasted "key" whose DER body trips asyncssh's ASN.1 decoder.
    b"0#" + b"\x03" * 96,
    # A tag cut at its length cap right after a space.
    b"a" * 63 + b" b",
]


def _inputs(name: str, count: int = 300) -> list[bytes]:
    rng = random.Random(name)  # noqa: S311 - reproducible test inputs, not secrets
    inputs = list(_SEEDS)
    for _ in range(count):
        if rng.random() < 0.2:
            inputs.append(rng.randbytes(rng.randint(0, 120)))
        else:
            text = "".join(rng.choice(_TOKENS) for _ in range(rng.randint(0, 40)))
            inputs.append(text.encode("utf-8", "surrogatepass"))
    return inputs


@pytest.mark.parametrize("name", sorted(TARGETS))
def test_fuzz_target_holds_its_contract(name: str) -> None:
    target: Callable[[bytes], None] = TARGETS[name]
    for data in _inputs(name):
        target(data)


def test_the_fuzz_workflow_runs_every_target() -> None:
    workflow = (Path(__file__).parent.parent / ".github" / "workflows" / "fuzz.yml").read_text(
        encoding="utf-8"
    )
    # The matrix is the only `target:` list in the file (no YAML parser here).
    block = workflow.split("        target:\n", 1)[1].split("    steps:", 1)[0]
    listed = re.findall(r"^          - (\w+)$", block, re.MULTILINE)
    assert sorted(listed) == sorted(TARGETS)
