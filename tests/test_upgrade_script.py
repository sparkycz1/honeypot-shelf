"""`scripts/upgrade.sh` is still being read by bash while its own `git pull`
replaces it on disk: after the pull, the old process carries on reading the
*new* file from the byte offset where the old one's pull block ended. So
everything up to and including that block must never change between
releases — new steps go below it. If this test fails, move your change
below the `git pull` block instead of updating the hash."""

from __future__ import annotations

import hashlib
from pathlib import Path

_PULL_BLOCK_END = b'  git pull --ff-only origin "$branch"\nfi\n'
_PREFIX_SHA256 = "e7b7f15721955790df3926bcb3610bd2acb041f77a1adbbfac6d6cd8ea4569dc"


def test_upgrade_script_prefix_is_unchanged():
    script = (Path(__file__).parent.parent / "scripts" / "upgrade.sh").read_bytes()
    end = script.index(_PULL_BLOCK_END) + len(_PULL_BLOCK_END)
    assert hashlib.sha256(script[:end]).hexdigest() == _PREFIX_SHA256
