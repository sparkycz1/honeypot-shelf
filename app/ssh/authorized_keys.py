"""Shared shell-command builder for idempotently appending one or more SSH
public keys to an account's `~/.ssh/authorized_keys` — used by
`app.ssh.initialize` (a freshly provisioned device) and
`app.tasks.jobs.push_superadmin_ssh_keys` (an already-onboarded honeypot).

Home-dir aware (`getent passwd`, never a literal `~`): both callers may run
this wrapped under a single `sudo bash <script>` invocation for the whole
script (see `app.ssh.initialize.wrap_for_sudo`) — under that wrapping, `~`
resolves to the *connecting* (root-after-sudo) account's home, not
necessarily the target account's, whenever they differ (e.g. connected as
`pi` but escalated via `sudo`). `getent passwd <user>` sidesteps that
entirely by asking for the real answer instead of relying on `$HOME`.

**Never removes or overwrites anything already there** — each key is
`grep -qxF` checked before being appended, exactly the same idempotent
pattern `app.ssh.onboarding.build_onboarding_command` and
`app.tasks.jobs._push_pending_ssh_key` already use for the same reason: a
key added by hand (or by an earlier run of this) must never be at risk
from a later one.
"""

from __future__ import annotations

import shlex


def build_authorized_keys_append_command(username: str, keys: list[str]) -> str:
    """One `;`-joined shell fragment (not a full `set -e` script of its
    own — callers embed this into a larger one) that ensures every key in
    `keys` is present in `username`'s `authorized_keys`, creating
    `~/.ssh` first if it doesn't exist yet. Keys already present are left
    untouched (`grep -qxF`); blank/malformed entries are the caller's
    problem to filter out first (see `app.auth.ssh_keys.
    parse_ssh_public_keys`) — this function trusts `keys` are already
    valid, single-line `authorized_keys` entries.
    """
    quoted_user = shlex.quote(username)
    parts = [
        f'home="$(getent passwd {quoted_user} | cut -d: -f6)"',
        'install -d -m 700 "$home/.ssh"',
        'touch "$home/.ssh/authorized_keys"',
    ]
    for key in keys:
        quoted_key = shlex.quote(key.strip())
        parts.append(
            f'(grep -qxF {quoted_key} "$home/.ssh/authorized_keys" 2>/dev/null || '
            f'echo {quoted_key} >> "$home/.ssh/authorized_keys")'
        )
    parts.append('chmod 600 "$home/.ssh/authorized_keys"')
    parts.append(f'chown -R {quoted_user}:{quoted_user} "$home/.ssh"')
    return "; ".join(parts)
