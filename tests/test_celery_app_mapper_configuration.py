"""Regression guard for a real bug found live: on its very first boot
after `HoneypotNotificationSubscription` was added (`User.
notification_subscriptions` referencing it), `celery beat` logged a
scary-looking `sqlalchemy.exc.InvalidRequestError: ... failed to locate a
name 'HoneypotNotificationSubscription'` and silently fell back to
hardcoded interval defaults instead of reading the real configured
values — caught by `_bootstrap_interval_settings`'s own `except
Exception`, so not a crash, but a real, avoidable miss nonetheless.

Root cause: `app.tasks.celery_app._bootstrap_interval_settings` runs a
real ORM query at *module import time*, before Celery's own
`include=[...]` has had a chance to import `app.tasks.jobs` (where most
model modules get imported as a side effect) — and SQLAlchemy configures
every mapped class's relationships the first time *any* one of them is
queried, so a relationship's string/forward-reference annotation (every
relationship in this codebase) needs its target class already registered
at that exact moment, not merely imported eventually.

This can only be caught with a genuinely fresh Python process — in the
normal test process, some earlier test has almost certainly already
imported `app.tasks.jobs` (or `app.db.models`), masking the bug entirely.
Hence the subprocess below, importing only `app.tasks.celery_app` in
isolation, exactly as Celery's own `-A app.tasks.celery_app` entry point
would before pulling in its `include` list."""

from __future__ import annotations

import subprocess
import sys


def test_importing_celery_app_alone_configures_every_mapper_cleanly():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.argv = ['celery', '-A', 'app.tasks.celery_app', 'beat']; "
            "import app.tasks.celery_app; "
            "from sqlalchemy.orm import configure_mappers; "
            "configure_mappers(); "
            "print('OK')",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout
