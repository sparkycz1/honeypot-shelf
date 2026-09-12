"""`app.tasks.celery_app._bootstrap_interval_settings` — the one-time,
process-start read of Celery Beat's own interval settings from
`AppSettings`, ported from an identical debcontrol change. Every process
except `celery ... beat` itself must get the built-in defaults immediately
with zero I/O (this app's whole test suite runs on that assumption — see
`app.tasks.celery_app`'s own module docstring)."""

from __future__ import annotations

from app.tasks.celery_app import _INTERVAL_SETTING_DEFAULTS, _bootstrap_interval_settings


def test_non_beat_process_gets_defaults_with_no_io(monkeypatch):
    """The test suite itself (collecting `app.main`) is exactly this case
    — if this ever touched the database, the whole suite's "no real
    Postgres" contract would be broken."""
    monkeypatch.setattr("sys.argv", ["pytest"])

    def _fail_if_called(*_args, **_kwargs):
        raise AssertionError("must not create a DB engine when not running as `beat`")

    monkeypatch.setattr("app.tasks.celery_app.create_async_engine", _fail_if_called)

    result = _bootstrap_interval_settings()

    assert result == _INTERVAL_SETTING_DEFAULTS
    assert result is not _INTERVAL_SETTING_DEFAULTS  # a copy, not the module's own dict


def test_beat_process_falls_back_to_defaults_when_db_unreachable(monkeypatch):
    """A fresh, not-yet-migrated instance's `beat` container must still
    start — never raise, just log a warning and fall back."""
    monkeypatch.setattr("sys.argv", ["celery", "-A", "app.tasks.celery_app", "beat"])

    def _boom(*_args, **_kwargs):
        raise RuntimeError("no database here")

    monkeypatch.setattr("app.tasks.celery_app.create_async_engine", _boom)

    result = _bootstrap_interval_settings()

    assert result == _INTERVAL_SETTING_DEFAULTS


def test_default_values_match_app_settings_column_defaults():
    """Keeps the two default sources (this module's fallback dict, and
    `AppSettings`'s own column defaults) from silently drifting apart —
    they must agree, since the fallback is meant to be indistinguishable
    from "the database just happens to hold the defaults."""
    from app.db.models.app_settings import AppSettings

    mapper = AppSettings.__mapper__
    for key, expected in _INTERVAL_SETTING_DEFAULTS.items():
        default = mapper.columns[key].default
        assert default is not None, f"{key} has no column default"
        assert getattr(default, "arg", None) == expected, f"{key} default drifted from AppSettings"
