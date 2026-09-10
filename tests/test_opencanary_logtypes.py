"""`app.services.opencanary_logtypes` — mapping OpenCanary's numeric
`logtype` ids to human labels and Config-tab module keys."""

from __future__ import annotations

from app.services.opencanary_logtypes import is_internal_logtype, logtype_label, module_key


def test_logtype_label_accepts_int_or_numeric_string():
    assert logtype_label(4002) == "SSH login attempt"
    assert logtype_label("4002") == "SSH login attempt"


def test_logtype_label_falls_back_to_the_raw_value_when_unknown():
    assert logtype_label(999999) == "999999"
    assert logtype_label("already-human-text") == "already-human-text"


def test_logtype_label_covers_custom_user_slots():
    assert logtype_label(99003) == "Custom event 3"


def test_module_key_maps_service_alerts_to_the_config_tabs_module_key():
    assert module_key(4002) == "ssh"
    assert module_key("3000") == "http"
    assert module_key(5001) == "portscan"


def test_module_key_is_none_for_base_system_lines_and_unknown_ids():
    assert module_key(1001) is None
    assert module_key(999999) is None


def test_is_internal_logtype_true_for_opencanarys_own_operational_lines():
    """Regression guard: these used to flood the Activity tab/Dashboard
    with "General message"/"Debug message" noise on every module
    registration and, worse, on every crash-loop restart — see
    app.ssh.initialize's opencanary.service Type=forking fix."""
    for logtype in (1000, 1001, 1002, 1003, 1004, 1005, 1006):
        assert is_internal_logtype(logtype) is True
        assert is_internal_logtype(str(logtype)) is True


def test_is_internal_logtype_false_for_real_alerts():
    assert is_internal_logtype(4002) is False
    assert is_internal_logtype("3000") is False


def test_is_internal_logtype_false_for_unrecognized_or_missing_values():
    assert is_internal_logtype(None) is False
    assert is_internal_logtype(999999) is False
    assert is_internal_logtype("already-human-text") is False
