"""`app.services.opencanary_logtypes` — mapping OpenCanary's numeric
`logtype` ids to human labels and Config-tab module keys."""

from __future__ import annotations

from app.services.opencanary_logtypes import logtype_label, module_key


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
