"""`app.services.notifications` — template rendering and defaults."""

from __future__ import annotations

from app.db.models.app_settings import AppSettings
from app.services.notifications import default_template, render_template


def test_default_template_falls_back_to_english_for_unknown_locale():
    en_subject, en_body = default_template("alert", "en")
    fallback_subject, fallback_body = default_template("alert", "xx")
    assert fallback_subject == en_subject
    assert fallback_body == en_body


def test_default_template_has_czech_translations_too():
    cs_subject, _cs_body = default_template("unavailable", "cs")
    en_subject, _en_body = default_template("unavailable", "en")
    assert cs_subject != en_subject


def test_render_template_uses_default_when_app_settings_has_no_override():
    app_settings = AppSettings()
    subject, body = render_template(
        "alert",
        app_settings,
        {
            "honeypot_name": "acme-honey1",
            "event_type": "ssh.login_attempt",
            "src_ip": "203.0.113.7",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "details": "",
        },
    )
    assert "acme-honey1" in subject
    assert "acme-honey1" in body
    assert "203.0.113.7" in body


def test_render_template_uses_admin_override_when_set():
    app_settings = AppSettings()
    app_settings.notification_alert_subject = "Custom: {honeypot_name}"
    app_settings.notification_alert_body = "Body for {honeypot_name}"
    subject, body = render_template(
        "alert", app_settings, {"honeypot_name": "acme-honey1"}
    )
    assert subject == "Custom: acme-honey1"
    assert body == "Body for acme-honey1"


def test_render_template_leaves_unknown_placeholders_as_literal_text():
    app_settings = AppSettings()
    app_settings.notification_alert_subject = "{honeypot_name} — {not_a_real_key}"
    app_settings.notification_alert_body = "body"
    subject, _body = render_template("alert", app_settings, {"honeypot_name": "x"})
    assert subject == "x — {not_a_real_key}"
