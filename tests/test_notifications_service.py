"""`app.services.notifications` — template rendering and defaults."""

from __future__ import annotations

from app.db.models.notification_rule import NotificationRule, NotificationScope
from app.db.models.user import AuthProvider, User
from app.services.notifications import default_template, render_template


def _rule(
    *,
    user: User | None = None,
    alert_subject: str | None = None,
    alert_body: str | None = None,
) -> NotificationRule:
    """An in-memory `NotificationRule` with its own in-memory `user` —
    never persisted, just enough for `render_template` to read `rule.user`
    (its own locale) without a real DB session."""
    rule = NotificationRule(
        name="test rule",
        scope=NotificationScope.HONEYPOT,
        alert_subject=alert_subject,
        alert_body=alert_body,
    )
    rule.user = user or User(username="rule-owner", auth_provider=AuthProvider.LOCAL)
    return rule


def test_default_template_falls_back_to_english_for_unknown_locale():
    en_subject, en_body = default_template("alert", "en")
    fallback_subject, fallback_body = default_template("alert", "xx")
    assert fallback_subject == en_subject
    assert fallback_body == en_body


def test_default_template_has_czech_translations_too():
    cs_subject, _cs_body = default_template("unavailable", "cs")
    en_subject, _en_body = default_template("unavailable", "en")
    assert cs_subject != en_subject


def test_render_template_uses_default_when_rule_has_no_override():
    rule = _rule()
    subject, body = render_template(
        "alert",
        rule,
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


def test_render_template_uses_the_rules_own_locale_for_the_default():
    cs_user = User(username="cs-owner", auth_provider=AuthProvider.LOCAL, locale="cs")
    rule = _rule(user=cs_user)
    subject, _body = render_template("alert", rule, {"honeypot_name": "x"})
    cs_default_subject, _ = default_template("alert", "cs")
    assert subject == cs_default_subject.format(honeypot_name="x")


def test_render_template_falls_back_to_the_instance_default_language(monkeypatch):
    """A user who never explicitly picked a UI language (`User.locale` is
    `None`) still gets their email in whatever language the instance is
    actually configured to show them by default — not hardcoded English —
    same fallback `request.state.locale` uses for their page views
    (`app.auth.middleware`). Regression test: this used to fall back to
    the hardcoded `DEFAULT_LOCALE_CODE` ("en") instead, so an instance
    configured with `DEFAULT_LANGUAGE=cs` sent still-uncustomized rules'
    emails in English even to a user who only ever saw the Czech UI."""
    from app.core.config import get_settings

    class _FakeSettings:
        default_language = "cs"

    monkeypatch.setattr(
        "app.services.notifications.get_settings", lambda: _FakeSettings()
    )
    assert get_settings().default_language != "cs"  # sanity: the real default is unchanged

    rule = _rule(user=User(username="no-locale-set", auth_provider=AuthProvider.LOCAL))
    subject, _body = render_template("alert", rule, {"honeypot_name": "x"})
    cs_default_subject, _ = default_template("alert", "cs")
    assert subject == cs_default_subject.format(honeypot_name="x")


def test_render_template_uses_rule_override_when_set():
    rule = _rule(alert_subject="Custom: {honeypot_name}", alert_body="Body for {honeypot_name}")
    subject, body = render_template("alert", rule, {"honeypot_name": "acme-honey1"})
    assert subject == "Custom: acme-honey1"
    assert body == "Body for acme-honey1"


def test_render_template_leaves_unknown_placeholders_as_literal_text():
    rule = _rule(alert_subject="{honeypot_name} — {not_a_real_key}", alert_body="body")
    subject, _body = render_template("alert", rule, {"honeypot_name": "x"})
    assert subject == "x — {not_a_real_key}"
