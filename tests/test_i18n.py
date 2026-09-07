"""app/i18n (locale discovery, translate() fallback rules)."""

from __future__ import annotations

import pytest

from app import i18n


@pytest.fixture(autouse=True)
def _fresh_registry():
    """`i18n._registry()` is `@lru_cache`d (parsed once per process) — clear
    it before and after every test in this file so a test always re-reads
    the shipped locale files rather than a stale cached copy from an
    earlier test run in the same session."""
    i18n._registry.cache_clear()
    yield
    i18n._registry.cache_clear()


def test_shipped_locales_include_english_and_czech():
    codes = {locale.code for locale in i18n.available_locales()}
    assert "en" in codes
    assert "cs" in codes


def test_available_locales_lists_english_first():
    locales = i18n.available_locales()
    assert locales[0].code == "en"


def test_get_locale_falls_back_to_default_for_unknown_or_none_code():
    default = i18n.get_locale(None)
    assert default.code == "en"
    assert i18n.get_locale("some-locale-nobody-shipped").code == "en"


def test_get_locale_returns_the_requested_one_when_it_exists():
    assert i18n.get_locale("cs").code == "cs"


def test_translate_uses_the_requested_locale():
    cs = i18n.get_locale("cs")
    assert i18n.translate(cs, "nav.dashboard") == "Přehled"


def test_translate_falls_back_to_english_for_a_key_missing_in_a_locale():
    # A locale file need not translate every key — see the module
    # docstring's "still catching up" reasoning.
    partial = i18n.Locale(code="xx", label="Test", strings={})
    en = i18n.get_locale(None)
    assert i18n.translate(partial, "nav.dashboard") == en.strings["nav.dashboard"]


def test_translate_falls_back_to_the_literal_key_when_missing_everywhere():
    partial = i18n.Locale(code="xx", label="Test", strings={})
    assert i18n.translate(partial, "some.key.nobody.defined") == "some.key.nobody.defined"


def test_translate_substitutes_kwargs():
    en = i18n.get_locale("en")
    result = i18n.translate(en, "nav.switch_theme", theme="dark")
    assert "dark" in result
