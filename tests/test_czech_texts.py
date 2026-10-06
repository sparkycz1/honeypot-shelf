"""The Czech texts speak one way: formal address, no English left over
from the port, one word for an event — and counts that decline."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.i18n import get_locale, translate

_ROOT = Path(__file__).resolve().parent.parent
_LOCALES = _ROOT / "app" / "i18n" / "locales"


def _strings(code: str) -> dict[str, str]:
    strings: dict[str, str] = json.loads((_LOCALES / f"{code}.json").read_text(encoding="utf-8"))[
        "strings"
    ]
    return strings


# Informal second person singular: pronouns and the imperatives this app's
# texts actually used. Not a grammar check — a tripwire for the next string
# written the old way.
_INFORMAL = re.compile(
    r"\b(jsi|bys|abys|budeš|můžeš|musíš|chceš|najdeš|potřebuješ|tvůj|tvoje|tvého|tvému|tvým|tvé"
    r"|tvou|tebe|tobě|sám/sama|spusť|klikni|zkus|potvrď|nastav|přidej|použij|vyber|zadej|ověř"
    r"|zkontroluj|změň|nech|vlož|ulož|napiš|přihlas|oprav|vypni|zapni)\b",
    re.IGNORECASE,
)

# English names of pages, tabs and states that have a Czech name in the UI.
# Wiki page titles ("Honeypot Initialize", "Architecture") stay as they are.
_ENGLISH = re.compile(
    r"\b(Settings|Overview|Dashboard|SSH key|Initialize|Updates|Terminal)\b|\bevent[yů]\b|appk"
)
_ENGLISH_ALLOWED = {"honeypots.config.module.portscan_hint"}  # names the wiki page


def test_czech_uses_formal_address_everywhere() -> None:
    informal = {k: v for k, v in _strings("cs").items() if _INFORMAL.search(v)}
    assert not informal


def test_czech_has_no_english_page_names_left() -> None:
    leftovers = {
        key: value
        for key, value in _strings("cs").items()
        if key not in _ENGLISH_ALLOWED and _ENGLISH.search(value)
    }
    assert not leftovers


def test_czech_calls_an_event_one_thing() -> None:
    # "alert" survives only as the syslog priority name and in an example URL.
    alerts = {
        key for key, value in _strings("cs").items() if re.search(r"alert", value, re.IGNORECASE)
    }
    assert alerts == {"honeypots.logs.priority.alert", "notifications.rule.channel_hint_ntfy"}


@pytest.mark.parametrize("code", ["en", "cs"])
def test_no_count_is_written_with_a_bracketed_ending(code: str) -> None:
    bracketed = {
        key: value
        for key, value in _strings(code).items()
        if "{count}" in value and re.search(r"\w\((s|í|ů|y|e)\)", value)
    }
    assert not bracketed


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        (0, "0 firem"),
        (1, "1 firma"),
        (2, "2 firmy"),
        (4, "4 firmy"),
        (5, "5 firem"),
        ("3", "3 firmy"),  # a count that came back through a query string
    ],
)
def test_czech_counts_decline(count: object, expected: str) -> None:
    assert translate(get_locale("cs"), "dashboard.companies_count", count=count) == expected


def test_english_counts_have_a_singular() -> None:
    english = get_locale("en")
    assert translate(english, "dashboard.companies_count", count=1) == "1 company"
    assert translate(english, "dashboard.companies_count", count=3) == "3 companies"
    one_event = translate(english, "honeypots.activity.total_in_range", count=1)
    assert one_event == "1 event in this range."


def test_a_plural_variant_always_has_its_base_string() -> None:
    for code in ("en", "cs"):
        strings = _strings(code)
        orphans = [
            key
            for key in strings
            if key.endswith((".one", ".few")) and key.rsplit(".", 1)[0] not in strings
        ]
        assert not orphans, code


def test_long_explanations_are_folded_under_more() -> None:
    templates = _ROOT / "app" / "web" / "templates"
    for relative, key in (
        ("honeypots/update_history.html", "honeypots.updates.history.hint_more"),
        ("auth/account.html", "account.ssh_keys.hint_more"),
        ("initialize/index.html", "initialize.intro_more"),
    ):
        text = (templates / relative).read_text(encoding="utf-8")
        folded = text.split('<details class="hint-more">', 1)[1].split("</details>", 1)[0]
        assert key in folded, relative
    for code in ("en", "cs"):
        strings = _strings(code)
        for key in ("honeypots.updates.history.hint", "account.ssh_keys.hint", "initialize.intro"):
            assert len(strings[key]) < 140, (code, key)


def test_no_heading_repeats_the_button_under_it() -> None:
    for code in ("en", "cs"):
        strings = _strings(code)
        assert (
            strings["honeypots.detail.test_connection_heading"]
            != strings["honeypots.detail.test_connection_button"]
        )
        assert strings["history.add_note"] != strings["history.save_note"]
