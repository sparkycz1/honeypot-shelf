"""Per-user UI language — a self-contained JSON file per locale under
`app/i18n/locales/`, auto-discovered at process start. Adding a language
needs **no code change**: drop a new `<code>.json` file next to `en.json`
(same `strings` keys, translated — partial is fine, see `translate()`'s
fallback) and it appears in every "Language" picker automatically, for
every account, the next time the app restarts.

File shape:

    {
      "meta": {"code": "cs", "label": "Čeština"},
      "strings": {"nav.dashboard": "Přehled", "...": "..."}
    }

`meta.code` must match the filename stem (`cs.json` → `"code": "cs"`) — a
defensive check, not just convention, so a renamed or copy-pasted file
fails loudly (skipped, logged) at startup instead of silently registering
under the wrong code.

Lookup order for any single key (`translate()`): the requested locale's
own string → the default locale's (English) → the literal key itself. A
locale file that's missing a key — translation still catching up, or
someone only translated part of the app — degrades to readable English
rather than a blank string or a crash, the same "never worse than doing
nothing" defensive style `app.ssh.facts` already uses for an unreadable
fact.

Deliberately not `gettext`/Babel: this app has no other i18n need (dates
render in `Settings.tz`, not per-locale — see `app.web.templating.
local_time`) and a flat JSON key→string map is the lowest-friction format
for a contributor with no Python/Babel tooling to send a translation for.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

LOCALES_DIR = Path(__file__).resolve().parent / "locales"

# The locale every account starts on, and the fallback for any key a
# non-default locale doesn't have (yet, or ever). Must always have a
# corresponding en.json — see _registry()'s own guard if it somehow doesn't.
DEFAULT_LOCALE_CODE = "en"


@dataclass(frozen=True)
class Locale:
    code: str
    label: str  # Native name, e.g. "Čeština" — shown in the picker, not "Czech".
    strings: dict[str, str]


def _load_locale_file(path: Path) -> Locale | None:
    try:
        data: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning("i18n: skipping unreadable locale file %s: %s", path, exc)
        return None
    if not isinstance(data, dict):
        logger.warning("i18n: skipping %s — not a JSON object", path)
        return None
    meta, strings = data.get("meta"), data.get("strings")
    if not isinstance(meta, dict) or not isinstance(strings, dict):
        logger.warning("i18n: skipping %s — missing/malformed \"meta\" or \"strings\"", path)
        return None
    code, label = meta.get("code"), meta.get("label")
    if not isinstance(code, str) or not code or not isinstance(label, str) or not label:
        logger.warning("i18n: skipping %s — meta.code/meta.label must be non-empty strings", path)
        return None
    if code != path.stem:
        logger.warning(
            'i18n: skipping %s — meta.code %r doesn\'t match its filename ("%s.json" expected)',
            path,
            code,
            code,
        )
        return None
    return Locale(
        code=code,
        label=label,
        strings={k: v for k, v in strings.items() if isinstance(k, str) and isinstance(v, str)},
    )


@lru_cache
def _registry() -> dict[str, Locale]:
    """Every valid locale file under `LOCALES_DIR`, keyed by code — parsed
    once per process (each web/worker/beat process loads its own copy, same
    as `app.web.os_logos`'s badge icons). Restart to pick up an added or
    edited locale file."""
    locales: dict[str, Locale] = {}
    if LOCALES_DIR.is_dir():
        for path in sorted(LOCALES_DIR.glob("*.json")):
            locale = _load_locale_file(path)
            if locale is not None:
                locales[locale.code] = locale
    if DEFAULT_LOCALE_CODE not in locales:
        # Should be unreachable — en.json ships with the app — but a
        # corrupt default locale file must never take the whole app down
        # over a translation, only degrade every string to its raw key.
        logger.error(
            "i18n: %s.json is missing or invalid — falling back to raw keys", DEFAULT_LOCALE_CODE
        )
        locales[DEFAULT_LOCALE_CODE] = Locale(code=DEFAULT_LOCALE_CODE, label="English", strings={})
    return locales


def available_locales() -> list[Locale]:
    """Every usable locale — English first, the rest alphabetized by their
    own native label. What a "Language" `<select>` should iterate."""
    locales = _registry()
    default = locales[DEFAULT_LOCALE_CODE]
    rest = sorted(
        (locale for locale in locales.values() if locale.code != DEFAULT_LOCALE_CODE),
        key=lambda locale: locale.label,
    )
    return [default, *rest]


def get_locale(code: str | None, *, default: str = DEFAULT_LOCALE_CODE) -> Locale:
    """The requested locale, or `default` if `code` is `None`/unknown — a
    user who never chose one, or whose chosen locale's file was since
    removed (see `User.locale`'s own docstring). `default` is the
    deploy-wide `Settings.default_language` (Middleware passes it for both
    an anonymous request and an authenticated user with `locale IS NULL`)
    — kept distinct from `DEFAULT_LOCALE_CODE` (the always-English
    translation-gap fallback in `translate()`, never configurable): an
    operator-chosen starting language is one thing, the safety net for a
    string a locale file hasn't translated yet is another, and the two
    must never be conflated. An unrecognized `default` itself still falls
    back to `DEFAULT_LOCALE_CODE`, same as an unrecognized `code`."""
    locales = _registry()
    if code and code in locales:
        return locales[code]
    if default in locales:
        return locales[default]
    return locales[DEFAULT_LOCALE_CODE]


# Languages whose nouns take a third form after 2-4 ("3 firmy", but "5
# firem"). Everything else here has just singular and plural.
_FEW_FORM_LOCALES = frozenset({"cs"})


def _plural_suffix(code: str, count: object) -> str | None:
    """Which variant of a counted string `count` calls for: `.one`, `.few`
    (only in a language that has it), or None for the plain key — the
    form used for 0 and for larger counts."""
    if isinstance(count, str) and count.isdigit():
        # A count that came back through a redirect's query string.
        count = int(count)
    if isinstance(count, bool) or not isinstance(count, int):
        return None
    if count == 1:
        return ".one"
    if code in _FEW_FORM_LOCALES and 2 <= count <= 4:
        return ".few"
    return None


def _lookup(locale: Locale, key: str, count: object) -> str | None:
    """`locale`'s string for `key`, then the default locale's. A caller
    passing `count=` gets `key.one`/`key.few` where the language file has
    one ("1 honeypot was skipped" / "3 honeypots were skipped"); a string
    with no such variant just uses `key` for every count."""
    candidates = [locale]
    if locale.code != DEFAULT_LOCALE_CODE:
        candidates.append(_registry()[DEFAULT_LOCALE_CODE])
    for candidate in candidates:
        suffix = _plural_suffix(candidate.code, count)
        if suffix is not None and key + suffix in candidate.strings:
            return candidate.strings[key + suffix]
        if key in candidate.strings:
            return candidate.strings[key]
    return None


def translate(locale: Locale, key: str, **kwargs: object) -> str:
    """`locale`'s own string for `key`, falling back to the default
    locale's, falling back to the literal key itself — see module
    docstring. `**kwargs` are `str.format`-substituted into the result
    (`translate(locale, "greeting", name=user.display_name)` against a
    string like `"Hello, {name}!"`); a template referencing a placeholder
    no caller supplied is returned unsubstituted rather than raising —
    a translation typo should never break a page render."""
    template = _lookup(locale, key, kwargs.get("count"))
    if template is None:
        return key
    if not kwargs:
        return template
    try:
        return template.format(**kwargs)
    except (KeyError, IndexError):
        return template
