"""Pure display helpers for GeoIP data — turning a country code into a flag
emoji, and a lat/long into pixel coordinates on the Map page's hand-rolled
SVG world outline (`app/web/templates/map/index.html`, `app.web.routes.map`
— see that route for how points/table rows are actually built from
`HoneypotEvent`/`AuditLogEntry` rows).

Kept separate from `app.services.geoip` (which only ever deals with
*resolving* an IP, never how the result gets drawn) so a template/route
concern doesn't leak into the lookup/download service.
"""

from __future__ import annotations

import math
from pathlib import Path

# A real world coastline outline for the Map page, projected the same way
# `project()` below projects an event's own lat/lon — so the landmass
# lines up with the dots plotted on top of it. Traced once, offline, from
# Natural Earth's 1:110m "land" dataset (public domain, naturalearthdata.
# com — no attribution required) via a small one-off script: each ring's
# lon/lat pairs run through the exact same linear Plate Carrée formula as
# `project()`, simplified with a pixel-space Douglas-Peucker pass (this
# viewBox is only ever ~760x380, so the source data's full 110m-scale
# node density is far more than a rendered pixel can show) then baked
# into one flat SVG path string, checked in as a plain text file — not
# meant to ever be regenerated at request time, and not a matter of
# projecting live geometry via a runtime GIS dependency this app
# otherwise has no use for.
WORLD_LAND_PATH = (Path(__file__).parent / "_world_land_path.txt").read_text().strip()

# Plate Carrée (equirectangular) projection — the same one every
# `lat`/`lon` pair from GeoIP2's `location.latitude`/`longitude` is already
# in (WGS84 degrees), and simple enough to invert by eye when debugging a
# misplaced dot: longitude maps linearly to x, latitude linearly to y, no
# distortion correction. Deliberately not a fancier projection (Mercator,
# ...) — this map has no real coastline data to align against anyway (see
# the route's own module docstring for why), so a more "correct" projection
# would only make the graticule harder to reason about for no visual gain.


def project(lat: float, lon: float, width: float, height: float) -> tuple[float, float]:
    """`(x, y)` in a `width` x `height` viewBox for a WGS84 `(lat, lon)` —
    `lon=-180` is the left edge, `lon=180` the right edge, `lat=90`
    (North Pole) the top edge, `lat=-90` the bottom edge. Not clamped —
    a caller passing an out-of-range value gets an out-of-viewBox point,
    which SVG just clips rather than raising."""
    x = (lon + 180.0) / 360.0 * width
    y = (90.0 - lat) / 180.0 * height
    return x, y


def dot_radius(
    count: int, max_count: int, *, min_radius: float = 3.0, max_radius: float = 14.0
) -> float:
    """Log-scaled, not linear — a single-event location and a
    thousand-event one would otherwise be visually indistinguishable (both
    "the smallest dot") or the busiest location would dwarf the map (both
    real shapes this data takes: one attacker hitting once, and a
    brute-force botnet hitting the same honeypot thousands of times from
    one source)."""
    if max_count <= 1:
        return min_radius
    # log1p so count=1 still maps to a nonzero fraction (log(1)=0 would
    # otherwise put every single-hit location at the exact minimum radius,
    # same as count=0 - which never appears here, but keeps the formula
    # honest either way).
    fraction = math.log1p(count) / math.log1p(max_count)
    return min_radius + fraction * (max_radius - min_radius)


def country_flag(country_code: str | None) -> str:
    """A flag emoji from a 2-letter ISO 3166-1 alpha-2 code (e.g. "US" ->
    US flag) via the standard Regional Indicator Symbol trick — each
    letter maps to its own Unicode codepoint 'AA' apart from the plain
    letter, and two of them side by side render as that country's flag in
    any font with the relevant glyphs. Returns an empty string for
    anything that isn't exactly two ASCII letters (a missing/malformed
    code, or the handful of MaxMind "user-assigned"/special codes that
    aren't real ISO country codes) rather than a broken/placeholder
    glyph."""
    if not country_code or len(country_code) != 2 or not country_code.isalpha():
        return ""
    code = country_code.upper()
    return "".join(chr(0x1F1E6 + (ord(letter) - ord("A"))) for letter in code)
