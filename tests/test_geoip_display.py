"""`app.services.geoip_display` — pure display helpers for the Map page and
the audit log (projection, dot sizing, flag emoji), no database/network
involved."""

from __future__ import annotations

from app.services.geoip_display import country_flag, dot_radius, project


def test_project_places_null_island_at_the_center():
    x, y = project(0.0, 0.0, 760, 380)
    assert x == 380
    assert y == 190


def test_project_left_edge_is_lon_minus_180():
    x, _y = project(0.0, -180.0, 760, 380)
    assert x == 0


def test_project_right_edge_is_lon_180():
    x, _y = project(0.0, 180.0, 760, 380)
    assert x == 760


def test_project_top_edge_is_north_pole():
    _x, y = project(90.0, 0.0, 760, 380)
    assert y == 0


def test_project_bottom_edge_is_south_pole():
    _x, y = project(-90.0, 0.0, 760, 380)
    assert y == 380


def test_dot_radius_is_monotonically_increasing_with_count():
    small = dot_radius(1, max_count=1000)
    medium = dot_radius(50, max_count=1000)
    large = dot_radius(1000, max_count=1000)
    assert small < medium < large


def test_dot_radius_stays_within_configured_bounds():
    assert dot_radius(1, max_count=1000, min_radius=3.0, max_radius=14.0) >= 3.0
    assert dot_radius(1000, max_count=1000, min_radius=3.0, max_radius=14.0) <= 14.0


def test_dot_radius_handles_a_single_location_with_no_variation():
    """max_count <= 1 (every location tied, or only one location at all) -
    no meaningful scale to log against, so every dot is just the minimum
    radius rather than dividing by log1p(1) == 0."""
    assert dot_radius(1, max_count=1) == 1.5
    assert dot_radius(1, max_count=0) == 1.5


def test_country_flag_builds_regional_indicator_pairs():
    assert country_flag("US") == "\U0001f1fa\U0001f1f8"
    assert country_flag("cz") == "\U0001f1e8\U0001f1ff"  # lowercase input works too


def test_country_flag_returns_empty_string_for_anything_not_two_letters():
    assert country_flag(None) == ""
    assert country_flag("") == ""
    assert country_flag("USA") == ""
    assert country_flag("1x") == ""
