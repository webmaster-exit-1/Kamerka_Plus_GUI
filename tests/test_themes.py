"""Tests for globe_3d/themes.py"""

import pytest

from globe_3d.themes import (
    DEFAULT_THEME,
    THEMES,
    GlobeTheme,
    CYBERPUNK,
    MATRIX,
    THERMAL,
    SATELLITE,
    GHOST,
)
from globe_3d.spike_renderer import SEVERITY_COLOURS


class TestThemesDict:
    def test_contains_all_five_themes(self):
        assert set(THEMES.keys()) == {"cyberpunk", "matrix", "thermal", "satellite", "ghost"}

    def test_default_theme_is_in_themes(self):
        assert DEFAULT_THEME in THEMES

    def test_default_theme_is_cyberpunk(self):
        assert DEFAULT_THEME == "cyberpunk"

    def test_keys_match_theme_names(self):
        for key, theme in THEMES.items():
            assert theme.name == key


class TestGlobeThemeDataclass:
    def test_label_falls_back_to_capitalised_name(self):
        t = GlobeTheme(
            name="testtheme",
            label="",
            background="black",
            earth_colour="#000000",
            use_texture=False,
            earth_opacity=1.0,
            grid_colour="white",
            grid_opacity=0.5,
            grid_line_width=1.0,
            severity_colours={},
        )
        assert t.label == "Testtheme"

    def test_explicit_label_is_kept(self):
        t = GlobeTheme(
            name="testtheme",
            label="My Label",
            background="black",
            earth_colour="#000000",
            use_texture=False,
            earth_opacity=1.0,
            grid_colour="white",
            grid_opacity=0.5,
            grid_line_width=1.0,
            severity_colours={},
        )
        assert t.label == "My Label"

    def test_ambient_defaults_to_0_3(self):
        t = GlobeTheme(
            name="x", label="x", background="black", earth_colour="#000",
            use_texture=False, earth_opacity=1.0, grid_colour="white",
            grid_opacity=0.5, grid_line_width=1.0, severity_colours={},
        )
        assert t.ambient == pytest.approx(0.3)


class TestSpikeColour:
    def test_returns_three_float_tuple(self):
        colour = CYBERPUNK.spike_colour("critical")
        assert len(colour) == 3
        assert all(isinstance(c, float) for c in colour)

    def test_empty_severity_colours_falls_back_to_defaults(self):
        # CYBERPUNK and SATELLITE have empty severity_colours — use SEVERITY_COLOURS defaults
        assert CYBERPUNK.spike_colour("critical") == SEVERITY_COLOURS["critical"]
        assert CYBERPUNK.spike_colour("medium") == SEVERITY_COLOURS["medium"]

    def test_theme_override_takes_priority(self):
        # MATRIX overrides critical → green, not the default red
        matrix_critical = MATRIX.spike_colour("critical")
        default_critical = SEVERITY_COLOURS["critical"]
        assert matrix_critical != default_critical
        # Matrix critical is green-ish
        r, g, b = matrix_critical
        assert g > r  # green channel dominates

    def test_ghost_critical_is_white(self):
        r, g, b = GHOST.spike_colour("critical")
        assert r == pytest.approx(1.0)
        assert g == pytest.approx(1.0)
        assert b == pytest.approx(1.0)

    def test_unknown_severity_key_falls_back_to_unknown_colour(self):
        colour = CYBERPUNK.spike_colour("nonexistent")
        assert colour == SEVERITY_COLOURS["unknown"]

    def test_whitespace_and_case_handled(self):
        assert CYBERPUNK.spike_colour("  CRITICAL  ") == CYBERPUNK.spike_colour("critical")


class TestBuiltinThemeAttributes:
    @pytest.mark.parametrize("theme", [CYBERPUNK, MATRIX, THERMAL, SATELLITE, GHOST])
    def test_opacity_in_range(self, theme):
        assert 0.0 < theme.earth_opacity <= 1.0
        assert 0.0 <= theme.grid_opacity <= 1.0

    @pytest.mark.parametrize("theme", [CYBERPUNK, MATRIX, THERMAL, SATELLITE, GHOST])
    def test_ambient_in_range(self, theme):
        assert 0.0 <= theme.ambient <= 1.0

    @pytest.mark.parametrize("theme", [CYBERPUNK, MATRIX, THERMAL, SATELLITE, GHOST])
    def test_grid_line_width_positive(self, theme):
        assert theme.grid_line_width > 0

    def test_ghost_earth_is_translucent(self):
        assert GHOST.earth_opacity < 0.5

    def test_satellite_uses_texture(self):
        assert SATELLITE.use_texture is True

    def test_matrix_does_not_use_texture(self):
        assert MATRIX.use_texture is False
