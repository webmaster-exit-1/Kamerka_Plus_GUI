"""Tests for globe_3d/spike_renderer.py"""

import pytest

from globe_3d.spike_renderer import (
    MIN_SPIKE_HEIGHT,
    MAX_SPIKE_HEIGHT,
    SEVERITY_COLOURS,
    SPIKE_RADIUS,
    _normalise_severity,
    build_spike_data,
    dominant_severity,
    scale_spike_height,
    severity_to_colour,
)


class TestConstants:
    def test_min_less_than_max(self):
        assert MIN_SPIKE_HEIGHT < MAX_SPIKE_HEIGHT

    def test_min_positive(self):
        assert MIN_SPIKE_HEIGHT > 0

    def test_max_reasonable(self):
        # Max spike should not dwarf the globe (radius=1)
        assert MAX_SPIKE_HEIGHT < 1.0

    def test_spike_radius_positive(self):
        assert SPIKE_RADIUS > 0

    def test_severity_colours_has_expected_keys(self):
        for key in ("critical", "high", "medium", "low", "info", "unknown"):
            assert key in SEVERITY_COLOURS

    def test_severity_colours_are_rgb_tuples(self):
        for key, colour in SEVERITY_COLOURS.items():
            assert len(colour) == 3
            for channel in colour:
                assert 0.0 <= channel <= 1.0, f"{key}: channel {channel} out of range"


class TestNormaliseSeverity:
    def test_lowercase_passthrough(self):
        assert _normalise_severity("critical") == "critical"

    def test_uppercase(self):
        assert _normalise_severity("CRITICAL") == "critical"

    def test_mixed_case(self):
        assert _normalise_severity("Critical") == "critical"

    def test_whitespace_stripped(self):
        assert _normalise_severity("  HIGH  ") == "high"

    def test_empty_string_returns_unknown(self):
        assert _normalise_severity("") == "unknown"

    def test_none_returns_unknown(self):
        assert _normalise_severity(None) == "unknown"

    def test_all_known_severities(self):
        for sev in ("critical", "high", "medium", "low", "info", "unknown"):
            assert _normalise_severity(sev.upper()) == sev


class TestSeverityToColour:
    def test_critical_is_red(self):
        assert severity_to_colour("critical") == (1.0, 0.0, 0.0)

    def test_case_insensitive(self):
        assert severity_to_colour("MEDIUM") == severity_to_colour("medium")

    def test_medium_is_yellow(self):
        r, g, b = severity_to_colour("medium")
        assert r == pytest.approx(1.0)
        assert g == pytest.approx(1.0)
        assert b == pytest.approx(0.0)

    def test_unknown_severity_falls_back_to_grey(self):
        assert severity_to_colour("bogus") == SEVERITY_COLOURS["unknown"]

    def test_returns_three_tuple(self):
        colour = severity_to_colour("low")
        assert len(colour) == 3


class TestScaleSpikeHeight:
    def test_zero_devices_returns_minimum(self):
        assert scale_spike_height(0, 10) == MIN_SPIKE_HEIGHT

    def test_zero_max_count_returns_minimum(self):
        assert scale_spike_height(5, 0) == MIN_SPIKE_HEIGHT

    def test_negative_device_count_returns_minimum(self):
        assert scale_spike_height(-1, 10) == MIN_SPIKE_HEIGHT

    def test_full_count_returns_maximum(self):
        assert scale_spike_height(10, 10) == MAX_SPIKE_HEIGHT

    def test_half_count_is_midpoint(self):
        result = scale_spike_height(5, 10)
        expected = MIN_SPIKE_HEIGHT + 0.5 * (MAX_SPIKE_HEIGHT - MIN_SPIKE_HEIGHT)
        assert result == pytest.approx(expected)

    def test_over_max_clamped_to_maximum(self):
        assert scale_spike_height(20, 10) == MAX_SPIKE_HEIGHT

    def test_result_always_in_bounds(self):
        for count in range(0, 20):
            h = scale_spike_height(count, 10)
            assert MIN_SPIKE_HEIGHT <= h <= MAX_SPIKE_HEIGHT


class TestDominantSeverity:
    def test_empty_returns_unknown(self):
        assert dominant_severity([]) == "unknown"

    def test_single_value_returned(self):
        assert dominant_severity(["low"]) == "low"

    def test_critical_wins_over_all(self):
        assert dominant_severity(["info", "low", "medium", "high", "critical"]) == "critical"

    def test_high_beats_medium(self):
        assert dominant_severity(["medium", "high"]) == "high"

    def test_info_beats_unknown(self):
        assert dominant_severity(["unknown", "info"]) == "info"

    def test_case_insensitive(self):
        assert dominant_severity(["LOW", "CRITICAL"]) == "critical"

    def test_all_unknown_returns_unknown(self):
        assert dominant_severity(["unknown", "unknown"]) == "unknown"

    def test_unrecognised_normalises_to_unknown(self):
        # "bogus" normalises to "unknown"; "low" should still win
        assert dominant_severity(["bogus", "low"]) == "low"


class TestBuildSpikeData:
    def test_empty_input_returns_empty(self):
        assert build_spike_data([]) == []

    def test_single_cluster_structure(self):
        clusters = [{"lat": 10.0, "lon": 20.0, "count": 1, "severity": "low"}]
        spikes = build_spike_data(clusters)
        assert len(spikes) == 1
        s = spikes[0]
        assert s["lat"] == 10.0
        assert s["lon"] == 20.0
        assert s["count"] == 1
        assert s["severity"] == "low"
        assert "height" in s
        assert "colour" in s
        assert "devices" in s

    def test_single_cluster_at_max_gets_max_height(self):
        clusters = [{"lat": 0.0, "lon": 0.0, "count": 1, "severity": "low"}]
        spikes = build_spike_data(clusters)
        # Only cluster → count == max_count → MAX_SPIKE_HEIGHT
        assert spikes[0]["height"] == MAX_SPIKE_HEIGHT

    def test_two_clusters_height_scaling(self):
        clusters = [
            {"lat": 0.0, "lon": 0.0, "count": 2, "severity": "low"},
            {"lat": 10.0, "lon": 10.0, "count": 4, "severity": "high"},
        ]
        spikes = build_spike_data(clusters)
        assert len(spikes) == 2
        # max_count = 4; first spike ratio = 2/4 = 0.5
        expected_h = MIN_SPIKE_HEIGHT + 0.5 * (MAX_SPIKE_HEIGHT - MIN_SPIKE_HEIGHT)
        # find the spike with count=2
        spike_small = next(s for s in spikes if s["count"] == 2)
        spike_large = next(s for s in spikes if s["count"] == 4)
        assert spike_small["height"] == pytest.approx(expected_h)
        assert spike_large["height"] == MAX_SPIKE_HEIGHT

    def test_devices_list_forwarded(self):
        device = {"ip": "1.2.3.4", "lat": 0.0, "lon": 0.0}
        clusters = [{"lat": 0.0, "lon": 0.0, "count": 1, "severity": "low", "devices": [device]}]
        spikes = build_spike_data(clusters)
        assert spikes[0]["devices"] == [device]

    def test_missing_devices_key_defaults_to_empty(self):
        clusters = [{"lat": 0.0, "lon": 0.0, "count": 1, "severity": "low"}]
        spikes = build_spike_data(clusters)
        assert spikes[0]["devices"] == []

    def test_colour_matches_severity(self):
        clusters = [{"lat": 0.0, "lon": 0.0, "count": 1, "severity": "critical"}]
        spikes = build_spike_data(clusters)
        assert spikes[0]["colour"] == SEVERITY_COLOURS["critical"]
