"""Tests for globe_3d/coordinate_mapper.py"""

import math
import pytest

from globe_3d.coordinate_mapper import (
    EARTH_RADIUS,
    SPIKE_OFFSET,
    latlon_to_xyz,
    spike_base_xyz,
    xyz_to_latlon,
)


class TestConstants:
    def test_earth_radius_is_one(self):
        assert EARTH_RADIUS == 1.0

    def test_spike_offset_is_positive_and_small(self):
        assert 0 < SPIKE_OFFSET < 0.1


class TestLatLonToXyz:
    def test_origin_equator_prime_meridian(self):
        x, y, z = latlon_to_xyz(0, 0)
        assert x == pytest.approx(1.0)
        assert y == pytest.approx(0.0, abs=1e-15)
        assert z == pytest.approx(0.0, abs=1e-15)

    def test_north_pole(self):
        x, y, z = latlon_to_xyz(90, 0)
        assert x == pytest.approx(0.0, abs=1e-15)
        assert y == pytest.approx(0.0, abs=1e-15)
        assert z == pytest.approx(1.0)

    def test_south_pole(self):
        x, y, z = latlon_to_xyz(-90, 0)
        assert x == pytest.approx(0.0, abs=1e-15)
        assert y == pytest.approx(0.0, abs=1e-15)
        assert z == pytest.approx(-1.0)

    def test_equator_90_east(self):
        x, y, z = latlon_to_xyz(0, 90)
        assert x == pytest.approx(0.0, abs=1e-15)
        assert y == pytest.approx(1.0)
        assert z == pytest.approx(0.0, abs=1e-15)

    def test_equator_180(self):
        x, y, z = latlon_to_xyz(0, 180)
        assert x == pytest.approx(-1.0)
        assert y == pytest.approx(0.0, abs=1e-15)
        assert z == pytest.approx(0.0, abs=1e-15)

    def test_custom_radius(self):
        x, y, z = latlon_to_xyz(0, 0, radius=2.0)
        assert x == pytest.approx(2.0)
        assert y == pytest.approx(0.0, abs=1e-15)
        assert z == pytest.approx(0.0, abs=1e-15)

    def test_result_on_unit_sphere(self):
        """Every output point should lie on the unit sphere."""
        for lat, lon in [(45, 90), (-30, 120), (60, -75), (0, 0), (90, 0)]:
            x, y, z = latlon_to_xyz(lat, lon)
            assert math.sqrt(x * x + y * y + z * z) == pytest.approx(1.0)

    def test_returns_three_floats(self):
        result = latlon_to_xyz(51.5, -0.12)
        assert len(result) == 3
        assert all(isinstance(v, float) for v in result)


class TestXyzToLatLon:
    def test_prime_meridian_equator(self):
        lat, lon = xyz_to_latlon(1, 0, 0)
        assert lat == pytest.approx(0.0)
        assert lon == pytest.approx(0.0)

    def test_north_pole(self):
        lat, lon = xyz_to_latlon(0, 0, 1)
        assert lat == pytest.approx(90.0)

    def test_south_pole(self):
        lat, lon = xyz_to_latlon(0, 0, -1)
        assert lat == pytest.approx(-90.0)

    def test_zero_vector_returns_zeros(self):
        lat, lon = xyz_to_latlon(0, 0, 0)
        assert lat == 0.0
        assert lon == 0.0

    def test_custom_radius_ignored_for_direction(self):
        """Direction is preserved regardless of vector magnitude."""
        lat1, lon1 = xyz_to_latlon(1, 0, 0)
        lat2, lon2 = xyz_to_latlon(5, 0, 0)
        assert lat1 == pytest.approx(lat2)
        assert lon1 == pytest.approx(lon2)


class TestRoundTrip:
    @pytest.mark.parametrize("lat,lon", [
        (0.0, 0.0),
        (37.5, -122.3),
        (-33.9, 151.2),
        (51.5, -0.12),
        (35.7, 139.7),
        (0.0, 90.0),
        (89.9, 0.0),
        (-89.9, 0.0),
    ])
    def test_round_trip(self, lat, lon):
        x, y, z = latlon_to_xyz(lat, lon)
        lat_out, lon_out = xyz_to_latlon(x, y, z)
        assert lat_out == pytest.approx(lat, abs=1e-10)
        assert lon_out == pytest.approx(lon, abs=1e-10)


class TestSpikeBaseXyz:
    def test_equator_prime_meridian(self):
        x, y, z = spike_base_xyz(0, 0)
        assert x == pytest.approx(EARTH_RADIUS + SPIKE_OFFSET)
        assert y == pytest.approx(0.0, abs=1e-15)
        assert z == pytest.approx(0.0, abs=1e-15)

    def test_spike_is_further_than_surface(self):
        """spike_base must sit outside the Earth sphere."""
        for lat, lon in [(0, 0), (45, 90), (-30, 120)]:
            bx, by, bz = spike_base_xyz(lat, lon)
            dist = math.sqrt(bx * bx + by * by + bz * bz)
            assert dist == pytest.approx(EARTH_RADIUS + SPIKE_OFFSET)

    def test_custom_radius(self):
        x, y, z = spike_base_xyz(0, 0, radius=2.0)
        assert x == pytest.approx(2.0 + SPIKE_OFFSET)
