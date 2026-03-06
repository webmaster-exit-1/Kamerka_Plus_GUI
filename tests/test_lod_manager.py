"""Tests for globe_3d/lod_manager.py"""

import pytest

from globe_3d.lod_manager import (
    CLUSTER_RADIUS_DEG,
    LOD_ZOOM_THRESHOLD,
    cluster_devices,
    dissolve_cluster,
    get_render_data,
)


class TestConstants:
    def test_cluster_radius_positive(self):
        assert CLUSTER_RADIUS_DEG > 0

    def test_lod_threshold_between_zero_and_one(self):
        assert 0.0 < LOD_ZOOM_THRESHOLD < 1.0


class TestClusterDevices:
    def test_empty_input(self):
        assert cluster_devices([]) == []

    def test_single_device_makes_one_cluster(self):
        devices = [{"lat": 10.0, "lon": 20.0, "severity": "low"}]
        clusters = cluster_devices(devices)
        assert len(clusters) == 1
        assert clusters[0]["count"] == 1

    def test_two_nearby_devices_merge_into_one_cluster(self):
        # Both fall in the 0–2° bucket: floor(0.5/2)*2 = 0, floor(1.0/2)*2 = 0
        devices = [
            {"lat": 0.5, "lon": 0.5, "severity": "low"},
            {"lat": 1.0, "lon": 1.0, "severity": "low"},
        ]
        clusters = cluster_devices(devices)
        assert len(clusters) == 1
        assert clusters[0]["count"] == 2

    def test_distant_devices_become_separate_clusters(self):
        # floor(0.5/2)*2=0 vs floor(5.0/2)*2=4 → different buckets
        devices = [
            {"lat": 0.5, "lon": 0.5, "severity": "low"},
            {"lat": 5.0, "lon": 5.0, "severity": "high"},
        ]
        clusters = cluster_devices(devices)
        assert len(clusters) == 2

    def test_cluster_centroid_is_average_of_members(self):
        devices = [
            {"lat": 0.0, "lon": 0.0, "severity": "low"},
            {"lat": 1.0, "lon": 1.0, "severity": "low"},
        ]
        clusters = cluster_devices(devices)
        assert len(clusters) == 1
        assert clusters[0]["lat"] == pytest.approx(0.5)
        assert clusters[0]["lon"] == pytest.approx(0.5)

    def test_dominant_severity_chosen(self):
        devices = [
            {"lat": 0.5, "lon": 0.5, "severity": "low"},
            {"lat": 1.0, "lon": 1.0, "severity": "critical"},
        ]
        clusters = cluster_devices(devices)
        assert len(clusters) == 1
        assert clusters[0]["severity"] == "critical"

    def test_device_missing_lat_is_skipped(self):
        devices = [
            {"lon": 0.0, "severity": "low"},          # no lat
            {"lat": 5.0, "lon": 5.0, "severity": "low"},
        ]
        clusters = cluster_devices(devices)
        assert len(clusters) == 1
        assert clusters[0]["count"] == 1

    def test_device_missing_lon_is_skipped(self):
        devices = [
            {"lat": 0.0, "severity": "low"},          # no lon
            {"lat": 5.0, "lon": 5.0, "severity": "low"},
        ]
        clusters = cluster_devices(devices)
        assert len(clusters) == 1

    def test_non_numeric_lat_lon_is_skipped(self):
        devices = [
            {"lat": "bad", "lon": "bad", "severity": "low"},
            {"lat": 5.0, "lon": 5.0, "severity": "low"},
        ]
        clusters = cluster_devices(devices)
        assert len(clusters) == 1

    def test_cluster_contains_devices_list(self):
        devices = [{"lat": 0.5, "lon": 0.5, "severity": "low"}]
        clusters = cluster_devices(devices)
        assert "devices" in clusters[0]
        assert len(clusters[0]["devices"]) == 1

    def test_custom_radius(self):
        # With a 10° radius both devices fall in the same bucket
        devices = [
            {"lat": 1.0, "lon": 1.0, "severity": "low"},
            {"lat": 5.0, "lon": 5.0, "severity": "low"},
        ]
        clusters = cluster_devices(devices, radius_deg=10.0)
        assert len(clusters) == 1
        assert clusters[0]["count"] == 2


class TestDissolveCluster:
    def test_empty_devices_returns_empty(self):
        assert dissolve_cluster({"devices": []}) == []

    def test_missing_devices_key_returns_empty(self):
        assert dissolve_cluster({}) == []

    def test_each_device_becomes_individual_point(self):
        cluster = {
            "devices": [
                {"lat": 10.0, "lon": 20.0, "severity": "high"},
                {"lat": 11.0, "lon": 21.0, "severity": "medium"},
            ]
        }
        points = dissolve_cluster(cluster)
        assert len(points) == 2
        assert all(p["count"] == 1 for p in points)

    def test_coordinates_preserved(self):
        cluster = {"devices": [{"lat": 37.5, "lon": -122.3, "severity": "low"}]}
        points = dissolve_cluster(cluster)
        assert points[0]["lat"] == pytest.approx(37.5)
        assert points[0]["lon"] == pytest.approx(-122.3)

    def test_severity_preserved(self):
        cluster = {"devices": [{"lat": 0.0, "lon": 0.0, "severity": "critical"}]}
        points = dissolve_cluster(cluster)
        assert points[0]["severity"] == "critical"

    def test_device_missing_lat_is_skipped(self):
        cluster = {
            "devices": [
                {"lon": 0.0, "severity": "low"},          # no lat
                {"lat": 5.0, "lon": 5.0, "severity": "low"},
            ]
        }
        points = dissolve_cluster(cluster)
        assert len(points) == 1

    def test_each_point_wraps_device_in_list(self):
        device = {"lat": 1.0, "lon": 2.0, "severity": "low"}
        cluster = {"devices": [device]}
        points = dissolve_cluster(cluster)
        assert points[0]["devices"] == [device]


class TestGetRenderData:
    def _devices(self):
        return [
            {"lat": 0.5, "lon": 0.5, "severity": "low"},   # bucket (0,0)
            {"lat": 1.0, "lon": 1.0, "severity": "medium"}, # bucket (0,0)
            {"lat": 5.0, "lon": 5.0, "severity": "high"},   # bucket (4,4)
        ]

    def test_global_view_returns_clusters(self):
        result = get_render_data(self._devices(), zoom_level=0.0)
        # Two buckets → two clusters
        assert len(result) == 2
        counts = sorted(r["count"] for r in result)
        assert counts == [1, 2]

    def test_zoomed_view_returns_individual_points(self):
        result = get_render_data(self._devices(), zoom_level=1.0)
        assert len(result) == 3
        assert all(r["count"] == 1 for r in result)

    def test_at_threshold_uses_individual_points(self):
        result = get_render_data(self._devices(), zoom_level=LOD_ZOOM_THRESHOLD)
        assert all(r["count"] == 1 for r in result)

    def test_just_below_threshold_uses_clusters(self):
        result = get_render_data(self._devices(), zoom_level=LOD_ZOOM_THRESHOLD - 0.01)
        assert len(result) == 2

    def test_empty_devices_returns_empty(self):
        assert get_render_data([], zoom_level=0.0) == []
        assert get_render_data([], zoom_level=1.0) == []
