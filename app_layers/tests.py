import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from app_layers.models import DataLayer, LayerFeature


class LayerViewsTests(TestCase):
    def setUp(self):
        self.staff_user = get_user_model().objects.create_user(
            username="staff",
            password="pw",
            is_staff=True,
        )

    def test_layer_features_hides_disabled_layers(self):
        DataLayer.objects.create(
            slug="hidden-layer",
            name="Hidden",
            enabled=False,
        )

        response = self.client.get(reverse("layer_features", args=["hidden-layer"]))

        self.assertEqual(response.status_code, 404)

    def test_layer_import_requires_staff(self):
        response = self.client.post(
            reverse("layer_import"),
            data=json.dumps({"slug": "custom"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)

    def test_layer_import_rejects_invalid_point_coordinates(self):
        self.client.force_login(self.staff_user)

        response = self.client.post(
            reverse("layer_import"),
            data=json.dumps({
                "slug": "custom",
                "features": {
                    "type": "FeatureCollection",
                    "features": [
                        {
                            "type": "Feature",
                            "geometry": {
                                "type": "Point",
                                "coordinates": ["bad", 10],
                            },
                            "properties": {"id": "feature-1"},
                        }
                    ],
                },
            }),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(DataLayer.objects.filter(slug="custom").exists())

    def test_layer_features_can_be_filtered_by_bbox(self):
        layer = DataLayer.objects.create(slug="bbox-layer", name="BBox Layer", enabled=True)
        LayerFeature.objects.create(
            layer=layer,
            geometry={"type": "Point", "coordinates": [10.0, 10.0]},
            properties={"id": "inside"},
        )
        LayerFeature.objects.create(
            layer=layer,
            geometry={"type": "Point", "coordinates": [50.0, 50.0]},
            properties={"id": "outside"},
        )

        response = self.client.get(
            reverse("layer_features", args=["bbox-layer"]),
            {"bbox": "0,0,20,20"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload["features"]), 1)
        self.assertEqual(payload["features"][0]["properties"]["id"], "inside")

    def test_layer_features_rejects_invalid_bbox(self):
        DataLayer.objects.create(slug="bbox-invalid", name="BBox Invalid", enabled=True)

        response = self.client.get(
            reverse("layer_features", args=["bbox-invalid"]),
            {"bbox": "0,0,0,20"},
        )

        self.assertEqual(response.status_code, 400)

    def test_layer_features_rejects_non_finite_bbox(self):
        DataLayer.objects.create(slug="bbox-non-finite", name="BBox Non-Finite", enabled=True)

        invalid_bbox_values = [
            "nan,0,20,20",
            "0,0,inf,20",
            "0,-inf,20,20",
        ]
        for bbox in invalid_bbox_values:
            with self.subTest(bbox=bbox):
                response = self.client.get(
                    reverse("layer_features", args=["bbox-non-finite"]),
                    {"bbox": bbox},
                )
                self.assertEqual(response.status_code, 400)

    def test_layer_list_supports_view_filter_and_shared_metadata(self):
        point_layer = DataLayer.objects.create(
            slug="point-layer",
            name="Point Layer",
            enabled=True,
            layer_type="point",
        )
        DataLayer.objects.create(
            slug="polygon-layer",
            name="Polygon Layer",
            enabled=True,
            layer_type="polygon",
        )
        DataLayer.objects.create(
            slug="map-only-layer",
            name="Map Only",
            enabled=True,
            layer_type="point",
            renderer_config={"views": ["map"]},
        )

        response = self.client.get(reverse("layer_list"), {"view": "globe"})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual([row["slug"] for row in payload], ["point-layer"])
        self.assertEqual(payload[0]["supported_views"], ["map", "globe"])
        self.assertIn("renderer_config", payload[0])
        self.assertEqual(
            payload[0]["endpoints"]["features"],
            "/api/layers/point-layer/features.json",
        )
        self.assertEqual(point_layer.slug, payload[0]["slug"])

    def test_layer_features_supports_limit(self):
        layer = DataLayer.objects.create(slug="limit-layer", name="Limit Layer", enabled=True)
        for idx in range(3):
            LayerFeature.objects.create(
                layer=layer,
                geometry={"type": "Point", "coordinates": [10.0 + idx, 10.0 + idx]},
                properties={"id": f"f-{idx}"},
            )

        response = self.client.get(
            reverse("layer_features", args=["limit-layer"]),
            {"limit": "2"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload["features"]), 2)
        self.assertEqual(payload["layer"]["layer_type"], "point")
        self.assertIn("renderer_config", payload["layer"])

    def test_layer_features_rejects_invalid_limit(self):
        DataLayer.objects.create(slug="limit-invalid", name="Limit Invalid", enabled=True)

        response = self.client.get(
            reverse("layer_features", args=["limit-invalid"]),
            {"limit": "not-a-number"},
        )
        self.assertEqual(response.status_code, 400)


class LayerTasksTests(TestCase):
    @patch("app_layers.tasks.refresh_layer.delay")
    def test_refresh_all_layers_queues_subtasks(self, mock_refresh_delay):
        DataLayer.objects.create(slug="alpha", name="Alpha", enabled=True)
        DataLayer.objects.create(slug="beta", name="Beta", enabled=True)

        from app_layers.tasks import refresh_all_layers

        result = refresh_all_layers()

        self.assertEqual(mock_refresh_delay.call_count, 2)
        self.assertEqual(result, "queued 2 layer refresh tasks")
