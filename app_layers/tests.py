import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from app_layers.models import DataLayer


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


class LayerTasksTests(TestCase):
    @patch("app_layers.tasks.refresh_layer.delay")
    def test_refresh_all_layers_queues_subtasks(self, refresh_delay):
        DataLayer.objects.create(slug="alpha", name="Alpha", enabled=True)
        DataLayer.objects.create(slug="beta", name="Beta", enabled=True)

        from app_layers.tasks import refresh_all_layers

        result = refresh_all_layers()

        self.assertEqual(refresh_delay.call_count, 2)
        self.assertEqual(result, "queued 2 layer refresh tasks")
