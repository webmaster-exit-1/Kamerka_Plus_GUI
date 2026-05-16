from unittest.mock import patch
from datetime import timedelta

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from app_feeds.models import Brief, FeedEntry, FeedSource


class FeedViewsTests(TestCase):
    def setUp(self):
        self.source = FeedSource.objects.create(
            name="Test Source",
            url="https://example.com/rss",
            category="cyber",
            active=True,
        )
        FeedEntry.objects.create(
            source=self.source,
            title="US ICS incident",
            summary="Critical infrastructure incident affecting US operators.",
            url="https://example.com/us-1",
            published=timezone.now(),
            geo_countries="US",
            entry_id="entry-us-1",
        )
        FeedEntry.objects.create(
            source=self.source,
            title="DE cyber update",
            summary="Regional incident in Germany.",
            url="https://example.com/de-1",
            published=timezone.now() - timedelta(hours=1),
            geo_countries="DE",
            entry_id="entry-de-1",
        )

    def test_brief_generate_requires_staff(self):
        response = self.client.post(reverse("brief_generate", args=["PL"]))

        self.assertEqual(response.status_code, 403)

    def test_feed_entries_support_country_filter(self):
        response = self.client.get(
            reverse("feed_entries"),
            {"country": "US", "limit": "10"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["entries"][0]["geo_countries"], "US")

    def test_feed_entries_respects_limit(self):
        response = self.client.get(reverse("feed_entries"), {"limit": "1"})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["count"], 1)
        self.assertEqual(len(payload["entries"]), 1)

    def test_feed_sse_endpoint_returns_event_stream_headers(self):
        response = self.client.get(reverse("feed_sse"))

        self.assertEqual(response.status_code, 200)
        self.assertIn("text/event-stream", response["Content-Type"])
        self.assertEqual(response["Cache-Control"], "no-cache")

    @patch("app_feeds.tasks.generate_brief.delay")
    def test_brief_view_returns_pending_and_queues_generation(self, mock_delay):
        response = self.client.get(reverse("brief_view", args=["US"]))

        self.assertEqual(response.status_code, 202)
        payload = response.json()
        self.assertEqual(payload["method"], "pending")
        mock_delay.assert_called_once_with("US")

    def test_brief_view_returns_latest_existing_brief(self):
        Brief.objects.create(region="US", content="Ready brief", method="extractive")

        response = self.client.get(reverse("brief_view", args=["US"]))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["method"], "extractive")
        self.assertEqual(payload["content"], "Ready brief")

    @patch("app_kamerka.views.check_credits", return_value=[0])
    def test_index_includes_regions_from_feed_geo_countries(self, _mock_credits):
        FeedEntry.objects.create(
            source=self.source,
            title="FR and DE update",
            summary="Regional item",
            url="https://example.com/fr-de",
            published=timezone.now() - timedelta(hours=2),
            geo_countries="FR,DE",
            entry_id="entry-fr-de",
        )

        response = self.client.get(reverse("index"))

        self.assertEqual(response.status_code, 200)
        content = response.content.decode("utf-8")
        self.assertIn('<option value="FR">FR</option>', content)
        self.assertIn('<option value="DE">DE</option>', content)


class FeedTaskTests(TestCase):
    @override_settings(REDIS_URL="redis://test-fake-redis:6379/0")
    @patch("redis.from_url")
    def test_publish_redis_uses_settings_redis_url(self, from_url):
        from app_feeds.tasks import _publish_redis

        _publish_redis("feed_updated", {"id": 1})

        from_url.assert_called_once_with("redis://test-fake-redis:6379/0")
