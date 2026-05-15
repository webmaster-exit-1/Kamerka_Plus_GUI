from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import reverse


class FeedViewsTests(TestCase):
    def test_brief_generate_requires_staff(self):
        response = self.client.post(reverse("brief_generate", args=["PL"]))

        self.assertEqual(response.status_code, 403)


class FeedTaskTests(TestCase):
    @override_settings(REDIS_URL="redis://test-fake-redis:6379/0")
    @patch("redis.from_url")
    def test_publish_redis_uses_settings_redis_url(self, from_url):
        from app_feeds.tasks import _publish_redis

        _publish_redis("feed_updated", {"id": 1})

        from_url.assert_called_once_with("redis://test-fake-redis:6379/0")
