from datetime import datetime, timezone
from unittest.mock import patch

import feedparser
from django.test import TestCase

from app_feeds.models import FeedEntry, FeedSource
from app_feeds.tasks import refresh_feeds


class FeedPublicationTests(TestCase):
    def test_refresh_preserves_utc_publication_date(self):
        FeedSource.objects.create(name="Test feed", url="https://example.com/feed")
        feed = feedparser.parse(
            "<rss version='2.0'><channel><title>Test</title><item>"
            "<guid>test-entry</guid><title>Test article</title>"
            "<pubDate>Mon, 19 Oct 2026 10:00:00 GMT</pubDate>"
            "</item></channel></rss>"
        )
        with (
            patch("feedparser.parse", return_value=feed),
            patch("app_feeds.tasks._translate_to_english", side_effect=lambda text, *a, **kw: text),
            patch("app_feeds.tasks._publish_redis"),
            patch("app_feeds.tasks._prune_old_entries"),
        ):
            refresh_feeds.run()

        self.assertEqual(
            FeedEntry.objects.get(entry_id="test-entry").published,
            datetime(2026, 10, 19, 10, 0, tzinfo=timezone.utc),
        )
