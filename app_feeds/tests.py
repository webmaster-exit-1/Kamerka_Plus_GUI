from datetime import datetime, timezone
import json
from unittest.mock import MagicMock, patch

import feedparser
from django.test import RequestFactory, SimpleTestCase, TestCase

from app_feeds.models import FeedEntry, FeedSource
from app_feeds.tasks import refresh_feeds
from app_feeds.video_search import match_videos
from app_feeds.views import feed_playlist


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


class VideoPlaylistTests(SimpleTestCase):
    def test_matches_headline_tokens_and_direct_youtube_urls(self):
        matched = match_videos(
            "Critical OpenSSL vulnerability disclosed",
            "https://example.com/story",
            fetcher=lambda _query: [
                {
                    "video_id": "abcdefghijk",
                    "title": "Cooking pasta tonight",
                    "channel": "Kitchen",
                    "thumbnail": "",
                    "url": "https://www.youtube.com/watch?v=abcdefghijk",
                    "embed_url": "https://www.youtube-nocookie.com/embed/abcdefghijk",
                },
                {
                    "video_id": "aaaabbbbccc",
                    "title": "Critical OpenSSL vulnerability explained",
                    "channel": "Sec",
                    "thumbnail": "https://i.ytimg.com/vi/aaaabbbbccc/hqdefault.jpg",
                    "url": "https://www.youtube.com/watch?v=aaaabbbbccc",
                    "embed_url": "https://www.youtube-nocookie.com/embed/aaaabbbbccc",
                },
            ],
        )
        self.assertEqual([item["video_id"] for item in matched], ["aaaabbbbccc"])

        direct = match_videos(
            "Weekly briefing",
            "https://youtu.be/dQw4w9wgVcQ",
            fetcher=lambda _query: [],
        )
        self.assertEqual(direct[0]["video_id"], "dQw4w9wgVcQ")
        self.assertTrue(direct[0]["embed_url"].startswith("https://www.youtube-nocookie.com/embed/"))

    def test_playlist_endpoint_uses_matcher(self):
        entry = MagicMock()
        entry.pk = 7
        entry.title = "Pipeline rupture shuts northern terminal"
        entry.summary = "Operators halted flow after the rupture."
        entry.url = "https://example.com/rupture"
        entry.published = None
        entry.source.name = "Wire"
        entry.source.category = "cyber"
        sliced = MagicMock()
        sliced.__iter__.return_value = iter([entry])
        with (
            patch("app_feeds.views.FeedEntry.objects") as manager,
            patch("app_feeds.views.match_videos", return_value=[{
                "video_id": "qwertyuiopa",
                "title": "Pipeline rupture shuts northern terminal",
                "channel": "Desk",
                "thumbnail": "",
                "url": "https://www.youtube.com/watch?v=qwertyuiopa",
                "embed_url": "https://www.youtube-nocookie.com/embed/qwertyuiopa",
            }]),
        ):
            manager.select_related.return_value.order_by.return_value.__getitem__.return_value = [entry]
            response = feed_playlist(RequestFactory().get("/api/feeds/playlist/?limit=4"))
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["items"][0]["videos"][0]["video_id"], "qwertyuiopa")
        self.assertNotIn("<", payload["items"][0]["title"])
