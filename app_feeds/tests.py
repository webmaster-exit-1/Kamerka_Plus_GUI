from pathlib import Path
from unittest.mock import patch
from datetime import timedelta

from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from app_feeds.models import Brief, FeedEntry, FeedSource
from app_feeds.opml import parse_opml, folder_to_category
from app_feeds.tasks import generate_brief
from app_feeds.text_utils import html_to_plain

BUNDLED_OPML = Path(__file__).resolve().parent / "data" / "feeder-export.opml"


class FeedViewsTests(TestCase):
    def setUp(self):
        cache.clear()
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

    @patch("app_feeds.tasks.generate_brief.delay")
    def test_brief_view_does_not_requeue_while_pending(self, mock_delay):
        from app_feeds.tasks import mark_brief_pending

        mark_brief_pending("US")
        response = self.client.get(reverse("brief_view", args=["US"]))

        self.assertEqual(response.status_code, 202)
        mock_delay.assert_not_called()

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


class HtmlToPlainTests(TestCase):
    def test_strips_tags_and_block_elements(self):
        raw = "<div><h3>Alert</h3><p>ICS incident in <b>China</b>.</p></div>"
        plain = html_to_plain(raw)
        self.assertNotIn("<", plain)
        self.assertIn("Alert", plain)
        self.assertIn("ICS incident", plain)
        self.assertIn("China", plain)

    def test_brief_view_returns_plain_text(self):
        Brief.objects.create(
            region="US",
            content="<h3>Test</h3><p>Plain body</p>",
            method="extractive",
        )
        response = self.client.get(reverse("brief_view", args=["US"]))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("<h3>", response.json()["content"])
        self.assertIn("Plain body", response.json()["content"])


class OpmlParserTests(TestCase):
    def test_parse_bundled_opml_has_97_feeds(self):
        feeds = parse_opml(BUNDLED_OPML)
        self.assertEqual(len(feeds), 97)

    def test_cve_exploits_folder_maps_to_cyber(self):
        self.assertEqual(folder_to_category("CVE & Exploits"), "cyber")

    def test_exploit_db_present(self):
        feeds = parse_opml(BUNDLED_OPML)
        urls = {f["url"] for f in feeds}
        self.assertIn("https://www.exploit-db.com/rss.xml", urls)

    def test_import_feeds_opml_command(self):
        call_command("import_feeds_opml", verbosity=0)
        self.assertEqual(FeedSource.objects.filter(active=True).count(), 97)
        edb = FeedSource.objects.get(url="https://www.exploit-db.com/rss.xml")
        self.assertEqual(edb.folder, "CVE & Exploits")
        self.assertEqual(edb.category, "cyber")


class GenerateBriefTaskTests(TestCase):
    def setUp(self):
        cache.clear()
        self.source = FeedSource.objects.create(
            name="Brief Test Source",
            url="https://example.com/rss-brief",
            category="cyber",
            active=True,
        )

    def test_generate_brief_creates_empty_brief_when_no_entries(self):
        result = generate_brief("ZZ")

        self.assertIn("empty brief", result)
        brief = Brief.objects.get(region="ZZ")
        self.assertEqual(brief.method, "empty")
        self.assertIn("ZZ", brief.content)

    def test_generate_brief_uses_geo_tagged_entries(self):
        FeedEntry.objects.create(
            source=self.source,
            title="China ICS alert",
            summary="Incident affecting operators in China.",
            url="https://example.com/cn-1",
            published=timezone.now(),
            geo_countries="CN",
            entry_id="entry-cn-brief",
        )

        result = generate_brief("CN")

        self.assertIn("brief created", result)
        brief = Brief.objects.filter(region="CN").order_by("-generated_at").first()
        self.assertIsNotNone(brief)
        self.assertIn("China", brief.content)


class FeedTaskTests(TestCase):
    @override_settings(REDIS_URL="redis://test-fake-redis:6379/0")
    @patch("redis.from_url")
    def test_publish_redis_uses_settings_redis_url(self, from_url):
        from app_feeds.tasks import _publish_redis

        _publish_redis("feed_updated", {"id": 1})

        from_url.assert_called_once_with("redis://test-fake-redis:6379/0")
