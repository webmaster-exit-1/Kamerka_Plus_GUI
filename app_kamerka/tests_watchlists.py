from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from app_kamerka.test_compat import apply_py314_django_test_patches

apply_py314_django_test_patches()

from app_kamerka.models import Device, Search, Watchlist
from kamerka.tasks import _upsert_device, run_watchlist_refresh, schedule_enabled_watchlists


class WatchlistTaskTests(TestCase):
    @patch("kamerka.tasks.shodan_search.delay")
    def test_run_watchlist_refresh_enqueues_search_and_updates_schedule(self, delay_mock):
        delay_mock.return_value = MagicMock(id="task-1")
        watchlist = Watchlist.objects.create(
            name="us-ics",
            query_type=Watchlist.QUERY_COUNTRY,
            country="US",
            query_items=["niagara", "modbus"],
            enabled=True,
            refresh_interval_minutes=15,
        )

        result = run_watchlist_refresh(watchlist.id)

        self.assertEqual(result["status"], "queued")
        self.assertEqual(Search.objects.count(), 1)
        delay_mock.assert_called_once()
        watchlist.refresh_from_db()
        self.assertIsNotNone(watchlist.last_run_at)
        self.assertIsNotNone(watchlist.next_run_at)
        self.assertGreater(watchlist.next_run_at, watchlist.last_run_at)

    @patch("kamerka.tasks.run_watchlist_refresh.delay")
    def test_schedule_enabled_watchlists_queues_only_due_watchlists(self, delay_mock):
        now = timezone.now()
        due = Watchlist.objects.create(
            name="due",
            country="US",
            query_items=["niagara"],
            enabled=True,
            next_run_at=now - timedelta(minutes=1),
        )
        Watchlist.objects.create(
            name="future",
            country="US",
            query_items=["modbus"],
            enabled=True,
            next_run_at=now + timedelta(minutes=30),
        )
        Watchlist.objects.create(
            name="disabled",
            country="US",
            query_items=["bacnet"],
            enabled=False,
            next_run_at=now - timedelta(minutes=1),
        )

        result = schedule_enabled_watchlists()

        self.assertEqual(result["queued"], 1)
        delay_mock.assert_called_once_with(due.id, False)


class DeviceDedupeTests(TestCase):
    def test_upsert_device_deduplicates_existing_record(self):
        old_search = Search.objects.create(
            country="US", ics="[]", coordinates="", coordinates_search=""
        )
        new_search = Search.objects.create(
            country="US", ics="[]", coordinates="", coordinates_search=""
        )
        existing = Device.objects.create(
            search=old_search,
            ip="1.2.3.4",
            port="80",
            product="old",
            org="old-org",
            data="old",
            type="old",
            city="old-city",
            country_code="US",
            query="old",
            category="ics",
            vulns="",
            indicator="",
            hostnames="",
            screenshot="",
        )

        updated = _upsert_device(
            new_search,
            {
                "ip": "1.2.3.4",
                "port": "80",
                "product": "new",
                "org": "new-org",
                "data": "new-data",
                "type": "new-type",
                "city": "new-city",
                "country_code": "US",
                "query": "new-query",
                "category": "ics",
                "vulns": "[]",
                "indicator": "[]",
                "hostnames": "test-host",
                "screenshot": "",
                "isp": "isp",
                "cpe": "cpe:/a:test",
            },
        )

        self.assertEqual(Device.objects.count(), 1)
        self.assertEqual(updated.id, existing.id)
        self.assertEqual(updated.search_id, new_search.id)
        self.assertEqual(updated.product, "new")
