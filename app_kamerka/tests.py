import base64
from unittest.mock import Mock, mock_open, patch

from django.test import SimpleTestCase

from kamerka import tasks


class ShodanSearchSafetyTests(SimpleTestCase):
    def banner(self, **overrides):
        banner = {
            "ip_str": "192.0.2.1",
            "port": 80,
            "org": "Example",
            "data": "Synthetic banner",
            "location": {"city": None, "country_code": "US"},
            "tags": [],
        }
        banner.update(overrides)
        return banner

    def run_worker(self, banners=None, **kwargs):
        api = Mock()
        api.search.return_value = {"matches": banners or [], "total": len(banners or [])}
        api.search_cursor.return_value = iter(banners or [])
        output = Mock()
        with (
            patch.object(tasks, "_get_env_key", return_value="offline-placeholder"),
            patch.object(tasks.Search.objects, "get"),
            patch.object(tasks, "Shodan", return_value=api),
            patch.object(tasks, "_shodan_download_path", return_value="/tmp/offline.json.gz"),
            patch.object(tasks.shodan_helpers, "open_file", return_value=output),
            patch.object(tasks.shodan_helpers, "write_banner") as write_banner,
            patch.object(tasks, "_upsert_device") as upsert,
            patch("builtins.open", mock_open()),
        ):
            tasks.shodan_search_worker(1, "test", "test", "ics", country="US", **kwargs)
        return api, output, write_banner, upsert

    def test_default_limits_requests_even_with_short_page(self):
        api = Mock()
        api.search.return_value = {"matches": [self.banner()], "total": 1000}
        self.assertEqual(list(tasks._bounded_shodan_banners(api, "test", 1)), [self.banner()])
        api.search.assert_called_once_with("test", page=1, minify=False)

    def test_two_pages_and_total_exhaustion(self):
        for total, expected in ((1000, 2), (100, 1)):
            with self.subTest(total=total):
                api = Mock()
                api.search.return_value = {"matches": [self.banner()], "total": total}
                list(tasks._bounded_shodan_banners(api, "test", "2"))
                self.assertEqual(api.search.call_count, expected)

    def test_invalid_limits_fall_back_to_one_page(self):
        for limit in (None, "", "invalid", 0, -1, float("inf")):
            with self.subTest(limit=limit):
                api = Mock()
                api.search.return_value = {"matches": [self.banner()], "total": 1000}
                list(tasks._bounded_shodan_banners(api, "test", limit))
                self.assertEqual(api.search.call_count, 1)

    def test_empty_page_stops(self):
        api = Mock()
        api.search.return_value = {"matches": [], "total": 1000}
        self.assertEqual(list(tasks._bounded_shodan_banners(api, "test", 5)), [])
        self.assertEqual(api.search.call_count, 1)

    def test_worker_default_and_explicit_all_results(self):
        api, _, _, _ = self.run_worker([self.banner()])
        api.search.assert_called_once_with("country:US test", page=1, minify=False)
        api.search_cursor.assert_not_called()
        api, _, _, _ = self.run_worker([self.banner()], all_results=True, max_pages=None)
        api.search.assert_not_called()
        api.search_cursor.assert_called_once_with("country:US test", minify=False)

    def test_honeypots_and_duplicates_retained_only_in_raw_download(self):
        banner = self.banner()
        banners = [
            self.banner(tags=["honeypot"]),
            banner,
            dict(reversed(list(banner.items()))),
            self.banner(port=443),
            self.banner(ip_str="192.0.2.2"),
            self.banner(data="Changed banner"),
        ]
        _, output, write_banner, upsert = self.run_worker(banners)
        self.assertEqual(write_banner.call_count, len(banners))
        self.assertEqual(upsert.call_count, 4)
        output.close.assert_called_once()

    def test_screenshot_does_not_leak_and_missing_location_is_accepted(self):
        screenshot = base64.b64encode(b"synthetic screenshot").decode()
        _, _, _, upsert = self.run_worker([
            self.banner(opts={"screenshot": {"data": screenshot, "labels": ["camera"]}}),
            self.banner(ip_str="192.0.2.2", location=None, tags=None),
        ])
        first, second = [call.args[1] for call in upsert.call_args_list]
        self.assertEqual(first["screenshot"], screenshot)
        self.assertEqual(second["screenshot"], "")
        self.assertEqual(second["indicator"], [])
        self.assertEqual(second["country_code"], "")

    def test_api_error_closes_download_without_retrying_forever(self):
        def failing_cursor(api, query, max_pages):
            yield self.banner()
            raise RuntimeError("Synthetic API failure")

        with patch.object(tasks, "_bounded_shodan_banners", side_effect=failing_cursor):
            _, output, _, upsert = self.run_worker()
        output.close.assert_called_once()
        upsert.assert_called_once()

    def test_task_forwards_page_limit_for_country_and_coordinates(self):
        with (
            patch.object(tasks, "ProgressRecorder"),
            patch.object(tasks, "shodan_search_worker") as worker,
            patch.object(tasks, "_resolve_country_preset", return_value=("test", "ics")),
            patch.dict(tasks.coordinates_queries, {"test": "test"}),
        ):
            tasks.shodan_search.run(
                1, country="US", ics=["test"], coordinates="1,2",
                coordinates_search=["test"], max_pages=2,
            )
        self.assertEqual(worker.call_count, 2)
        for call in worker.call_args_list:
            self.assertEqual(call.kwargs["max_pages"], 2)
            self.assertFalse(call.kwargs["all_results"])
