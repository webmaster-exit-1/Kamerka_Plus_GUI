"""
Fixture-based integration tests for the Shodan ingest path.

These tests use the saved Shodan API response fixture (tests/fixtures/shodan_response.json)
so they run without a real Shodan API key and make no network calls.
"""

from unittest.mock import patch, MagicMock

from django.test import TestCase

from tests.fixtures import load_shodan_fixture


class ShodanFixtureShapeTests(TestCase):
    """Validate that the fixture data matches the expected Shodan API response shape."""

    def test_fixture_has_matches_key(self):
        fixture = load_shodan_fixture()
        self.assertIn('matches', fixture)

    def test_fixture_has_exactly_one_match(self):
        fixture = load_shodan_fixture()
        self.assertEqual(len(fixture['matches']), 1)

    def test_fixture_total_is_one(self):
        fixture = load_shodan_fixture()
        self.assertEqual(fixture['total'], 1)

    def test_fixture_ip_str(self):
        fixture = load_shodan_fixture()
        result = fixture['matches'][0]
        self.assertEqual(result['ip_str'], '119.23.253.64')

    def test_fixture_port(self):
        fixture = load_shodan_fixture()
        result = fixture['matches'][0]
        self.assertEqual(result['port'], 2067)

    def test_fixture_location_city(self):
        fixture = load_shodan_fixture()
        result = fixture['matches'][0]
        self.assertEqual(result['location']['city'], 'Shenzhen')

    def test_fixture_location_country_code(self):
        fixture = load_shodan_fixture()
        result = fixture['matches'][0]
        self.assertEqual(result['location']['country_code'], 'CN')

    def test_fixture_org(self):
        fixture = load_shodan_fixture()
        result = fixture['matches'][0]
        self.assertEqual(result['org'], 'Aliyun Computing Co., LTD')

    def test_fixture_http_server(self):
        fixture = load_shodan_fixture()
        result = fixture['matches'][0]
        self.assertEqual(result['http']['server'], 'GoAhead-Webs')

    def test_fixture_http_status(self):
        fixture = load_shodan_fixture()
        result = fixture['matches'][0]
        self.assertEqual(result['http']['status'], 401)

    def test_fixture_asn(self):
        fixture = load_shodan_fixture()
        result = fixture['matches'][0]
        self.assertEqual(result['asn'], 'AS37963')


class ShodanFixtureIngestTests(TestCase):
    """Tests that verify Device record creation from the Shodan fixture."""

    @patch('kamerka.tasks.shodan.Shodan')
    def test_device_created_from_shodan_result(self, mock_shodan_class):
        from app_kamerka.models import Device, Search

        fixture = load_shodan_fixture()
        mock_instance = MagicMock()
        mock_instance.search_cursor.return_value = iter(fixture['matches'])
        mock_shodan_class.return_value = mock_instance

        # Create the required Search record
        search = Search.objects.create(
            country='CN',
            ics='[]',
            coordinates_search='[]',
        )

        with patch('kamerka.tasks._get_env_key', return_value='ci-dummy-key'), \
             patch('kamerka.tasks._shodan_download_path', return_value='/dev/null'), \
             patch('kamerka.tasks.shodan_helpers') as mock_helpers:

            mock_helpers.open_file.return_value.__enter__ = lambda s: s
            mock_helpers.open_file.return_value.__exit__ = MagicMock(return_value=False)
            mock_helpers.write_banner = MagicMock()

            from kamerka.tasks import shodan_search_worker
            shodan_search_worker(
                fk=search.id,
                query='GoAhead port:2067',
                search_type='ics',
                category='ics',
                country='CN',
            )

        device = Device.objects.filter(ip='119.23.253.64').first()
        self.assertIsNotNone(device, "Device record should be created from fixture data")
        self.assertEqual(str(device.port), '2067')
        self.assertEqual(device.org, 'Aliyun Computing Co., LTD')
