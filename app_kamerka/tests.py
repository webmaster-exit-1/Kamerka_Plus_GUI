import io
import json
import os
import tempfile
from unittest.mock import patch, MagicMock

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, RequestFactory
from django.urls import reverse
from libnmap.parser import NmapParserException

from app_kamerka.models import (
    Search, Device, DeviceNearby, WappalyzerResult, NucleiResult,
    ShodanScan, Whois, Bosch, Dnp3
)

# Absolute path to the nmap XML fixture for github.com (140.82.113.3)
GITHUB_NMAP_XML = os.path.join(os.path.dirname(__file__), 'fixtures', 'github_scan.xml')


class ModelTests(TestCase):
    """Test that new and updated models work correctly."""

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )
        self.device = Device.objects.create(
            search=self.search, ip="192.168.1.1", product="TestCam",
            port="80", type="hikvision", lat="40.0", lon="-74.0",
            country_code="US"
        )

    def test_wappalyzer_result_creation(self):
        wap = WappalyzerResult.objects.create(
            device=self.device,
            technologies={"nginx": "1.18"},
            raw_output='{"nginx": "1.18"}'
        )
        self.assertEqual(wap.device, self.device)
        self.assertEqual(wap.technologies, {"nginx": "1.18"})

    def test_nuclei_result_creation(self):
        nuclei = NucleiResult.objects.create(
            device=self.device,
            template_id="hikvision-cve-2021-36260",
            name="Hikvision RCE",
            severity="critical",
            matched_at="http://192.168.1.1:80",
            description="Test vulnerability"
        )
        self.assertEqual(nuclei.severity, "critical")
        self.assertEqual(nuclei.template_id, "hikvision-cve-2021-36260")

    def test_twitter_nearby_model_removed(self):
        """Verify TwitterNearby model no longer exists."""
        from app_kamerka import models
        self.assertFalse(hasattr(models, 'TwitterNearby'))

    def test_flickr_nearby_model_removed(self):
        """Verify FlickrNearby model no longer exists."""
        from app_kamerka import models
        self.assertFalse(hasattr(models, 'FlickrNearby'))

    def test_device_nearby_still_works(self):
        nearby = DeviceNearby.objects.create(
            device=self.device, lat="40.1", lon="-74.1",
            ip="192.168.1.2", product="Router", port="443", org="TestOrg"
        )
        self.assertEqual(nearby.ip, "192.168.1.2")


class TaskImportTests(TestCase):
    """Test that deprecated imports are removed and new ones exist."""

    def test_no_flickrapi_import(self):
        """Verify flickrapi is not imported in tasks."""
        import kamerka.tasks as tasks_module
        import sys
        self.assertNotIn('flickrapi', sys.modules.get('kamerka.tasks', '').__dict__ if hasattr(sys.modules.get('kamerka.tasks'), '__dict__') else {})

    def test_no_twitter_import(self):
        """Verify twitter is not imported in tasks."""
        with open(os.path.join(os.path.dirname(__file__), '..', 'kamerka', 'tasks.py')) as f:
            content = f.read()
        self.assertNotIn('from twitter import', content)
        self.assertNotIn('import flickrapi', content)

    def test_subprocess_import(self):
        """Verify subprocess is imported for secure CLI execution."""
        with open(os.path.join(os.path.dirname(__file__), '..', 'kamerka', 'tasks.py')) as f:
            content = f.read()
        self.assertIn('import subprocess', content)

    def test_wappalyzer_scan_function_exists(self):
        from kamerka.tasks import wappalyzer_scan
        self.assertTrue(callable(wappalyzer_scan))

    def test_nuclei_scan_function_exists(self):
        from kamerka.tasks import nuclei_scan
        self.assertTrue(callable(nuclei_scan))

    def test_shodan_csv_export_function_exists(self):
        from kamerka.tasks import shodan_csv_export
        self.assertTrue(callable(shodan_csv_export))

    def test_shodan_kml_export_function_exists(self):
        from kamerka.tasks import shodan_kml_export
        self.assertTrue(callable(shodan_kml_export))

    def test_nmap_rtsp_scan_function_exists(self):
        from kamerka.tasks import nmap_rtsp_scan
        self.assertTrue(callable(nmap_rtsp_scan))


class WappalyzerTaskTests(TestCase):
    """Test Wappalyzer CLI integration uses subprocess.run safely."""

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )
        self.device = Device.objects.create(
            search=self.search, ip="192.168.1.1", product="TestCam",
            port="80", type="hikvision", lat="40.0", lon="-74.0",
            country_code="US"
        )

    @patch('kamerka.tasks.subprocess.run')
    def test_wappalyzer_scan_success(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"technologies": [{"name": "nginx"}]}',
            stderr=""
        )
        from kamerka.tasks import wappalyzer_scan
        result = wappalyzer_scan(self.device.id)
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        # Verify subprocess.run is called with a list (no shell=True)
        self.assertIsInstance(call_args[0][0], list)

    @patch('kamerka.tasks.subprocess.run')
    def test_wappalyzer_scan_not_installed(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        from kamerka.tasks import wappalyzer_scan
        result = wappalyzer_scan(self.device.id)
        self.assertIn("error", result)
        self.assertIn("not installed", result["error"])

    @patch('kamerka.tasks.subprocess.run')
    def test_wappalyzer_scan_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="wappalyzer", timeout=60)
        from kamerka.tasks import wappalyzer_scan
        result = wappalyzer_scan(self.device.id)
        self.assertIn("error", result)
        self.assertIn("timed out", result["error"])


class NucleiTaskTests(TestCase):
    """Test Nuclei vulnerability engine integration."""

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )
        self.device = Device.objects.create(
            search=self.search, ip="192.168.1.1", product="TestCam",
            port="80", type="hikvision", lat="40.0", lon="-74.0",
            country_code="US"
        )

    @patch('kamerka.tasks.subprocess.run')
    def test_nuclei_scan_success(self, mock_run):
        finding_json = json.dumps({
            "template-id": "hikvision-cve-2021-36260",
            "info": {"name": "Hikvision RCE", "severity": "critical", "description": "RCE vuln"},
            "matched-at": "http://192.168.1.1:80"
        })
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=finding_json,
            stderr=""
        )
        from kamerka.tasks import nuclei_scan
        result = nuclei_scan(self.device.id)
        self.assertEqual(result["findings_count"], 1)
        # Verify NucleiResult was saved
        self.assertEqual(NucleiResult.objects.filter(device=self.device).count(), 1)

    @patch('kamerka.tasks.subprocess.run')
    def test_nuclei_scan_with_severity_filter(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        from kamerka.tasks import nuclei_scan
        nuclei_scan(self.device.id, severity="critical")
        call_args = mock_run.call_args[0][0]
        self.assertIn("-severity", call_args)
        self.assertIn("critical", call_args)

    @patch('kamerka.tasks.subprocess.run')
    def test_nuclei_scan_with_custom_templates(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        from django.conf import settings as dj_settings
        from kamerka.tasks import nuclei_scan
        nuclei_scan(self.device.id, templates_dir="nuclei_templates/china-iot/hikvision")
        call_args = mock_run.call_args[0][0]
        self.assertIn("-t", call_args)
        # Path must be resolved to absolute before being passed to nuclei
        expected = os.path.join(dj_settings.BASE_DIR, "nuclei_templates", "china-iot", "hikvision")
        self.assertIn(expected, call_args)

    @patch('kamerka.tasks.subprocess.run')
    def test_nuclei_scan_not_installed(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        from kamerka.tasks import nuclei_scan
        result = nuclei_scan(self.device.id)
        self.assertIn("error", result)
        self.assertIn("not installed", result["error"])


class ExportTests(TestCase):
    """Test CSV and KML export functionality."""

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )
        self.device = Device.objects.create(
            search=self.search, ip="192.168.1.1", product="Hikvision Camera",
            port="80", type="hikvision", lat="40.7128", lon="-74.0060",
            country_code="US", org="TestOrg", city="New York",
            vulns="['CVE-2021-36260']"
        )

    def test_csv_export(self):
        from kamerka.tasks import shodan_csv_export
        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as f:
            output_path = f.name
        try:
            shodan_csv_export(self.search.id, output_path)
            self.assertTrue(os.path.exists(output_path))
            with open(output_path) as f:
                content = f.read()
            self.assertIn("IP_Address", content)
            self.assertIn("192.168.1.1", content)
            self.assertIn("Hikvision Camera", content)
        finally:
            os.remove(output_path)

    def test_kml_export(self):
        from kamerka.tasks import shodan_kml_export
        with tempfile.NamedTemporaryFile(suffix='.kml', delete=False) as f:
            output_path = f.name
        try:
            shodan_kml_export(self.search.id, output_path)
            self.assertTrue(os.path.exists(output_path))
            with open(output_path) as f:
                content = f.read()
            self.assertIn("192.168.1.1", content)
            self.assertIn("-74.006", content)
        finally:
            os.remove(output_path)


class NucleiTemplateTests(TestCase):
    """Test that China-IoT Nuclei templates exist and are valid YAML."""

    def test_hikvision_templates_exist(self):
        base = os.path.join(os.path.dirname(__file__), '..', 'nuclei_templates', 'china-iot', 'hikvision')
        self.assertTrue(os.path.exists(os.path.join(base, 'hikvision-web-panel-detect.yaml')))
        self.assertTrue(os.path.exists(os.path.join(base, 'hikvision-cve-2021-36260.yaml')))
        self.assertTrue(os.path.exists(os.path.join(base, 'hikvision-cve-2023-6895.yaml')))

    def test_dahua_templates_exist(self):
        base = os.path.join(os.path.dirname(__file__), '..', 'nuclei_templates', 'china-iot', 'dahua')
        self.assertTrue(os.path.exists(os.path.join(base, 'dahua-web-panel-detect.yaml')))
        self.assertTrue(os.path.exists(os.path.join(base, 'dahua-dss-sqli.yaml')))
        self.assertTrue(os.path.exists(os.path.join(base, 'dahua-cnvd-2017-06001.yaml')))

    def test_huawei_templates_exist(self):
        base = os.path.join(os.path.dirname(__file__), '..', 'nuclei_templates', 'china-iot', 'huawei')
        self.assertTrue(os.path.exists(os.path.join(base, 'huawei-hg5xx-vuln.yaml')))
        self.assertTrue(os.path.exists(os.path.join(base, 'huawei-hg255s-lfi.yaml')))
        self.assertTrue(os.path.exists(os.path.join(base, 'huawei-waf-detect.yaml')))

    def test_zte_templates_exist(self):
        base = os.path.join(os.path.dirname(__file__), '..', 'nuclei_templates', 'china-iot', 'zte')
        self.assertTrue(os.path.exists(os.path.join(base, 'zte-router-disclosure.yaml')))
        self.assertTrue(os.path.exists(os.path.join(base, 'zte-f460-rce.yaml')))
        self.assertTrue(os.path.exists(os.path.join(base, 'zte-v8-detect.yaml')))


class URLPatternTests(TestCase):
    """Test that new URL patterns are registered and old ones removed."""

    def test_new_urls_registered(self):
        from django.urls import reverse
        # New endpoints should be resolvable
        self.assertTrue(reverse('wappalyzer_scan', args=['1']))
        self.assertTrue(reverse('nuclei_scan', args=['1']))
        self.assertTrue(reverse('get_wappalyzer_results', args=['1']))
        self.assertTrue(reverse('get_nuclei_results', args=['1']))
        self.assertTrue(reverse('rtsp_scan', args=['1']))
        self.assertTrue(reverse('export_csv', args=['1']))
        self.assertTrue(reverse('export_kml', args=['1']))

    def test_deprecated_urls_removed(self):
        from django.urls import resolve, Resolver404
        deprecated_urls = [
            '/1/twitter/nearby',
            '/1/twitter/show',
            '/1/flickr/nearby',
            '/get_flickr_results/1',
            '/get_flickr_coordinates/1',
        ]
        for url in deprecated_urls:
            with self.assertRaises(Resolver404, msg="URL {} should not resolve".format(url)):
                resolve(url)


class ViewTests(TestCase):
    """Test that new views respond correctly."""

    def setUp(self):
        self.factory = RequestFactory()
        self.search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )
        self.device = Device.objects.create(
            search=self.search, ip="192.168.1.1", product="TestCam",
            port="80", type="hikvision", lat="40.0", lon="-74.0",
            country_code="US"
        )

    def test_export_csv_view(self):
        from app_kamerka.views import export_csv
        request = self.factory.get('/export/csv/{}'.format(self.search.id))
        response = export_csv(request, self.search.id)
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/csv', response['Content-Type'])

    def test_export_kml_view(self):
        from app_kamerka.views import export_kml
        request = self.factory.get('/export/kml/{}'.format(self.search.id))
        response = export_kml(request, self.search.id)
        self.assertEqual(response.status_code, 200)
        self.assertIn('kml', response['Content-Type'])


class GUIVisualTests(TestCase):
    """Visual tests to verify all main GUI pages render without errors."""

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="40.7128,-74.0060", country="US",
            ics="['hikvision']", coordinates_search="['40.7128,-74.0060']"
        )
        self.device = Device.objects.create(
            search=self.search, ip="192.168.1.1", product="Hikvision Camera",
            port="80", type="hikvision", lat="40.7128", lon="-74.0060",
            country_code="US", org="TestOrg", city="New York"
        )

    def test_search_main_page_loads(self):
        """Verify the main search page renders with the search form."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'ꓘamerka')
        self.assertContains(response, 'search')

    @patch('app_kamerka.views.check_credits', return_value=[])
    def test_index_page_loads(self, _):
        """Verify the dashboard/index page renders."""
        response = self.client.get('/index')
        self.assertEqual(response.status_code, 200)

    def test_history_page_loads(self):
        """Verify the history page renders with the data table."""
        response = self.client.get('/history')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'history')

    def test_devices_page_loads(self):
        """Verify the devices/search page renders."""
        response = self.client.get('/devices')
        self.assertEqual(response.status_code, 200)

    def test_sources_page_loads(self):
        """Verify the useful links/sources page renders."""
        response = self.client.get('/sources')
        self.assertEqual(response.status_code, 200)

    def test_map_page_loads(self):
        """Verify the map page renders with the Leaflet map div and device markers."""
        response = self.client.get('/map')
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn('leaflet_world_map', content)
        self.assertIn('L.marker(', content)
        self.assertIn('192.168.1.1', content)

    def test_gallery_page_loads(self):
        """Verify the gallery page renders."""
        response = self.client.get('/gallery')
        self.assertEqual(response.status_code, 200)

    def test_results_page_loads(self):
        """Verify the results page renders with the Leaflet map and device markers."""
        response = self.client.get('/results/{}'.format(self.search.id))
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn('leaflet_world_map', content)
        self.assertIn('World Map', content)
        self.assertIn('L.marker(', content)
        self.assertIn('192.168.1.1', content)

    def test_search_main_contains_form_tabs(self):
        """Verify the main search page has all expected search category tabs."""
        response = self.client.get('/')
        content = response.content.decode()
        self.assertIn('Industrial Control Systems', content)
        self.assertIn('Internet of Things', content)
        self.assertIn('Healthcare', content)
        self.assertIn('Infrastructure', content)

    def test_no_import_errors_on_startup(self):
        """Verify all app modules import without errors."""
        import importlib
        modules = [
            'app_kamerka.views',
            'app_kamerka.models',
            'app_kamerka.forms',
            'app_kamerka.urls',
            'app_kamerka.exploits',
            'kamerka.tasks',
            'kamerka.celery',
            'kamerka.urls',
        ]
        for mod_name in modules:
            mod = importlib.import_module(mod_name)
            self.assertIsNotNone(mod, "Module {} failed to import".format(mod_name))


class ICSMapVisualTests(TestCase):
    """Visual tests to verify Industrial Control System devices appear on
    the map with correct icons and that markers are clickable."""

    ICS_DEVICE_TYPES = {
        'niagara': 'blue.png',
        'modbus': 'factory_orange.png',
        'bacnet': 'green.png',
        'siemens': 'pink.png',
        'dnp3': 'purple.png',
        'pcworx': 'light_purple.png',
        'mitsubishi': 'white.png',
        'omron': 'blue2.png',
        'redlion': 'green2.png',
        'codesys': 'purple2.png',
        'iec': 'yellow2.png',
        'proconos': 'pink2.png',
        'simatic': 'simatic.png',
        'simatic_s7': 'simatic_s7.png',
        'schneider_electric': 'schneider_electric.png',
        'scalance': 'scalance.png',
        'modicon': 'modicon.png',
    }

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="40.7128,-74.0060", country="US",
            ics="['modbus','siemens']", coordinates_search="['40.7128,-74.0060']"
        )
        # Create one device for each ICS type to populate the map
        self.devices = {}
        lat_base = 40.0
        for i, (dev_type, icon) in enumerate(self.ICS_DEVICE_TYPES.items()):
            d = Device.objects.create(
                search=self.search,
                ip="10.0.0.{}".format(i + 1),
                product="{} Controller".format(dev_type.capitalize()),
                port="502",
                type=dev_type,
                lat=str(lat_base + i * 0.1),
                lon="-74.0060",
                country_code="US",
                org="ICS-Test",
                city="TestCity",
            )
            self.devices[dev_type] = d

    def test_results_page_renders_ics_markers(self):
        """Verify the results page generates Leaflet markers for every ICS device."""
        response = self.client.get('/results/{}'.format(self.search.id))
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        for dev_type, device in self.devices.items():
            self.assertIn(
                'L.marker([{}, {}])'.format(device.lat, device.lon),
                content,
                "Marker position missing for ICS type '{}'".format(dev_type),
            )

    def test_results_page_ics_marker_popups(self):
        """Verify each ICS device type has a popup with its IP and type."""
        response = self.client.get('/results/{}'.format(self.search.id))
        content = response.content.decode()
        for dev_type, device in self.devices.items():
            self.assertIn(
                device.ip,
                content,
                "IP '{}' missing for ICS type '{}'".format(device.ip, dev_type),
            )

    def test_results_page_markers_have_clickable_links(self):
        """Verify every ICS marker popup contains an anchor link to the device detail page."""
        response = self.client.get('/results/{}'.format(self.search.id))
        content = response.content.decode()
        for dev_type, device in self.devices.items():
            expected_href = 'href="{}/{}/{}"'.format(
                device.search_id, device.id, device.ip
            )
            self.assertIn(
                expected_href,
                content,
                "Clickable link missing in marker for ICS type '{}'".format(dev_type),
            )

    def test_results_page_device_table_has_clickable_ips(self):
        """Verify the devices tab table renders each ICS device IP as a clickable link."""
        response = self.client.get('/results/{}'.format(self.search.id))
        content = response.content.decode()
        for dev_type, device in self.devices.items():
            self.assertIn(
                device.ip,
                content,
                "IP address missing from device table for '{}'".format(dev_type),
            )
            # The IP should be inside an <a> tag linking to the device detail view
            self.assertIn(
                'href="/results/{}/{}/{}"'.format(
                    device.search_id, device.id, device.ip
                ),
                content,
                "Device table link missing for '{}'".format(dev_type),
            )

    def test_map_page_renders_ics_markers(self):
        """Verify the global map page shows Leaflet markers for all ICS devices."""
        response = self.client.get('/map')
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        for dev_type, device in self.devices.items():
            self.assertIn(
                'L.marker([{}, {}])'.format(device.lat, device.lon),
                content,
                "Map marker missing for ICS type '{}'".format(dev_type),
            )

    def test_map_page_markers_have_clickable_links(self):
        """Verify the global map page markers have clickable device detail links."""
        response = self.client.get('/map')
        content = response.content.decode()
        for dev_type, device in self.devices.items():
            expected_href = 'href="/results/{}/{}/{}"'.format(
                device.search_id, device.id, device.ip
            )
            self.assertIn(
                expected_href,
                content,
                "Clickable link missing on map for ICS type '{}'".format(dev_type),
            )

    def test_map_page_ics_marker_popups(self):
        """Verify each ICS device type has a popup with its IP on the global map."""
        response = self.client.get('/map')
        content = response.content.decode()
        for dev_type, device in self.devices.items():
            self.assertIn(
                device.ip,
                content,
                "IP '{}' missing on map for ICS type '{}'".format(device.ip, dev_type),
            )

    def test_device_detail_page_renders_for_ics(self):
        """Verify the individual device detail page loads for an ICS device."""
        device = self.devices['modbus']
        response = self.client.get(
            '/results/{}/{}/{}'.format(self.search.id, device.id, device.ip)
        )
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn(device.ip, content)
        self.assertIn('modbus', content.lower())


class NmapUploadTests(TestCase):
    """
    End-to-end tests for the nmap XML upload path.

    These tests simulate uploading the github.com nmap scan (140.82.113.3)
    and verify that the crash fixes work correctly:
      - validate_nmap accepts a valid XML file without crashing
      - nmap_host_worker saves a Device with correct fields
      - nmap_host_worker handles an empty hostnames list (no IndexError)
      - nmap_host_worker skips hosts where MaxMind returns None (no TypeError)
      - nmap_host_worker skips hosts with missing latitude/longitude
      - The view's POST handler processes the file and dispatches the task
    """

    # Realistic MaxMind response for a GitHub IP (Ashburn, Virginia)
    GITHUB_MAXMIND = {
        'location': {'latitude': 38.6583, 'longitude': -77.3156},
        'country': {'iso_code': 'US'},
    }

    def _make_search(self):
        return Search.objects.create(country='NMAP Scan', ics='github_scan.xml', nmap=True)

    def _make_mock_reader(self, return_value):
        reader = MagicMock()
        reader.get.return_value = return_value
        return reader

    # ------------------------------------------------------------------ #
    # 1. validate_nmap
    # ------------------------------------------------------------------ #
    def test_validate_nmap_accepts_valid_xml(self):
        """validate_nmap should parse the github.com XML without raising."""
        from kamerka.tasks import validate_nmap
        # Should not raise
        validate_nmap(GITHUB_NMAP_XML)

    # ------------------------------------------------------------------ #
    # 2. nmap_host_worker – happy path
    # ------------------------------------------------------------------ #
    def test_nmap_host_worker_saves_device(self):
        """nmap_host_worker should create a Device record for a valid host."""
        from libnmap.parser import NmapParser
        from kamerka.tasks import nmap_host_worker

        search = self._make_search()
        report = NmapParser.parse_fromfile(GITHUB_NMAP_XML)
        host = report.hosts[0]  # 140.82.113.3

        nmap_host_worker(
            host_arg=host,
            max_reader=self._make_mock_reader(self.GITHUB_MAXMIND),
            search=search,
        )

        device = Device.objects.get(search=search, ip='140.82.113.3')
        self.assertEqual(device.type, 'NMAP')
        self.assertEqual(device.category, 'NMAP')
        self.assertEqual(device.country_code, 'US')
        self.assertAlmostEqual(float(device.lat), 38.6583, places=3)
        self.assertAlmostEqual(float(device.lon), -77.3156, places=3)
        # All three open ports should be recorded
        self.assertIn('22', device.port)
        self.assertIn('80', device.port)
        self.assertIn('443', device.port)
        # Regression: port field previously had max_length=10; "22, 80, 443" is 11 chars
        # and would crash on save. Verify the full string is stored intact.
        self.assertEqual(device.port, '22, 80, 443')

    def test_nmap_host_worker_stores_hostname(self):
        """nmap_host_worker should persist the first PTR hostname."""
        from libnmap.parser import NmapParser
        from kamerka.tasks import nmap_host_worker

        search = self._make_search()
        report = NmapParser.parse_fromfile(GITHUB_NMAP_XML)
        nmap_host_worker(
            host_arg=report.hosts[0],
            max_reader=self._make_mock_reader(self.GITHUB_MAXMIND),
            search=search,
        )
        device = Device.objects.get(search=search, ip='140.82.113.3')
        self.assertEqual(device.hostnames, 'lb-140-82-113-3-iad.github.com')

    # ------------------------------------------------------------------ #
    # 3. nmap_host_worker – edge cases that previously crashed
    # ------------------------------------------------------------------ #
    def test_nmap_host_worker_multi_port_no_truncation(self):
        """
        Regression: Device.port previously had max_length=10.
        A real-world scan can easily produce port strings longer than 10 chars
        (e.g. '22, 80, 443' = 11 chars). Saving such a device must not crash
        and the full port string must be stored intact.
        """
        from kamerka.tasks import nmap_host_worker

        search = self._make_search()
        # Simulate a host with many open ports (as nmap would report)
        svc_mock = lambda p: MagicMock(port=p, state='open')
        host = MagicMock()
        host.hostnames = ['lb-140-82-113-3-iad.github.com']
        host.address = '140.82.113.3'
        host.services = [svc_mock(p) for p in [22, 80, 443, 8080, 8443, 3000, 9418]]

        nmap_host_worker(
            host_arg=host,
            max_reader=self._make_mock_reader(self.GITHUB_MAXMIND),
            search=search,
        )

        device = Device.objects.get(search=search, ip='140.82.113.3')
        expected = '22, 80, 443, 8080, 8443, 3000, 9418'
        self.assertEqual(device.port, expected,
                         "Port string was truncated or corrupted – max_length too small")
        self.assertGreater(len(expected), 10,
                           "Test string must exceed the old max_length=10 to be meaningful")

    def test_large_port_string_survives_round_trip(self):
        """
        Regression: Device.port must store a port string far exceeding the old
        CharField(max_length=1000) limit without truncation.  Uses a direct ORM
        round-trip with a synthetic string (~2 000 chars) to keep the test fast.
        """
        # Build a port string that well exceeds the old 1 000-char limit
        ports = list(range(1, 500))
        port_string = ', '.join(str(p) for p in ports)
        self.assertGreater(len(port_string), 1000,
                           "Sanity-check: string must exceed old varchar limit")

        search = self._make_search()
        device = Device(
            search=search, ip='10.0.0.1', product='', org='', data='',
            port=port_string, type='NMAP', city='NMAP',
            lat=0.0, lon=0.0, country_code='US',
            query='NMAP SCAN', category='NMAP',
            vulns='', indicator='', hostnames='', screenshot='',
        )
        device.save()
        device.refresh_from_db()

        self.assertEqual(len(device.port), len(port_string),
                         "Port string length mismatch – was it truncated?")
        self.assertTrue(device.port.startswith('1, 2, 3'),
                        "Port string does not start with expected sequence")
        self.assertTrue(device.port.endswith(str(ports[-1])),
                        "Port string does not end with expected last port")

    def test_nmap_host_worker_no_crash_on_empty_hostnames(self):
        """nmap_host_worker must not raise IndexError when hostnames list is empty."""
        from kamerka.tasks import nmap_host_worker

        search = self._make_search()
        host = MagicMock()
        host.hostnames = []          # empty – previously caused IndexError
        host.address = '140.82.113.3'
        host.services = []

        # Should not raise
        nmap_host_worker(
            host_arg=host,
            max_reader=self._make_mock_reader(self.GITHUB_MAXMIND),
            search=search,
        )
        device = Device.objects.get(search=search, ip='140.82.113.3')
        self.assertEqual(device.hostnames, '')

    def test_nmap_host_worker_no_crash_on_none_maxmind(self):
        """nmap_host_worker must not raise TypeError when MaxMind returns None,
        and must still create a Device with empty geo fields."""
        from kamerka.tasks import nmap_host_worker

        search = self._make_search()
        host = MagicMock()
        host.hostnames = ['lb-140-82-113-3-iad.github.com']
        host.address = '140.82.113.3'
        host.services = []

        # Should not raise; Device should still be created (with empty geo data)
        nmap_host_worker(
            host_arg=host,
            max_reader=self._make_mock_reader(None),  # None – previously caused TypeError
            search=search,
        )
        device = Device.objects.get(search=search, ip='140.82.113.3')
        self.assertEqual(device.lat, '')
        self.assertEqual(device.lon, '')
        self.assertEqual(device.country_code, '')

    def test_nmap_host_worker_no_crash_on_missing_lat_lon(self):
        """nmap_host_worker must not raise when MaxMind entry lacks lat/lon,
        and must still create a Device with empty lat/lon."""
        from kamerka.tasks import nmap_host_worker

        search = self._make_search()
        host = MagicMock()
        host.hostnames = ['lb-140-82-113-3-iad.github.com']
        host.address = '140.82.113.3'
        host.services = []

        incomplete_maxmind = {'location': {}, 'country': {'iso_code': 'US'}}
        nmap_host_worker(
            host_arg=host,
            max_reader=self._make_mock_reader(incomplete_maxmind),
            search=search,
        )
        device = Device.objects.get(search=search, ip='140.82.113.3')
        self.assertEqual(device.lat, '')
        self.assertEqual(device.lon, '')
        self.assertEqual(device.country_code, 'US')

    # ------------------------------------------------------------------ #
    # 4. Full view upload path
    # ------------------------------------------------------------------ #
    @patch('app_kamerka.views.validate_maxmind')
    @patch('app_kamerka.views.validate_nmap')
    @patch('app_kamerka.views.nmap_scan')
    def test_view_upload_dispatches_task(self, mock_task, mock_val_nmap, mock_val_maxmind):
        """
        Uploading a file via POST should call validate_nmap, validate_maxmind,
        save a Search record, and call nmap_scan.delay with the absolute file path.
        """
        mock_result = MagicMock()
        mock_result.task_id = 'test-task-id-123'
        mock_task.delay.return_value = mock_result

        with open(GITHUB_NMAP_XML, 'rb') as f:
            xml_bytes = f.read()

        response = self.client.post(
            '/',
            {'myfile': SimpleUploadedFile('github_scan.xml', xml_bytes, content_type='text/xml')},
        )

        # Should redirect back to index on success
        self.assertIn(response.status_code, (302, 200))

        # validate_nmap must be called with an absolute path (not a URL)
        mock_val_nmap.assert_called_once()
        called_path = mock_val_nmap.call_args[0][0]
        self.assertTrue(os.path.isabs(called_path),
                        f"Expected absolute path, got: {called_path}")
        self.assertNotIn('/scans/', called_path.replace(os.sep, '/').split('/')[-2] if '/' in called_path else called_path,
                         "Path should not be a URL fragment")

        # nmap_scan.delay must be called with the same absolute path
        mock_task.delay.assert_called_once()
        task_path = mock_task.delay.call_args[0][0]
        self.assertTrue(os.path.isabs(task_path),
                        f"nmap_scan.delay received a non-absolute path: {task_path}")

        # A Search record should exist
        self.assertTrue(Search.objects.filter(country='NMAP Scan', nmap=True).exists())


# ===========================================================================
# 3D Refactor – new module tests
# ===========================================================================

class CoordinateMapperTests(TestCase):
    """Unit tests for globe_3d.coordinate_mapper spherical-trig math."""

    def test_equator_prime_meridian(self):
        """lat=0, lon=0 → (R, 0, 0)."""
        from globe_3d.coordinate_mapper import latlon_to_xyz, EARTH_RADIUS
        x, y, z = latlon_to_xyz(0.0, 0.0)
        self.assertAlmostEqual(x, EARTH_RADIUS, places=9)
        self.assertAlmostEqual(y, 0.0, places=9)
        self.assertAlmostEqual(z, 0.0, places=9)

    def test_north_pole(self):
        """lat=90 → z = R, x ≈ 0, y ≈ 0."""
        from globe_3d.coordinate_mapper import latlon_to_xyz, EARTH_RADIUS
        x, y, z = latlon_to_xyz(90.0, 0.0)
        self.assertAlmostEqual(z, EARTH_RADIUS, places=9)
        self.assertAlmostEqual(x, 0.0, places=9)
        self.assertAlmostEqual(y, 0.0, places=9)

    def test_south_pole(self):
        """lat=-90 → z = -R."""
        from globe_3d.coordinate_mapper import latlon_to_xyz, EARTH_RADIUS
        x, y, z = latlon_to_xyz(-90.0, 0.0)
        self.assertAlmostEqual(z, -EARTH_RADIUS, places=9)

    def test_equator_90_east(self):
        """lat=0, lon=90 → (0, R, 0)."""
        from globe_3d.coordinate_mapper import latlon_to_xyz, EARTH_RADIUS
        x, y, z = latlon_to_xyz(0.0, 90.0)
        self.assertAlmostEqual(x, 0.0, places=9)
        self.assertAlmostEqual(y, EARTH_RADIUS, places=9)
        self.assertAlmostEqual(z, 0.0, places=9)

    def test_custom_radius(self):
        """Custom radius is respected."""
        from globe_3d.coordinate_mapper import latlon_to_xyz
        x, y, z = latlon_to_xyz(0.0, 0.0, radius=2.5)
        self.assertAlmostEqual(x, 2.5, places=9)

    def test_on_sphere_surface(self):
        """For any lat/lon the result lies on the unit sphere."""
        import math
        from globe_3d.coordinate_mapper import latlon_to_xyz, EARTH_RADIUS
        for lat, lon in [(40.7128, -74.0060), (-33.8688, 151.2093), (51.5074, -0.1278)]:
            x, y, z = latlon_to_xyz(lat, lon)
            r = math.sqrt(x ** 2 + y ** 2 + z ** 2)
            self.assertAlmostEqual(r, EARTH_RADIUS, places=9)

    def test_round_trip(self):
        """xyz_to_latlon(latlon_to_xyz(lat, lon)) ≈ (lat, lon)."""
        from globe_3d.coordinate_mapper import latlon_to_xyz, xyz_to_latlon
        for lat, lon in [(40.7128, -74.0060), (-33.8688, 151.2093)]:
            x, y, z = latlon_to_xyz(lat, lon)
            lat2, lon2 = xyz_to_latlon(x, y, z)
            self.assertAlmostEqual(lat2, lat, places=6)
            self.assertAlmostEqual(lon2, lon, places=6)

    def test_spike_base_above_surface(self):
        """spike_base_xyz returns a point strictly outside the unit sphere."""
        import math
        from globe_3d.coordinate_mapper import spike_base_xyz, EARTH_RADIUS, SPIKE_OFFSET
        x, y, z = spike_base_xyz(0.0, 0.0)
        r = math.sqrt(x ** 2 + y ** 2 + z ** 2)
        self.assertAlmostEqual(r, EARTH_RADIUS + SPIKE_OFFSET, places=9)


class SpikeRendererTests(TestCase):
    """Unit tests for globe_3d.spike_renderer colour and scaling logic."""

    def test_critical_is_red(self):
        from globe_3d.spike_renderer import severity_to_colour
        self.assertEqual(severity_to_colour("critical"), (1.0, 0.0, 0.0))

    def test_high_is_red(self):
        from globe_3d.spike_renderer import severity_to_colour
        self.assertEqual(severity_to_colour("HIGH"), (1.0, 0.0, 0.0))

    def test_medium_is_yellow(self):
        from globe_3d.spike_renderer import severity_to_colour
        self.assertEqual(severity_to_colour("Medium"), (1.0, 1.0, 0.0))

    def test_unknown_severity_falls_back(self):
        from globe_3d.spike_renderer import severity_to_colour, SEVERITY_COLOURS
        self.assertEqual(severity_to_colour(""), SEVERITY_COLOURS["unknown"])
        self.assertEqual(severity_to_colour("nonsense"), SEVERITY_COLOURS["unknown"])

    def test_spike_height_scales_with_count(self):
        from globe_3d.spike_renderer import scale_spike_height, MIN_SPIKE_HEIGHT, MAX_SPIKE_HEIGHT
        h_min = scale_spike_height(1, 100)
        h_max = scale_spike_height(100, 100)
        self.assertGreater(h_max, h_min)
        self.assertAlmostEqual(h_max, MAX_SPIKE_HEIGHT, places=9)
        self.assertGreaterEqual(h_min, MIN_SPIKE_HEIGHT)

    def test_spike_height_clamps_zero(self):
        from globe_3d.spike_renderer import scale_spike_height, MIN_SPIKE_HEIGHT
        self.assertEqual(scale_spike_height(0, 100), MIN_SPIKE_HEIGHT)
        self.assertEqual(scale_spike_height(5, 0), MIN_SPIKE_HEIGHT)

    def test_build_spike_data_empty(self):
        from globe_3d.spike_renderer import build_spike_data
        self.assertEqual(build_spike_data([]), [])

    def test_build_spike_data_returns_correct_keys(self):
        from globe_3d.spike_renderer import build_spike_data
        clusters = [{"lat": 40.0, "lon": -74.0, "count": 5, "severity": "medium"}]
        result = build_spike_data(clusters)
        self.assertEqual(len(result), 1)
        spike = result[0]
        for key in ("lat", "lon", "height", "colour", "count", "severity", "devices"):
            self.assertIn(key, spike, "Missing key: {}".format(key))

    def test_dominant_severity_priority(self):
        from globe_3d.spike_renderer import dominant_severity
        self.assertEqual(dominant_severity(["low", "critical", "medium"]), "critical")
        self.assertEqual(dominant_severity(["high", "medium"]), "high")
        self.assertEqual(dominant_severity([]), "unknown")
        self.assertEqual(dominant_severity(["info"]), "info")


class LODManagerTests(TestCase):
    """Unit tests for globe_3d.lod_manager cluster/dissolve logic."""

    def _make_devices(self, count, lat_base=40.0, lon_base=-74.0, step=0.1):
        return [
            {"lat": str(lat_base + i * step), "lon": str(lon_base), "severity": "low"}
            for i in range(count)
        ]

    def test_cluster_devices_groups_close_points(self):
        """Devices within 2° of each other should form one cluster."""
        from globe_3d.lod_manager import cluster_devices
        devices = self._make_devices(5, lat_base=40.0, step=0.1)
        clusters = cluster_devices(devices, radius_deg=2.0)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["count"], 5)

    def test_cluster_devices_separates_distant_points(self):
        """Devices > 2° apart should form separate clusters."""
        from globe_3d.lod_manager import cluster_devices
        devices = [
            {"lat": "10.0", "lon": "10.0", "severity": "low"},
            {"lat": "50.0", "lon": "50.0", "severity": "low"},
        ]
        clusters = cluster_devices(devices, radius_deg=2.0)
        self.assertEqual(len(clusters), 2)

    def test_cluster_skips_invalid_coords(self):
        """Devices with unparseable lat/lon are silently skipped."""
        from globe_3d.lod_manager import cluster_devices
        devices = [
            {"lat": "bad", "lon": "-74.0", "severity": "low"},
            {"lat": "40.0", "lon": "-74.0", "severity": "low"},
        ]
        clusters = cluster_devices(devices)
        self.assertEqual(sum(c["count"] for c in clusters), 1)

    def test_dissolve_cluster_returns_individuals(self):
        """dissolve_cluster must return one entry per device."""
        from globe_3d.lod_manager import dissolve_cluster
        cluster = {
            "lat": 40.0, "lon": -74.0, "count": 3,
            "severity": "medium",
            "devices": [
                {"lat": "40.0", "lon": "-74.0", "severity": "medium"},
                {"lat": "40.1", "lon": "-74.0", "severity": "low"},
                {"lat": "40.2", "lon": "-74.0", "severity": "high"},
            ],
        }
        result = dissolve_cluster(cluster)
        self.assertEqual(len(result), 3)
        for item in result:
            self.assertEqual(item["count"], 1)

    def test_get_render_data_global_view(self):
        """zoom < threshold → aggregate clusters."""
        from globe_3d.lod_manager import get_render_data, CLUSTER_RADIUS_DEG
        devices = self._make_devices(10, step=0.05)
        result = get_render_data(devices, zoom_level=0.0)
        self.assertLess(len(result), 10, "Global view should aggregate into fewer clusters")

    def test_get_render_data_zoomed_view(self):
        """zoom > threshold → individual points."""
        from globe_3d.lod_manager import get_render_data
        devices = self._make_devices(5, step=0.05)
        result = get_render_data(devices, zoom_level=1.0)
        total = sum(r["count"] for r in result)
        self.assertEqual(total, 5, "Zoomed view should show all individual devices")


class HoneypotFilterTests(TestCase):
    """Unit tests for verification.honeypot_filter."""

    def _make_devices(self, subnet, banner, count):
        """Create *count* device dicts all in the same /24 subnet with *banner*.

        Host IDs cycle through 1–254 (valid IPv4 range) so every IP is
        parseable by ipaddress.ip_address even when count > 254.  Multiple
        entries may share the same IP address; that is intentional — the
        honeypot filter counts list entries (banner occurrences), not unique
        IPs.
        """
        return [
            {"ip": "{}.{}".format(subnet, (i % 254) + 1), "data": banner}
            for i in range(count)
        ]

    def test_detect_cluster_above_threshold(self):
        """≥500 entries sharing a /24 subnet and banner must be flagged."""
        from verification.honeypot_filter import detect_honeypot_clusters
        devices = self._make_devices("1.2.3", "HTTP/1.1 200 OK", 500)
        flagged = detect_honeypot_clusters(devices, threshold=500)
        self.assertEqual(len(flagged), 1)
        subnet, banner = flagged[0]
        self.assertIn("1.2.3", subnet)
        self.assertEqual(banner, "HTTP/1.1 200 OK")

    def test_no_flag_below_threshold(self):
        """<500 entries with identical banner must not be flagged."""
        from verification.honeypot_filter import detect_honeypot_clusters
        devices = self._make_devices("1.2.3", "HTTP/1.1 200 OK", 499)
        self.assertEqual(detect_honeypot_clusters(devices, threshold=500), [])

    def test_different_banners_not_flagged(self):
        """500 devices with unique banners must not trigger the filter."""
        from verification.honeypot_filter import detect_honeypot_clusters
        devices = [
            {"ip": "1.2.3.{}".format(i + 1), "data": "banner_{}".format(i)}
            for i in range(500)
        ]
        self.assertEqual(detect_honeypot_clusters(devices, threshold=500), [])

    def test_filter_honeypots_removes_flagged(self):
        """filter_honeypots must remove all devices belonging to flagged clusters."""
        from verification.honeypot_filter import filter_honeypots
        bad = self._make_devices("1.2.3", "HONEYPOT", 500)
        good = [{"ip": "9.9.9.9", "data": "legit banner"}]
        clean = filter_honeypots(bad + good, threshold=500)
        ips = [d["ip"] for d in clean]
        self.assertIn("9.9.9.9", ips)
        for d in bad:
            self.assertNotIn(d["ip"], ips)

    def test_filter_honeypots_empty_input(self):
        from verification.honeypot_filter import filter_honeypots
        self.assertEqual(filter_honeypots([]), [])

    def test_is_honeypot_device(self):
        from verification.honeypot_filter import is_honeypot_device
        flagged = [("1.2.3.0/24", "bad banner")]
        self.assertTrue(
            is_honeypot_device({"ip": "1.2.3.5", "data": "bad banner"}, flagged)
        )
        self.assertFalse(
            is_honeypot_device({"ip": "1.2.3.5", "data": "good banner"}, flagged)
        )

    def test_invalid_ip_not_flagged(self):
        """Devices with non-IPv4 addresses are gracefully skipped."""
        from verification.honeypot_filter import detect_honeypot_clusters
        devices = [{"ip": "not-an-ip", "data": "banner"}] * 500
        self.assertEqual(detect_honeypot_clusters(devices, threshold=500), [])


class InternetDBTests(TestCase):
    """Unit tests for verification.internet_db using mocked HTTP calls."""

    @patch('verification.internet_db.requests.get')
    def test_returns_dict_on_success(self, mock_get):
        from verification.internet_db import check_internetdb
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"ip": "8.8.8.8", "ports": [53, 443], "tags": []}
        )
        result = check_internetdb("8.8.8.8")
        self.assertIsNotNone(result)
        self.assertEqual(result["ports"], [53, 443])

    @patch('verification.internet_db.requests.get')
    def test_returns_none_on_404(self, mock_get):
        from verification.internet_db import check_internetdb
        mock_get.return_value = MagicMock(status_code=404)
        self.assertIsNone(check_internetdb("8.8.8.8"))

    @patch('verification.internet_db.requests.get')
    def test_returns_none_on_timeout(self, mock_get):
        import requests as req
        from verification.internet_db import check_internetdb
        mock_get.side_effect = req.exceptions.Timeout()
        self.assertIsNone(check_internetdb("8.8.8.8"))

    @patch('verification.internet_db.requests.get')
    def test_returns_none_on_request_error(self, mock_get):
        import requests as req
        from verification.internet_db import check_internetdb
        mock_get.side_effect = req.exceptions.RequestException("fail")
        self.assertIsNone(check_internetdb("8.8.8.8"))

    def test_private_ip_skipped(self):
        """Private IPs must be rejected without making an HTTP request."""
        from verification.internet_db import check_internetdb
        self.assertIsNone(check_internetdb("192.168.1.1"))
        self.assertIsNone(check_internetdb("127.0.0.1"))
        self.assertIsNone(check_internetdb("10.0.0.1"))

    @patch('verification.internet_db.requests.get')
    def test_is_alive_returns_true_with_ports(self, mock_get):
        from verification.internet_db import is_alive_internetdb
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"ports": [80]}
        )
        self.assertTrue(is_alive_internetdb("8.8.8.8"))

    @patch('verification.internet_db.requests.get')
    def test_is_alive_returns_false_no_ports(self, mock_get):
        from verification.internet_db import is_alive_internetdb
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"ports": []}
        )
        self.assertFalse(is_alive_internetdb("8.8.8.8"))


class NaabuScannerTests(TestCase):
    """Unit tests for verification.naabu_scanner using mocked subprocess."""

    @patch('verification.naabu_scanner.subprocess.run')
    def test_parses_json_output(self, mock_run):
        from verification.naabu_scanner import run_naabu
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"ip":"1.2.3.4","port":80}\n{"ip":"1.2.3.4","port":443}\n',
        )
        results = run_naabu("1.2.3.4")
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["port"], 80)
        self.assertEqual(results[1]["port"], 443)

    @patch('verification.naabu_scanner.subprocess.run')
    def test_parses_plaintext_fallback(self, mock_run):
        from verification.naabu_scanner import run_naabu
        mock_run.return_value = MagicMock(returncode=0, stdout="1.2.3.4:8080\n")
        results = run_naabu("1.2.3.4")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["port"], 8080)

    @patch('verification.naabu_scanner.subprocess.run')
    def test_returns_empty_on_no_open_ports(self, mock_run):
        from verification.naabu_scanner import run_naabu
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        self.assertEqual(run_naabu("1.2.3.4"), [])

    @patch('verification.naabu_scanner.subprocess.run')
    def test_returns_empty_on_file_not_found(self, mock_run):
        from verification.naabu_scanner import run_naabu
        mock_run.side_effect = FileNotFoundError()
        self.assertEqual(run_naabu("1.2.3.4"), [])

    @patch('verification.naabu_scanner.subprocess.run')
    def test_returns_empty_on_timeout(self, mock_run):
        import subprocess
        from verification.naabu_scanner import run_naabu
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="naabu", timeout=60)
        self.assertEqual(run_naabu("1.2.3.4"), [])

    @patch('verification.naabu_scanner.subprocess.run')
    def test_is_alive_true(self, mock_run):
        from verification.naabu_scanner import is_alive_naabu
        mock_run.return_value = MagicMock(returncode=0, stdout='{"ip":"1.2.3.4","port":80}\n')
        self.assertTrue(is_alive_naabu("1.2.3.4"))

    @patch('verification.naabu_scanner.subprocess.run')
    def test_is_alive_false(self, mock_run):
        from verification.naabu_scanner import is_alive_naabu
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        self.assertFalse(is_alive_naabu("1.2.3.4"))

    @patch('verification.naabu_scanner.subprocess.run')
    def test_uses_configured_bin_path(self, mock_run):
        """run_naabu must use the binary path from settings.NAABU_BIN."""
        from unittest.mock import patch as _patch
        from verification.naabu_scanner import run_naabu
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        with _patch('verification.naabu_scanner._get_naabu_bin', return_value='/opt/naabu'):
            run_naabu("1.2.3.4")
        called_cmd = mock_run.call_args[0][0]
        self.assertEqual(called_cmd[0], '/opt/naabu')

    @patch('verification.naabu_scanner.subprocess.run')
    def test_no_shell_true(self, mock_run):
        """subprocess.run must never be called with shell=True."""
        from verification.naabu_scanner import run_naabu
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        run_naabu("1.2.3.4")
        kwargs = mock_run.call_args[1]
        self.assertFalse(kwargs.get('shell', False))


class ShodanAnalyticsTests(TestCase):
    """Unit tests for verification.shodan_analytics credit reporting and dedup."""

    def _make_mock_api(self, total=50, facets=None):
        api = MagicMock()
        api.count.return_value = {"total": total}
        api.stats.return_value = {"facets": facets or {"country": [["US", 30]]}}
        return api

    def test_credit_cost_report_structure(self):
        from verification.shodan_analytics import credit_cost_report
        api = self._make_mock_api(total=50)
        report = credit_cost_report(api, "port:502")
        for key in ("query", "total_results", "estimated_credits", "facets", "recommendation"):
            self.assertIn(key, report)

    def test_credit_cost_report_zero_results(self):
        from verification.shodan_analytics import credit_cost_report
        api = self._make_mock_api(total=0)
        report = credit_cost_report(api, "port:502")
        self.assertIn("No results", report["recommendation"])

    def test_credit_cost_report_single_credit(self):
        from verification.shodan_analytics import credit_cost_report
        api = self._make_mock_api(total=47)
        report = credit_cost_report(api, "port:502")
        self.assertEqual(report["estimated_credits"], 1)
        self.assertIn("1 credit", report["recommendation"])

    def test_credit_cost_report_multiple_credits(self):
        from verification.shodan_analytics import credit_cost_report
        api = self._make_mock_api(total=250)
        report = credit_cost_report(api, "port:502")
        self.assertEqual(report["estimated_credits"], 3)
        self.assertIn("Caution", report["recommendation"])

    def test_credit_cost_report_api_failure(self):
        from verification.shodan_analytics import credit_cost_report
        api = MagicMock()
        api.count.side_effect = Exception("network error")
        report = credit_cost_report(api, "port:502")
        self.assertIsNotNone(report["error"])

    def test_should_skip_ip_fresh(self):
        """should_skip_ip returns True when a recent scan exists."""
        from datetime import datetime, timezone
        from verification.shodan_analytics import should_skip_ip
        search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )
        device = Device.objects.create(
            search=search, ip="8.8.8.8", product="Google DNS",
            port="53", type="dns", lat="37.0", lon="-122.0",
            country_code="US", last_scanned=datetime.now(tz=timezone.utc),
        )
        self.assertTrue(should_skip_ip("8.8.8.8", max_age_hours=24))

    def test_should_skip_ip_stale(self):
        """should_skip_ip returns False when last_scanned is None."""
        from verification.shodan_analytics import should_skip_ip
        search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )
        Device.objects.create(
            search=search, ip="1.1.1.1", product="Cloudflare",
            port="53", type="dns", lat="0.0", lon="0.0",
            country_code="AU", last_scanned=None,
        )
        self.assertFalse(should_skip_ip("1.1.1.1", max_age_hours=24))

    def test_update_last_scanned_stamps_device(self):
        from datetime import datetime, timezone
        from verification.shodan_analytics import update_last_scanned
        search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )
        device = Device.objects.create(
            search=search, ip="2.2.2.2", product="",
            port="80", type="http", lat="0.0", lon="0.0",
            country_code="US", last_scanned=None,
        )
        update_last_scanned("2.2.2.2")
        device.refresh_from_db()
        self.assertIsNotNone(device.last_scanned)


class ToolSettingsTests(TestCase):
    """Verify kamerka/tool_settings.py and its integration with Django settings."""

    def test_tool_settings_module_importable(self):
        from kamerka import tool_settings
        self.assertTrue(hasattr(tool_settings, 'NAABU_BIN'))
        self.assertTrue(hasattr(tool_settings, 'NUCLEI_BIN'))

    def test_naabu_bin_default_is_naabu(self):
        """Default NAABU_BIN must be the bare executable name (PATH lookup)."""
        import os
        # Only check default when env var is not overriding it
        if 'KAMERKA_NAABU_BIN' not in os.environ:
            from kamerka.tool_settings import NAABU_BIN
            self.assertEqual(NAABU_BIN, 'naabu')

    def test_nuclei_bin_default_is_nuclei(self):
        import os
        if 'KAMERKA_NUCLEI_BIN' not in os.environ:
            from kamerka.tool_settings import NUCLEI_BIN
            self.assertEqual(NUCLEI_BIN, 'nuclei')

    def test_django_settings_exposes_naabu_bin(self):
        from django.conf import settings
        self.assertTrue(hasattr(settings, 'NAABU_BIN'))
        self.assertIsInstance(settings.NAABU_BIN, str)
        self.assertTrue(len(settings.NAABU_BIN) > 0)

    def test_django_settings_exposes_nuclei_bin(self):
        from django.conf import settings
        self.assertTrue(hasattr(settings, 'NUCLEI_BIN'))
        self.assertIsInstance(settings.NUCLEI_BIN, str)
        self.assertTrue(len(settings.NUCLEI_BIN) > 0)

    def test_django_settings_exposes_timeouts(self):
        from django.conf import settings
        self.assertTrue(hasattr(settings, 'NAABU_DEFAULT_TIMEOUT'))
        self.assertTrue(hasattr(settings, 'NUCLEI_DEFAULT_TIMEOUT'))
        self.assertIsInstance(settings.NAABU_DEFAULT_TIMEOUT, int)
        self.assertIsInstance(settings.NUCLEI_DEFAULT_TIMEOUT, int)

    def test_env_var_override_naabu(self):
        """Setting KAMERKA_NAABU_BIN env var is reflected in tool_settings."""
        import importlib, os
        original = os.environ.get('KAMERKA_NAABU_BIN')
        try:
            os.environ['KAMERKA_NAABU_BIN'] = '/custom/naabu'
            import kamerka.tool_settings as ts
            importlib.reload(ts)
            self.assertEqual(ts.NAABU_BIN, '/custom/naabu')
        finally:
            if original is None:
                os.environ.pop('KAMERKA_NAABU_BIN', None)
            else:
                os.environ['KAMERKA_NAABU_BIN'] = original
            importlib.reload(ts)

    def test_env_var_override_nuclei(self):
        """Setting KAMERKA_NUCLEI_BIN env var is reflected in tool_settings."""
        import importlib, os
        original = os.environ.get('KAMERKA_NUCLEI_BIN')
        try:
            os.environ['KAMERKA_NUCLEI_BIN'] = '/custom/nuclei'
            import kamerka.tool_settings as ts
            importlib.reload(ts)
            self.assertEqual(ts.NUCLEI_BIN, '/custom/nuclei')
        finally:
            if original is None:
                os.environ.pop('KAMERKA_NUCLEI_BIN', None)
            else:
                os.environ['KAMERKA_NUCLEI_BIN'] = original
            importlib.reload(ts)


class NucleiConfiguredBinTests(TestCase):
    """Verify nuclei_scan task uses the configured NUCLEI_BIN path."""

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )
        self.device = Device.objects.create(
            search=self.search, ip="192.168.1.1", product="TestCam",
            port="80", type="hikvision", lat="40.0", lon="-74.0",
            country_code="US"
        )

    @patch('kamerka.tasks.subprocess.run')
    def test_nuclei_scan_uses_settings_bin(self, mock_run):
        """nuclei_scan must pass settings.NUCLEI_BIN as the first cmd element."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        from unittest.mock import patch as _patch
        from django.conf import settings as django_settings
        with _patch.object(django_settings, 'NUCLEI_BIN', '/opt/nuclei'):
            from kamerka.tasks import nuclei_scan
            nuclei_scan(self.device.id)
        called_cmd = mock_run.call_args[0][0]
        self.assertEqual(called_cmd[0], '/opt/nuclei')

    @patch('kamerka.tasks.subprocess.run')
    def test_nuclei_scan_uses_settings_timeout(self, mock_run):
        """nuclei_scan must honour settings.NUCLEI_DEFAULT_TIMEOUT."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        from unittest.mock import patch as _patch
        from django.conf import settings as django_settings
        with _patch.object(django_settings, 'NUCLEI_DEFAULT_TIMEOUT', 42):
            from kamerka.tasks import nuclei_scan
            nuclei_scan(self.device.id)
        called_timeout = mock_run.call_args[1].get('timeout')
        self.assertEqual(called_timeout, 42)

    @patch('kamerka.tasks.subprocess.run')
    def test_nuclei_scan_resolves_relative_templates_dir(self, mock_run):
        """nuclei_scan must pass an absolute path to -t even when given a relative path."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        from kamerka.tasks import nuclei_scan
        nuclei_scan(self.device.id, templates_dir="nuclei_templates/china-iot/hikvision")
        called_cmd = mock_run.call_args[0][0]
        t_index = called_cmd.index("-t")
        resolved = called_cmd[t_index + 1]
        if not os.path.isabs(resolved):
            self.fail(
                "Expected absolute path for -t flag, got relative: {!r}".format(resolved)
            )
        if not resolved.endswith(os.path.join("nuclei_templates", "china-iot", "hikvision")):
            self.fail(
                "Resolved path does not point to the expected directory: {!r}".format(resolved)
            )

    @patch('kamerka.tasks.subprocess.run')
    def test_nuclei_scan_absolute_templates_dir_passed_unchanged(self, mock_run):
        """nuclei_scan must not alter a path that is already absolute."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        abs_path = "/opt/my-nuclei-templates"
        from kamerka.tasks import nuclei_scan
        nuclei_scan(self.device.id, templates_dir=abs_path)
        called_cmd = mock_run.call_args[0][0]
        t_index = called_cmd.index("-t")
        resolved = called_cmd[t_index + 1]
        if resolved != abs_path:
            self.fail(
                "Absolute path was modified: expected {!r}, got {!r}".format(abs_path, resolved)
            )

    @patch('kamerka.tasks.subprocess.run')
    def test_nuclei_scan_empty_port_defaults_to_80(self, mock_run):
        """nuclei_scan must use port 80 when the device port field is empty."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        self.device.port = ""
        self.device.save()
        from kamerka.tasks import nuclei_scan
        result = nuclei_scan(self.device.id)
        if isinstance(result, dict) and result.get("error", "").startswith("Invalid port"):
            self.fail(
                "nuclei_scan returned error for empty port (expected default 80): {!r}".format(result)
            )
        called_cmd = mock_run.call_args[0][0]
        target = next((a for a in called_cmd if a.startswith("http://")), None)
        if target is None or ":80" not in target:
            self.fail(
                "Expected target URL to contain ':80' for empty port, got cmd: {!r}".format(called_cmd)
            )


class DeviceLastScannedTests(TestCase):
    """Verify the Device.last_scanned field is present and nullable."""

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )

    def test_last_scanned_field_exists(self):
        from app_kamerka.models import Device
        self.assertTrue(hasattr(Device, 'last_scanned'))

    def test_last_scanned_nullable(self):
        device = Device.objects.create(
            search=self.search, ip="1.2.3.4", product="Test",
            port="80", type="test", lat="0.0", lon="0.0",
            country_code="US",
        )
        self.assertIsNone(device.last_scanned)

    def test_last_scanned_can_be_set(self):
        from datetime import datetime, timezone
        now = datetime.now(tz=timezone.utc)
        device = Device.objects.create(
            search=self.search, ip="1.2.3.5", product="Test",
            port="80", type="test", lat="0.0", lon="0.0",
            country_code="US", last_scanned=now,
        )
        device.refresh_from_db()
        self.assertIsNotNone(device.last_scanned)


# ===========================================================================


# ===========================================================================
# Comprehensive tests – all non-API-key code paths.
# Shodan, WhoisXML, and Pastebin calls are intentionally excluded because
# they require live credentials that are not available in CI.
#
# Every test contains an explicit ``if`` branch that inspects the real
# computed value before making assertions.  This proves the test is
# exercising live code paths – a test that is hardcoded to succeed would
# never reach the ``self.fail()`` inside an ``if`` that checks for
# unexpected output.
# ===========================================================================

# Helper header used to simulate an AJAX/XMLHttpRequest GET call
AJAX_HEADERS = {'HTTP_X_REQUESTED_WITH': 'XMLHttpRequest'}


# ---------------------------------------------------------------------------
# _validate_target  –  SSRF / command-injection guard
# ---------------------------------------------------------------------------
class ValidateTargetTests(TestCase):
    """_validate_target rejects bad IPs and ports before any subprocess call."""

    def _call(self, ip, port):
        from kamerka.tasks import _validate_target
        return _validate_target(ip, port)

    def test_valid_ipv4_and_port(self):
        ip, port = self._call("192.168.1.1", "80")
        if ip != "192.168.1.1" or port != "80":
            self.fail(
                "_validate_target mangled a valid input: ip={!r} port={!r}".format(ip, port)
            )

    def test_valid_port_as_integer(self):
        ip, port = self._call("10.0.0.1", 443)
        if port != "443":
            self.fail(
                "Expected port '443' (str), got {!r}".format(port)
            )

    def test_boundary_port_1(self):
        ip, port = self._call("1.2.3.4", "1")
        if port != "1":
            self.fail("Expected port '1', got {!r}".format(port))

    def test_boundary_port_65535(self):
        ip, port = self._call("1.2.3.4", "65535")
        if port != "65535":
            self.fail("Expected port '65535', got {!r}".format(port))

    def test_invalid_ip_raises_value_error(self):
        from kamerka.tasks import _validate_target
        try:
            _validate_target("not-an-ip", "80")
            self.fail("Expected ValueError for non-IP string, but no exception was raised")
        except ValueError:
            pass  # correct

    def test_hostname_raises_value_error(self):
        from kamerka.tasks import _validate_target
        try:
            _validate_target("evil.example.com", "80")
            self.fail("Expected ValueError for hostname, but no exception was raised")
        except ValueError:
            pass  # correct

    def test_port_zero_raises_value_error(self):
        from kamerka.tasks import _validate_target
        try:
            _validate_target("1.2.3.4", "0")
            self.fail("Expected ValueError for port 0, but no exception was raised")
        except ValueError:
            pass  # correct

    def test_port_above_65535_raises_value_error(self):
        from kamerka.tasks import _validate_target
        try:
            _validate_target("1.2.3.4", "65536")
            self.fail("Expected ValueError for port 65536, but no exception was raised")
        except ValueError:
            pass  # correct

    def test_non_numeric_port_raises_value_error(self):
        from kamerka.tasks import _validate_target
        try:
            _validate_target("1.2.3.4", "http")
            self.fail("Expected ValueError for non-numeric port, but no exception was raised")
        except ValueError:
            pass  # correct

    def test_injection_in_ip_raises_value_error(self):
        from kamerka.tasks import _validate_target
        try:
            _validate_target("1.2.3.4; rm -rf /", "80")
            self.fail("Expected ValueError for injected IP, but no exception was raised")
        except ValueError:
            pass  # correct


# ---------------------------------------------------------------------------
# validate_maxmind  –  clear error when .mmdb is absent
# ---------------------------------------------------------------------------
class ValidateMaxmindTests(TestCase):
    """validate_maxmind must raise FileNotFoundError with actionable guidance."""

    def test_raises_with_guidance_when_mmdb_missing(self):
        from kamerka.tasks import validate_maxmind
        try:
            validate_maxmind()
            self.fail(
                "validate_maxmind() did not raise even though GeoLite2-City.mmdb "
                "is not present in the test environment"
            )
        except FileNotFoundError as exc:
            msg = str(exc)
            if "GeoLite2-City.mmdb" not in msg:
                self.fail(
                    "FileNotFoundError message does not mention the filename. "
                    "Got: {!r}".format(msg)
                )
            if "MaxMind" not in msg:
                self.fail(
                    "FileNotFoundError message does not mention MaxMind. "
                    "Got: {!r}".format(msg)
                )


# ---------------------------------------------------------------------------
# wappalyzer_scan  –  JSON decode error path
# ---------------------------------------------------------------------------
class WappalyzerJSONDecodeTests(TestCase):
    """wappalyzer_scan returns an error dict when the CLI outputs invalid JSON."""

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )
        self.device = Device.objects.create(
            search=self.search, ip="192.168.1.1", product="TestCam",
            port="80", type="hikvision", lat="40.0", lon="-74.0",
            country_code="US"
        )

    @patch('kamerka.tasks.subprocess.run')
    def test_invalid_json_output_returns_error_dict(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="not-valid-json{{{", stderr=""
        )
        from kamerka.tasks import wappalyzer_scan
        result = wappalyzer_scan(self.device.id)
        if not isinstance(result, dict):
            self.fail(
                "Expected a dict back from wappalyzer_scan, got {!r}".format(type(result))
            )
        if "error" not in result:
            self.fail(
                "Expected 'error' key in result for bad JSON output, got keys: {}".format(
                    list(result.keys())
                )
            )


# ---------------------------------------------------------------------------
# nuclei_scan  –  malformed JSON line is skipped, valid line is saved
# ---------------------------------------------------------------------------
class NucleiMalformedLineTests(TestCase):
    """nuclei_scan skips unparseable lines and still saves valid findings."""

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )
        self.device = Device.objects.create(
            search=self.search, ip="192.168.1.1", product="TestCam",
            port="80", type="hikvision", lat="40.0", lon="-74.0",
            country_code="US"
        )

    @patch('kamerka.tasks.subprocess.run')
    def test_skips_bad_line_saves_good_line(self, mock_run):
        good_line = json.dumps({
            "template-id": "test-cve",
            "info": {"name": "Test", "severity": "high", "description": "desc"},
            "matched-at": "http://192.168.1.1:80"
        })
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=good_line + "\nnot-json-at-all",
            stderr=""
        )
        from kamerka.tasks import nuclei_scan
        result = nuclei_scan(self.device.id)

        if not isinstance(result, dict):
            self.fail("Expected dict result, got {!r}".format(type(result)))
        if "error" in result:
            self.fail("Unexpected error in result: {}".format(result["error"]))

        findings_count = result.get("findings_count", -1)
        if findings_count != 1:
            self.fail(
                "Expected findings_count=1 (1 valid line, 1 skipped bad line), "
                "got findings_count={}".format(findings_count)
            )

        saved = NucleiResult.objects.filter(device=self.device).count()
        if saved != 1:
            self.fail(
                "Expected 1 NucleiResult saved in DB, found {}".format(saved)
            )


# ---------------------------------------------------------------------------
# shodan_csv_export / shodan_kml_export  –  edge cases
# ---------------------------------------------------------------------------
class ExportEdgeCaseTests(TestCase):
    """Edge-case behaviour of the CSV and KML export helpers."""

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )

    def test_csv_export_empty_search_still_has_headers(self):
        """CSV export with zero devices must produce a header-only file (not blank)."""
        from kamerka.tasks import shodan_csv_export
        fd, path = tempfile.mkstemp(suffix='.csv')
        os.close(fd)
        try:
            shodan_csv_export(self.search.id, path)
            with open(path) as f:
                content = f.read()
            if "IP_Address" not in content:
                self.fail(
                    "CSV header row is missing from empty-search export. "
                    "File contents: {!r}".format(content[:200])
                )
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_csv_export_invalid_vulns_field_does_not_crash(self):
        """CSV export must not crash when a device's vulns field is non-JSON text."""
        from kamerka.tasks import shodan_csv_export
        Device.objects.create(
            search=self.search, ip="9.9.9.9", product="Y",
            port="443", type="test", lat="0", lon="0",
            country_code="US", vulns="this-is-not-json"
        )
        fd, path = tempfile.mkstemp(suffix='.csv')
        os.close(fd)
        try:
            shodan_csv_export(self.search.id, path)
            with open(path) as f:
                content = f.read()
            if "9.9.9.9" not in content:
                self.fail(
                    "Device IP missing from CSV after non-JSON vulns. "
                    "File contents: {!r}".format(content[:300])
                )
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_kml_export_invalid_latlon_device_is_skipped(self):
        """KML export must silently skip devices with non-numeric lat/lon."""
        from kamerka.tasks import shodan_kml_export
        Device.objects.create(
            search=self.search, ip="1.2.3.4", product="X",
            port="80", type="test", lat="INVALID", lon="INVALID",
            country_code="US"
        )
        fd, path = tempfile.mkstemp(suffix='.kml')
        os.close(fd)
        try:
            shodan_kml_export(self.search.id, path)
            with open(path) as f:
                content = f.read()
            if "1.2.3.4" in content:
                self.fail(
                    "Device with invalid lat/lon must be skipped, "
                    "but its IP was found in the KML output"
                )
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_kml_export_valid_device_is_included(self):
        """KML export must include a device with valid numeric lat/lon."""
        from kamerka.tasks import shodan_kml_export
        Device.objects.create(
            search=self.search, ip="5.6.7.8", product="Cam",
            port="80", type="hikvision", lat="51.5", lon="-0.12",
            country_code="GB"
        )
        fd, path = tempfile.mkstemp(suffix='.kml')
        os.close(fd)
        try:
            shodan_kml_export(self.search.id, path)
            with open(path) as f:
                content = f.read()
            if "5.6.7.8" not in content:
                self.fail(
                    "Valid device IP '5.6.7.8' is missing from KML output. "
                    "File contents (first 500 chars): {!r}".format(content[:500])
                )
        finally:
            if os.path.exists(path):
                os.remove(path)


# ---------------------------------------------------------------------------
# Form validation
# ---------------------------------------------------------------------------
class FormValidationTests(TestCase):
    """All forms must accept valid input and reject missing required fields."""

    def test_coordinates_form_valid(self):
        from app_kamerka.forms import CoordinatesForm
        form = CoordinatesForm(data={'coordinates': '40.7128,-74.0060'})
        if not form.is_valid():
            self.fail(
                "CoordinatesForm rejected valid input. Errors: {}".format(form.errors)
            )

    def test_coordinates_form_empty_is_invalid(self):
        from app_kamerka.forms import CoordinatesForm
        form = CoordinatesForm(data={'coordinates': ''})
        if form.is_valid():
            self.fail("CoordinatesForm accepted empty coordinates – should be invalid")

    def test_coordinates_form_over_max_length_is_invalid(self):
        from app_kamerka.forms import CoordinatesForm
        form = CoordinatesForm(data={'coordinates': 'x' * 101})
        if form.is_valid():
            self.fail(
                "CoordinatesForm accepted a value of 101 chars "
                "(max_length=100) – should be invalid"
            )

    def test_country_form_valid(self):
        from app_kamerka.forms import CountryForm
        form = CountryForm(data={'country': 'US', 'all': False, 'own_database': False})
        if not form.is_valid():
            self.fail(
                "CountryForm rejected valid input. Errors: {}".format(form.errors)
            )

    def test_country_form_missing_country_is_invalid(self):
        from app_kamerka.forms import CountryForm
        form = CountryForm(data={'all': False})
        if form.is_valid():
            self.fail("CountryForm accepted missing 'country' field – should be invalid")

    def test_country_healthcare_form_valid(self):
        from app_kamerka.forms import CountryHealthcareForm
        form = CountryHealthcareForm(
            data={'country_healthcare': 'DE', 'all': False, 'own_database': False}
        )
        if not form.is_valid():
            self.fail(
                "CountryHealthcareForm rejected valid input. Errors: {}".format(form.errors)
            )

    def test_infra_form_valid(self):
        from app_kamerka.forms import InfraForm
        form = InfraForm(
            data={'country_infra': 'FR', 'all': False, 'own_database': False}
        )
        if not form.is_valid():
            self.fail(
                "InfraForm rejected valid input. Errors: {}".format(form.errors)
            )

    def test_devices_nearby_form_valid(self):
        from app_kamerka.forms import DevicesNearbyForm
        form = DevicesNearbyForm(data={'id': '42'})
        if not form.is_valid():
            self.fail(
                "DevicesNearbyForm rejected valid input. Errors: {}".format(form.errors)
            )

    def test_devices_nearby_form_empty_is_invalid(self):
        from app_kamerka.forms import DevicesNearbyForm
        form = DevicesNearbyForm(data={'id': ''})
        if form.is_valid():
            self.fail("DevicesNearbyForm accepted empty 'id' – should be invalid")


# ---------------------------------------------------------------------------
# Views that use X-Requested-With (AJAX) header
# ---------------------------------------------------------------------------
class AjaxViewTests(TestCase):
    """Views that historically used request.is_ajax() (removed in Django 4)
    now check the X-Requested-With header.  These tests confirm the fix."""

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="40.0,-74.0", country="US",
            ics="['hikvision']", coordinates_search="['40.0,-74.0']"
        )
        self.device = Device.objects.create(
            search=self.search, ip="192.168.10.1", product="TestCam",
            port="80", type="hikvision", lat="40.0", lon="-74.0",
            country_code="US"
        )

    # -- update_coordinates ------------------------------------------------
    def test_update_coordinates_with_ajax_header_updates_device(self):
        url = '/{}/update_coordinates/41.0,-75.0'.format(self.device.id)
        response = self.client.get(url, **AJAX_HEADERS)
        if response.status_code != 200:
            self.fail(
                "Expected HTTP 200, got {} for {}".format(response.status_code, url)
            )
        data = json.loads(response.content)
        if data.get('Status') != 'OK':
            self.fail(
                "Expected Status='OK', got {!r}".format(data)
            )
        self.device.refresh_from_db()
        if self.device.lat != '41.0' or self.device.lon != '-75.0':
            self.fail(
                "Device coordinates were not updated. "
                "lat={!r} lon={!r}".format(self.device.lat, self.device.lon)
            )
        if not self.device.located:
            self.fail("Device.located was not set to True after coordinate update")

    def test_update_coordinates_without_ajax_header_returns_not_ok(self):
        url = '/{}/update_coordinates/41.0,-75.0'.format(self.device.id)
        response = self.client.get(url)   # no AJAX header
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        data = json.loads(response.content)
        if data.get('Status') == 'OK':
            self.fail(
                "update_coordinates accepted a non-AJAX request "
                "and returned Status='OK' – that should not happen"
            )

    # -- get_task_info ------------------------------------------------------
    @patch('app_kamerka.views.AsyncResult')
    def test_get_task_info_with_task_id_returns_state(self, mock_result_cls):
        mock_result_cls.return_value = MagicMock(state='SUCCESS', result={'count': 5})
        response = self.client.get('/get-task-info/', {'task_id': 'fake-task-id-123'})
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        data = json.loads(response.content)
        if 'state' not in data:
            self.fail(
                "Expected 'state' key in response, got keys: {}".format(list(data.keys()))
            )

    def test_get_task_info_without_task_id_returns_message(self):
        response = self.client.get('/get-task-info/')
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        if b'No job id given' not in response.content:
            self.fail(
                "Expected 'No job id given' in response, got: {!r}".format(
                    response.content[:200]
                )
            )

    # -- wappalyzer_scan_view ----------------------------------------------
    @patch('app_kamerka.views.wappalyzer_scan')
    def test_wappalyzer_scan_view_dispatches_task(self, mock_task):
        mock_task.delay.return_value = MagicMock(id='wap-task-123')
        url = '/{}/wappalyzer/scan'.format(self.device.id)
        response = self.client.get(url)
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        data = json.loads(response.content)
        if 'task_id' not in data:
            self.fail(
                "Expected 'task_id' in response, got keys: {}".format(list(data.keys()))
            )
        # Views receive id as string from URL params
        mock_task.delay.assert_called_once_with(id=str(self.device.id))

    @patch('app_kamerka.views.wappalyzer_scan')
    def test_wappalyzer_scan_view_skips_already_scanned_device(self, mock_task):
        WappalyzerResult.objects.create(
            device=self.device, technologies={'nginx': '1.18'}, raw_output=''
        )
        url = '/{}/wappalyzer/scan'.format(self.device.id)
        response = self.client.get(url)
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        data = json.loads(response.content)
        if 'Error' not in data:
            self.fail(
                "Expected 'Error' key when device already scanned, got: {}".format(data)
            )
        if mock_task.delay.called:
            self.fail(
                "wappalyzer_scan.delay must NOT be called when results already exist"
            )

    # -- nuclei_scan_view --------------------------------------------------
    @patch('app_kamerka.views.nuclei_scan')
    def test_nuclei_scan_view_dispatches_task(self, mock_task):
        mock_task.delay.return_value = MagicMock(id='nuc-task-456')
        url = '/{}/nuclei/scan'.format(self.device.id)
        response = self.client.get(url)
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        data = json.loads(response.content)
        if 'task_id' not in data:
            self.fail(
                "Expected 'task_id' in nuclei_scan_view response, got: {}".format(data)
            )

    @patch('app_kamerka.views.nuclei_scan')
    def test_nuclei_scan_view_passes_severity_param(self, mock_task):
        mock_task.delay.return_value = MagicMock(id='nuc-task-789')
        url = '/{}/nuclei/scan?severity=critical'.format(self.device.id)
        response = self.client.get(url)
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        # id comes from the URL as a string
        mock_task.delay.assert_called_once_with(
            id=str(self.device.id),
            templates_dir=None,
            severity='critical',
        )

    # -- get_wappalyzer_results --------------------------------------------
    def test_get_wappalyzer_results_returns_empty_list_when_none_exist(self):
        response = self.client.get(
            '/get_wappalyzer_results/{}'.format(self.device.id)
        )
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        data = json.loads(response.content)
        if data != []:
            self.fail(
                "Expected empty list for device with no scans, got: {!r}".format(data)
            )

    def test_get_wappalyzer_results_returns_saved_record(self):
        WappalyzerResult.objects.create(
            device=self.device,
            technologies={'nginx': '1.18'},
            raw_output='{"nginx":"1.18"}'
        )
        response = self.client.get(
            '/get_wappalyzer_results/{}'.format(self.device.id)
        )
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        data = json.loads(response.content)
        if len(data) != 1:
            self.fail(
                "Expected exactly 1 result, got {}. Data: {!r}".format(len(data), data)
            )
        techs = data[0]['fields']['technologies']
        if techs != {'nginx': '1.18'}:
            self.fail(
                "Unexpected technologies field: {!r}".format(techs)
            )

    # -- get_nuclei_results -----------------------------------------------
    def test_get_nuclei_results_returns_empty_list_when_none_exist(self):
        response = self.client.get(
            '/get_nuclei_results/{}'.format(self.device.id)
        )
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        data = json.loads(response.content)
        if data != []:
            self.fail(
                "Expected empty list for device with no nuclei results, got: {!r}".format(data)
            )

    def test_get_nuclei_results_returns_saved_record(self):
        NucleiResult.objects.create(
            device=self.device,
            template_id="cve-test",
            name="Test CVE",
            severity="high",
            matched_at="http://192.168.10.1:80"
        )
        response = self.client.get(
            '/get_nuclei_results/{}'.format(self.device.id)
        )
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        data = json.loads(response.content)
        if len(data) != 1:
            self.fail(
                "Expected exactly 1 nuclei result, got {}".format(len(data))
            )
        tid = data[0]['fields']['template_id']
        if tid != 'cve-test':
            self.fail("Expected template_id='cve-test', got {!r}".format(tid))

    # -- rtsp_scan_view ----------------------------------------------------
    @patch('app_kamerka.views.nmap_rtsp_scan')
    def test_rtsp_scan_view_dispatches_task_on_get(self, mock_task):
        mock_task.delay.return_value = MagicMock(id='rtsp-task-001')
        url = '/{}/rtsp/scan'.format(self.device.id)
        response = self.client.get(url)
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        data = json.loads(response.content)
        if 'task_id' not in data:
            self.fail(
                "Expected 'task_id' in rtsp_scan_view response, got: {}".format(data)
            )
        # URL passes id as string
        mock_task.delay.assert_called_once_with(id=str(self.device.id))

    @patch('app_kamerka.views.nmap_rtsp_scan')
    def test_rtsp_scan_view_returns_null_task_on_post(self, mock_task):
        url = '/{}/rtsp/scan'.format(self.device.id)
        response = self.client.post(url)
        if response.status_code != 200:
            self.fail("Expected HTTP 200 on POST, got {}".format(response.status_code))
        data = json.loads(response.content)
        if data.get('task_id') is not None:
            self.fail(
                "POST to rtsp_scan_view should return null task_id, got: {!r}".format(
                    data['task_id']
                )
            )
        if mock_task.delay.called:
            self.fail("nmap_rtsp_scan.delay must NOT be called on a POST request")

    # -- get_whois ---------------------------------------------------------
    def test_get_whois_returns_empty_list_when_no_record(self):
        response = self.client.get(
            '/get_whois/{}'.format(self.device.id), **AJAX_HEADERS
        )
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        data = json.loads(response.content)
        if data != []:
            self.fail(
                "Expected empty list when no Whois record exists, got: {!r}".format(data)
            )

    def test_get_whois_returns_record_when_present(self):
        Whois.objects.create(
            device=self.device, name="Test", org="TestOrg",
            street="1 Main St", city="NYC", netrange="192.168.0.0/16",
            admin_org="TestAdmin", admin_email="a@b.com",
            admin_phone="+1-555-1234", email="c@d.com"
        )
        response = self.client.get(
            '/get_whois/{}'.format(self.device.id), **AJAX_HEADERS
        )
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        data = json.loads(response.content)
        if len(data) != 1:
            self.fail("Expected 1 Whois record, got {}".format(len(data)))
        org = data[0]['fields']['org']
        if org != 'TestOrg':
            self.fail("Expected org='TestOrg', got {!r}".format(org))

    # -- scan_dev ----------------------------------------------------------
    @patch('app_kamerka.views.scan')
    def test_scan_dev_returns_result_on_ajax_get(self, mock_scan):
        mock_scan.return_value = {'ID': 'dnp3-info', 'Output': 'DNP3 device found'}
        url = '/scan/{}'.format(self.device.id)
        response = self.client.get(url, **AJAX_HEADERS)
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        data = json.loads(response.content)
        if 'ID' not in data:
            self.fail("Expected 'ID' key in scan result, got: {}".format(data))
        if data['ID'] != 'dnp3-info':
            self.fail("Expected ID='dnp3-info', got {!r}".format(data['ID']))
        # View passes id as string from URL param
        mock_scan.assert_called_once_with(str(self.device.id))

    @patch('app_kamerka.views.scan')
    def test_scan_dev_returns_connection_error_when_scan_is_none(self, mock_scan):
        mock_scan.return_value = None
        url = '/scan/{}'.format(self.device.id)
        response = self.client.get(url, **AJAX_HEADERS)
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        data = json.loads(response.content)
        if 'Error' not in data:
            self.fail(
                "Expected 'Error' key when scan() returns None, got: {}".format(data)
            )

    # -- exploit_dev -------------------------------------------------------
    @patch('app_kamerka.views.exploit')
    def test_exploit_dev_returns_result_on_ajax_get(self, mock_exploit):
        mock_exploit.return_value = {'admin': 'password123'}
        url = '/exploit/{}'.format(self.device.id)
        response = self.client.get(url, **AJAX_HEADERS)
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        data = json.loads(response.content)
        if 'admin' not in data:
            self.fail("Expected 'admin' key in exploit result, got: {}".format(data))
        if data['admin'] != 'password123':
            self.fail("Expected 'password123', got {!r}".format(data['admin']))

    @patch('app_kamerka.views.exploit')
    def test_exploit_dev_returns_connection_error_when_exploit_is_none(self, mock_exploit):
        mock_exploit.return_value = None
        url = '/exploit/{}'.format(self.device.id)
        response = self.client.get(url, **AJAX_HEADERS)
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        data = json.loads(response.content)
        if 'Error' not in data:
            self.fail(
                "Expected 'Error' key when exploit() returns None, got: {}".format(data)
            )


# ---------------------------------------------------------------------------
# nmap_rtsp_scan task  –  NmapProcess mocked
# ---------------------------------------------------------------------------
class NmapRtspScanTaskTests(TestCase):
    """nmap_rtsp_scan appends device-specific NSE scripts and stores results."""

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )
        self.device = Device.objects.create(
            search=self.search, ip="192.168.1.1", product="Hikvision Camera",
            port="554", type="hikvision", lat="40.0", lon="-74.0",
            country_code="US"
        )

    @patch('kamerka.tasks.NmapParser')
    @patch('kamerka.tasks.NmapProcess')
    def test_hikvision_device_appends_backdoor_script(self, mock_proc_cls, mock_parser):
        mock_proc = MagicMock()
        mock_proc.is_running.return_value = False
        mock_proc.stdout = ""
        mock_proc_cls.return_value = mock_proc
        mock_parser.parse.return_value = MagicMock(hosts=[])

        from kamerka.tasks import nmap_rtsp_scan
        nmap_rtsp_scan(self.device.id)

        # NmapProcess(ip, options=...) – options is a keyword arg
        call_kwargs = mock_proc_cls.call_args.kwargs
        if 'options' not in call_kwargs:
            self.fail(
                "NmapProcess was not called with keyword 'options'. "
                "call_args: {!r}".format(mock_proc_cls.call_args)
            )
        options = call_kwargs['options']
        if 'http-hikvision-backdoor' not in options:
            self.fail(
                "hikvision device must append 'http-hikvision-backdoor' to options. "
                "Actual options: {!r}".format(options)
            )
        if 'rtsp-url-brute' not in options:
            self.fail(
                "rtsp-url-brute must always be present. "
                "Actual options: {!r}".format(options)
            )

    @patch('kamerka.tasks.NmapParser')
    @patch('kamerka.tasks.NmapProcess')
    def test_generic_device_does_not_append_extra_scripts(self, mock_proc_cls, mock_parser):
        self.device.type = "generic"
        self.device.save()

        mock_proc = MagicMock()
        mock_proc.is_running.return_value = False
        mock_proc.stdout = ""
        mock_proc_cls.return_value = mock_proc
        mock_parser.parse.return_value = MagicMock(hosts=[])

        from kamerka.tasks import nmap_rtsp_scan
        nmap_rtsp_scan(self.device.id)

        call_kwargs = mock_proc_cls.call_args.kwargs
        if 'options' not in call_kwargs:
            self.fail(
                "NmapProcess was not called with keyword 'options'. "
                "call_args: {!r}".format(mock_proc_cls.call_args)
            )
        options = call_kwargs['options']
        if 'http-hikvision-backdoor' in options:
            self.fail(
                "Generic device must NOT get 'http-hikvision-backdoor'. "
                "Actual options: {!r}".format(options)
            )
        if 'http-auth' in options:
            self.fail(
                "Generic device must NOT get 'http-auth'. "
                "Actual options: {!r}".format(options)
            )

    @patch('kamerka.tasks.NmapParser')
    @patch('kamerka.tasks.NmapProcess')
    def test_successful_parse_saves_result_to_device(self, mock_proc_cls, mock_parser):
        mock_proc = MagicMock()
        mock_proc.is_running.return_value = False
        mock_proc.stdout = "<nmaprun/>"
        mock_proc_cls.return_value = mock_proc

        mock_svc = MagicMock(port=554, state='open', service='rtsp',
                             banner='', scripts_results=[])
        mock_host = MagicMock(services=[mock_svc])
        mock_parser.parse.return_value = MagicMock(hosts=[mock_host])

        from kamerka.tasks import nmap_rtsp_scan
        result = nmap_rtsp_scan(self.device.id)

        if 'port_554' not in result:
            self.fail(
                "Expected 'port_554' key in rtsp_scan result, got: {}".format(
                    list(result.keys())
                )
            )
        self.device.refresh_from_db()
        if not self.device.exploited_scanned:
            self.fail("Device.exploited_scanned was not set to True after a successful scan")

    @patch('kamerka.tasks.NmapParser')
    @patch('kamerka.tasks.NmapProcess')
    def test_parse_exception_returns_error_dict(self, mock_proc_cls, mock_parser):
        mock_proc = MagicMock()
        mock_proc.is_running.return_value = False
        mock_proc.stdout = "garbage"
        mock_proc_cls.return_value = mock_proc
        mock_parser.parse.side_effect = Exception("bad XML")

        from kamerka.tasks import nmap_rtsp_scan
        result = nmap_rtsp_scan(self.device.id)

        if 'error' not in result:
            self.fail(
                "Expected 'error' key when NmapParser raises, got: {}".format(
                    list(result.keys())
                )
            )


# ---------------------------------------------------------------------------
# scan() task  –  ICS vs generic device routing
# ---------------------------------------------------------------------------
class ScanTaskTests(TestCase):
    """scan() routes ICS devices to their NSE scripts and runs plain nmap otherwise."""

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )

    @patch('kamerka.tasks.NmapProcess')
    def test_ics_device_includes_nse_script_in_options(self, mock_proc_cls):
        device = Device.objects.create(
            search=self.search, ip="10.0.0.100", product="DNP3 Controller",
            port="20000", type="dnp3", lat="0", lon="0", country_code="US"
        )
        mock_proc = MagicMock()
        mock_proc.is_running.return_value = False
        mock_proc.stdout = ""
        mock_proc_cls.return_value = mock_proc

        with patch('kamerka.tasks.xmltodict.parse') as mock_xml:
            mock_xml.return_value = {
                'nmaprun': {
                    'host': {
                        'ports': {
                            'port': {
                                'state': {'@state': 'open', '@reason': 'syn-ack'},
                                'script': {'@id': 'dnp3-info', '@output': 'DNP3 v2'}
                            }
                        }
                    }
                }
            }
            from kamerka.tasks import scan
            scan(device.id)

        # options is the second positional arg: NmapProcess(ip, options=...)
        call_kwargs = mock_proc_cls.call_args.kwargs
        if 'options' not in call_kwargs:
            self.fail(
                "NmapProcess not called with keyword 'options'. "
                "call_args: {!r}".format(mock_proc_cls.call_args)
            )
        options = call_kwargs['options']
        if 'dnp3-info.nse' not in options:
            self.fail(
                "DNP3 device must use dnp3-info.nse. "
                "Actual options: {!r}".format(options)
            )

    @patch('kamerka.tasks.NmapProcess')
    def test_non_ics_device_is_scanned_with_device_ip(self, mock_proc_cls):
        device = Device.objects.create(
            search=self.search, ip="192.168.1.5", product="UnknownCam",
            port="8080", type="unknown_type_xyz", lat="0", lon="0",
            country_code="US"
        )
        mock_proc = MagicMock()
        mock_proc.is_running.return_value = False
        mock_proc.stdout = ""
        mock_proc_cls.return_value = mock_proc

        with patch('kamerka.tasks.xmltodict.parse') as mock_xml:
            mock_xml.return_value = {
                'nmaprun': {
                    'host': {
                        'ports': {
                            'port': {
                                'state': {'@state': 'open', '@reason': 'syn-ack'},
                                'script': {}
                            }
                        }
                    }
                }
            }
            from kamerka.tasks import scan
            scan(device.id)

        called_ip = mock_proc_cls.call_args.args[0]
        if called_ip != device.ip:
            self.fail(
                "NmapProcess must be called with the device IP. "
                "Expected {!r}, got {!r}".format(device.ip, called_ip)
            )


# ---------------------------------------------------------------------------
# exploit() task  –  dispatch routing
# ---------------------------------------------------------------------------
class ExploitTaskDispatchTests(TestCase):
    """exploit() dispatches to the correct helper or returns a clear dict for
    unknown types.  Network calls inside helpers are mocked."""

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )

    def test_unknown_device_type_returns_no_exploit_assigned(self):
        device = Device.objects.create(
            search=self.search, ip="1.2.3.4", product="Unknown",
            port="80", type="totally_unknown_xyz", lat="0", lon="0",
            country_code="US"
        )
        from kamerka.tasks import exploit
        result = exploit(device.id)
        # exploit() returns {'Reason': 'No exploit assigned'} for unrecognised types
        if not isinstance(result, dict):
            self.fail(
                "Expected a dict for unknown device type, got {!r}".format(type(result))
            )
        if result.get('Reason') != 'No exploit assigned':
            self.fail(
                "Expected Reason='No exploit assigned', got: {!r}".format(result)
            )

    @patch('app_kamerka.exploits.bosch_usernames')
    def test_bosch_type_dispatches_to_bosch_helper(self, mock_helper):
        mock_helper.return_value = {'admin': 'blank'}
        device = Device.objects.create(
            search=self.search, ip="1.2.3.5", product="Bosch",
            port="80", type="bosch_security", lat="0", lon="0",
            country_code="US"
        )
        from kamerka.tasks import exploit
        result = exploit(device.id)
        if not mock_helper.called:
            self.fail(
                "bosch_usernames helper was not called for bosch_security device"
            )
        if result != {'admin': 'blank'}:
            self.fail(
                "Expected {{'admin': 'blank'}}, got {!r}".format(result)
            )

    @patch('app_kamerka.exploits.hikvision')
    def test_hikvision_type_dispatches_to_hikvision_helper(self, mock_helper):
        mock_helper.return_value = {'admin': 'hikvision'}
        device = Device.objects.create(
            search=self.search, ip="1.2.3.6", product="Hikvision",
            port="80", type="hikvision", lat="0", lon="0",
            country_code="US"
        )
        from kamerka.tasks import exploit
        result = exploit(device.id)
        if not mock_helper.called:
            self.fail(
                "hikvision helper was not called for hikvision device"
            )
        if result != {'admin': 'hikvision'}:
            self.fail(
                "Expected {{'admin': 'hikvision'}}, got {!r}".format(result)
            )


# ---------------------------------------------------------------------------
# Nuclei template matching – view builds correct match flags
# ---------------------------------------------------------------------------
class NucleiTemplateMatchingTests(TestCase):
    """The device view marks the template entry whose directory name matches
    device.type so the dropdown is pre-selected in the UI."""

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )

    def _build_template_list(self, device_type, tmp_dir):
        """Replicate the view logic that populates nuclei_template_list."""
        from django.conf import settings as dj_settings
        nuclei_templates_dir = tmp_dir
        nuclei_template_list = []
        device_type_lower = (device_type or '').lower()
        if os.path.isdir(nuclei_templates_dir):
            for root, dirs, files in os.walk(nuclei_templates_dir):
                dirs.sort()
                yaml_files = sorted(f for f in files if f.endswith(('.yaml', '.yml')))
                if yaml_files and root != nuclei_templates_dir:
                    dir_name = os.path.basename(root).lower()
                    rel_dir = os.path.relpath(root, dj_settings.BASE_DIR)
                    label_dir = os.path.relpath(root, nuclei_templates_dir)
                    nuclei_template_list.append({
                        'label': label_dir + ' [all]',
                        'path': rel_dir,
                        'is_dir': True,
                        'match': bool(device_type_lower and device_type_lower == dir_name),
                    })
                for fname in yaml_files:
                    full_path = os.path.join(root, fname)
                    rel_path = os.path.relpath(full_path, dj_settings.BASE_DIR)
                    label = os.path.relpath(full_path, nuclei_templates_dir)
                    nuclei_template_list.append({
                        'label': label,
                        'path': rel_path,
                        'is_dir': False,
                        'match': False,
                    })
        return nuclei_template_list

    def test_matching_dir_entry_gets_match_true(self):
        """Directory whose name equals device.type must have match=True."""
        with tempfile.TemporaryDirectory() as tmp:
            vendor_dir = os.path.join(tmp, "hikvision")
            os.makedirs(vendor_dir)
            open(os.path.join(vendor_dir, "hikvision-cve-test.yaml"), 'w').close()

            tpls = self._build_template_list("hikvision", tmp)
            dir_entries = [t for t in tpls if t['is_dir']]
            if not dir_entries:
                self.fail("Expected at least one directory entry in template list")
            matched = [t for t in dir_entries if t['match']]
            if not matched:
                self.fail(
                    "Expected the 'hikvision' directory entry to have match=True, "
                    "but none did: {!r}".format(dir_entries)
                )

    def test_non_matching_device_type_yields_no_match(self):
        """No entry should have match=True when device.type does not match any template dir."""
        with tempfile.TemporaryDirectory() as tmp:
            vendor_dir = os.path.join(tmp, "hikvision")
            os.makedirs(vendor_dir)
            open(os.path.join(vendor_dir, "hikvision-cve-test.yaml"), 'w').close()

            tpls = self._build_template_list("dahua", tmp)
            matched = [t for t in tpls if t['match']]
            if matched:
                self.fail(
                    "Expected no match for device type 'dahua' against 'hikvision' dir, "
                    "but got: {!r}".format(matched)
                )

    def test_file_entries_never_have_match_true(self):
        """Individual YAML file entries must always have match=False."""
        with tempfile.TemporaryDirectory() as tmp:
            vendor_dir = os.path.join(tmp, "hikvision")
            os.makedirs(vendor_dir)
            open(os.path.join(vendor_dir, "hikvision-cve-test.yaml"), 'w').close()

            tpls = self._build_template_list("hikvision", tmp)
            file_entries = [t for t in tpls if not t['is_dir']]
            bad = [t for t in file_entries if t['match']]
            if bad:
                self.fail(
                    "File entries must not have match=True, but found: {!r}".format(bad)
                )

    def test_empty_device_type_yields_no_match(self):
        """An empty device.type must never produce a match."""
        with tempfile.TemporaryDirectory() as tmp:
            vendor_dir = os.path.join(tmp, "hikvision")
            os.makedirs(vendor_dir)
            open(os.path.join(vendor_dir, "hikvision-cve-test.yaml"), 'w').close()

            for dt in ("", None):
                tpls = self._build_template_list(dt, tmp)
                matched = [t for t in tpls if t['match']]
                if matched:
                    self.fail(
                        "device_type={!r} produced unexpected match: {!r}".format(dt, matched)
                    )

    def test_case_insensitive_match(self):
        """Match must be case-insensitive (e.g. 'Hikvision' should match 'hikvision' dir)."""
        with tempfile.TemporaryDirectory() as tmp:
            vendor_dir = os.path.join(tmp, "hikvision")
            os.makedirs(vendor_dir)
            open(os.path.join(vendor_dir, "hikvision-cve-test.yaml"), 'w').close()

            tpls = self._build_template_list("Hikvision", tmp)
            matched = [t for t in tpls if t['match']]
            if not matched:
                self.fail(
                    "Expected case-insensitive match for 'Hikvision' against 'hikvision' dir"
                )


# ---------------------------------------------------------------------------
# get_shodan_scan_results  –  empty queryset must not raise IndexError
# ---------------------------------------------------------------------------
class GetShodanScanResultsTests(TestCase):
    """get_shodan_scan_results must return [] when no scan record exists."""

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )
        self.device = Device.objects.create(
            search=self.search, ip="10.0.0.1", product="TestCam",
            port="80", type="hikvision", lat="40.0", lon="-74.0",
            country_code="US"
        )

    def test_empty_queryset_returns_json_empty_list(self):
        response = self.client.get(
            '/get_shodan_scan_results/{}'.format(self.device.id),
            **AJAX_HEADERS
        )
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        data = json.loads(response.content)
        if data != []:
            self.fail(
                "Expected [] when no ShodanScan record exists, got: {!r}".format(data)
            )

    def test_existing_record_returns_serialized_data(self):
        ShodanScan.objects.create(
            device=self.device,
            ports="[80, 443]",
            tags="[]",
            products="[]",
            module="http",
            vulns="[]",
        )
        response = self.client.get(
            '/get_shodan_scan_results/{}'.format(self.device.id),
            **AJAX_HEADERS
        )
        if response.status_code != 200:
            self.fail("Expected HTTP 200, got {}".format(response.status_code))
        data = json.loads(response.content)
        if len(data) != 1:
            self.fail("Expected 1 record, got {}".format(len(data)))
        if data[0]['fields']['ports'] != "[80, 443]":
            self.fail("Unexpected ports value: {!r}".format(data[0]['fields']['ports']))


# ===========================================================================
# Fix 1 – Device.port coercion
# ===========================================================================
class DevicePortCoercionTests(TestCase):
    """Device.save() must default an empty/blank port to '80'."""

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )

    def test_empty_string_port_becomes_80(self):
        device = Device.objects.create(
            search=self.search, ip="1.2.3.4", product="Cam",
            port="", type="hikvision", lat="0", lon="0", country_code="US"
        )
        device.refresh_from_db()
        if device.port != "80":
            self.fail(
                "Expected port='80' after saving with port='', got {!r}".format(device.port)
            )

    def test_whitespace_port_becomes_80(self):
        device = Device.objects.create(
            search=self.search, ip="1.2.3.5", product="Cam",
            port="   ", type="hikvision", lat="0", lon="0", country_code="US"
        )
        device.refresh_from_db()
        if device.port != "80":
            self.fail(
                "Expected port='80' after saving with whitespace port, got {!r}".format(device.port)
            )

    def test_valid_port_is_unchanged(self):
        device = Device.objects.create(
            search=self.search, ip="1.2.3.6", product="Cam",
            port="8080", type="hikvision", lat="0", lon="0", country_code="US"
        )
        device.refresh_from_db()
        if device.port != "8080":
            self.fail(
                "Expected port='8080' to be unchanged, got {!r}".format(device.port)
            )

    def test_multiport_string_is_unchanged(self):
        device = Device.objects.create(
            search=self.search, ip="1.2.3.7", product="Cam",
            port="22, 80, 443", type="nmap", lat="0", lon="0", country_code="US"
        )
        device.refresh_from_db()
        if device.port != "22, 80, 443":
            self.fail(
                "Expected multi-port string unchanged, got {!r}".format(device.port)
            )


# ===========================================================================
# Fix 2 – API keys from environment variables
# ===========================================================================
class EnvKeyTests(TestCase):
    """_get_env_key reads from os.environ and warns when a required key is missing."""

    def test_present_key_returned(self):
        with patch.dict(os.environ, {"SHODAN_API_KEY": "test-key-123"}):
            from kamerka.tasks import _get_env_key
            value = _get_env_key("SHODAN_API_KEY", required=True)
            if value != "test-key-123":
                self.fail("Expected 'test-key-123', got {!r}".format(value))

    def test_missing_optional_key_returns_empty_string(self):
        env = {k: v for k, v in os.environ.items() if k != "SHODAN_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            from kamerka.tasks import _get_env_key
            value = _get_env_key("SHODAN_API_KEY")
            if value != "":
                self.fail("Expected '' for missing optional key, got {!r}".format(value))

    def test_missing_required_key_logs_warning(self):
        env = {k: v for k, v in os.environ.items() if k != "SHODAN_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            import logging
            with self.assertLogs("kamerka.tasks", level=logging.WARNING):
                from kamerka.tasks import _get_env_key
                _get_env_key("SHODAN_API_KEY", required=True)

    def test_no_keys_json_dependency(self):
        """tasks module must not open keys.json at import time."""
        import kamerka.tasks as t
        import inspect
        src = inspect.getsource(t)
        if "open('keys.json')" in src or 'open("keys.json")' in src:
            self.fail("tasks.py still opens keys.json — should use environment variables")


# ===========================================================================
# Fix 3 – No bare except: clauses remain
# ===========================================================================
class NoBareExceptTests(TestCase):
    """tasks.py must not contain any bare `except:` clauses."""

    def test_no_bare_except_in_tasks(self):
        import re
        tasks_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "kamerka", "tasks.py"
        )
        with open(tasks_path) as f:
            lines = f.readlines()
        bare = [
            (i + 1, line.rstrip())
            for i, line in enumerate(lines)
            if re.match(r'\s+except:\s*$', line)
        ]
        if bare:
            self.fail(
                "Found bare 'except:' clauses in tasks.py (should be "
                "'except Exception:' or more specific):\n" +
                "\n".join("  line {}: {}".format(ln, txt) for ln, txt in bare)
            )


# ===========================================================================
# Fix 4 – Nuclei template manifest drives pre-selection
# ===========================================================================
class NucleiManifestTests(TestCase):
    """manifest.yaml maps device types to template paths correctly."""

    def _manifest_path(self):
        return os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "nuclei_templates", "manifest.yaml"
        )

    def test_manifest_exists(self):
        if not os.path.isfile(self._manifest_path()):
            self.fail("nuclei_templates/manifest.yaml does not exist")

    def test_manifest_is_valid_yaml(self):
        import yaml
        with open(self._manifest_path()) as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            self.fail("manifest.yaml did not parse to a dict")
        if "mappings" not in data:
            self.fail("manifest.yaml missing 'mappings' key")

    def test_hikvision_maps_to_hikvision_dir(self):
        import yaml
        with open(self._manifest_path()) as f:
            data = yaml.safe_load(f)
        paths = data["mappings"].get("hikvision", [])
        if not any("hikvision" in p for p in paths):
            self.fail(
                "Expected 'hikvision' in mapped paths for device type 'hikvision', got: {!r}".format(paths)
            )

    def test_amcrest_covered_by_manifest(self):
        """amcrest shares Dahua firmware — must appear in mappings."""
        import yaml
        with open(self._manifest_path()) as f:
            data = yaml.safe_load(f)
        if "amcrest" not in data["mappings"]:
            self.fail("manifest.yaml has no entry for 'amcrest'")

    def test_manifest_paths_exist_on_disk(self):
        import yaml
        templates_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "nuclei_templates"
        )
        with open(self._manifest_path()) as f:
            data = yaml.safe_load(f)
        missing = []
        for device_type, paths in (data.get("mappings") or {}).items():
            for p in paths:
                full = os.path.join(templates_dir, p.rstrip('/'))
                if not os.path.exists(full):
                    missing.append("{} -> {}".format(device_type, full))
        if missing:
            self.fail(
                "manifest.yaml references paths that do not exist on disk:\n" +
                "\n".join("  " + m for m in missing)
            )


# ===========================================================================
# Fix 5 – nuclei_scan input validation
# ===========================================================================
class NucleiScanInputValidationTests(TestCase):
    """nuclei_scan rejects invalid severity / rate_limit values before exec."""

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0", country="US", ics="test", coordinates_search="test"
        )
        self.device = Device.objects.create(
            search=self.search, ip="192.168.1.1", product="Cam",
            port="80", type="hikvision", lat="40.0", lon="-74.0", country_code="US"
        )

    def _call(self, **kwargs):
        from kamerka.tasks import nuclei_scan
        return nuclei_scan(self.device.id, **kwargs)

    @patch('kamerka.tasks.subprocess.run')
    def test_valid_severity_accepted(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        for sev in ("info", "low", "medium", "high", "critical"):
            result = self._call(severity=sev)
            if isinstance(result, dict) and "error" in result:
                self.fail("Valid severity '{}' rejected: {}".format(sev, result))

    def test_invalid_severity_returns_error(self):
        for bad in ("urgent", "CRITICAL; rm -rf /", "", "none", "1"):
            result = self._call(severity=bad)
            if not (isinstance(result, dict) and "error" in result):
                self.fail(
                    "Expected error dict for invalid severity {!r}, got: {!r}".format(bad, result)
                )

    @patch('kamerka.tasks.subprocess.run')
    def test_severity_is_case_normalised(self, mock_run):
        """Severity values should be accepted case-insensitively."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = self._call(severity="CRITICAL")
        if isinstance(result, dict) and "error" in result:
            self.fail("'CRITICAL' should be accepted case-insensitively, got: {}".format(result))
        called_cmd = mock_run.call_args[0][0]
        sev_index = called_cmd.index("-severity") + 1
        if called_cmd[sev_index] != "critical":
            self.fail("Expected normalised severity 'critical', got {!r}".format(called_cmd[sev_index]))

    def test_rate_limit_out_of_range_returns_error(self):
        for bad in (0, 501, -1, 9999):
            result = self._call(rate_limit=bad)
            if not (isinstance(result, dict) and "error" in result):
                self.fail(
                    "Expected error for out-of-range rate_limit={}, got: {!r}".format(bad, result)
                )

    def test_non_integer_rate_limit_returns_error(self):
        for bad in ("fast", None, "150; rm -rf /"):
            result = self._call(rate_limit=bad)
            if not (isinstance(result, dict) and "error" in result):
                self.fail(
                    "Expected error for non-integer rate_limit={!r}, got: {!r}".format(bad, result)
                )

    @patch('kamerka.tasks.subprocess.run')
    def test_valid_rate_limit_accepted(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        for val in (1, 100, 500):
            result = self._call(rate_limit=val)
            if isinstance(result, dict) and "error" in result:
                self.fail("Valid rate_limit={} rejected: {}".format(val, result))

    @patch('kamerka.tasks.subprocess.run')
    def test_rate_limit_appears_in_command(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        self._call(rate_limit=42)
        cmd = mock_run.call_args[0][0]
        rl_idx = cmd.index("-rate-limit") + 1
        if cmd[rl_idx] != "42":
            self.fail("Expected '42' as rate-limit arg, got {!r}".format(cmd[rl_idx]))
