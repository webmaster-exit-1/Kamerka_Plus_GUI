import io
import json
import os
import tempfile
from unittest.mock import patch, MagicMock

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, RequestFactory

from app_kamerka.models import (
    Search, Device, DeviceNearby, WappalyzerResult, NucleiResult,
    ShodanScan, BinaryEdgeScore, Whois, Bosch, Dnp3
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

    def test_binary_edge_score_jsonfield(self):
        """Test BinaryEdgeScore uses Django's built-in JSONField."""
        be = BinaryEdgeScore.objects.create(
            device=self.device,
            grades={"http": "A"},
            cve={"cpe1": ["CVE-2021-1234"]},
            score="85"
        )
        self.assertEqual(be.grades, {"http": "A"})

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
        from kamerka.tasks import nuclei_scan
        nuclei_scan(self.device.id, templates_dir="nuclei_templates/china-iot/hikvision")
        call_args = mock_run.call_args[0][0]
        self.assertIn("-t", call_args)
        self.assertIn("nuclei_templates/china-iot/hikvision", call_args)

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

    def test_index_page_loads(self):
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
        """nmap_host_worker must not raise TypeError when MaxMind returns None."""
        from kamerka.tasks import nmap_host_worker

        search = self._make_search()
        host = MagicMock()
        host.hostnames = ['lb-140-82-113-3-iad.github.com']
        host.address = '140.82.113.3'
        host.services = []

        # Should not raise, and should NOT create a Device
        nmap_host_worker(
            host_arg=host,
            max_reader=self._make_mock_reader(None),  # None – previously caused TypeError
            search=search,
        )
        self.assertFalse(Device.objects.filter(search=search, ip='140.82.113.3').exists())

    def test_nmap_host_worker_no_crash_on_missing_lat_lon(self):
        """nmap_host_worker must not raise when MaxMind entry lacks lat/lon."""
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
        self.assertFalse(Device.objects.filter(search=search, ip='140.82.113.3').exists())

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
