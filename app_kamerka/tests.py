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
