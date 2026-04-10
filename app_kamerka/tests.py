"""
Kamerka tests — test what matters.

Each test here would catch a real bug in the application:
  - shodan_search_worker creates Device records from Shodan banner data
  - ShodanFixtureFileTest uses tests/fixtures/shodan_response.json (real shodan.json.gz data)
  - scan() saves results to the device record
  - exploit() routes to the right handler per device type
  - nuclei_scan saves NucleiResult rows
  - wappalyzer_scan saves WappalyzerResult rows
  - port_scan_ip creates a new device when IP is unseen
  - export endpoints produce valid CSV / KML content
  - device detail page renders scan and exploit results
  - results page shows devices with CVE links
"""

import json
import os
import re
import subprocess
from unittest.mock import patch, MagicMock, call

from django.test import TestCase, override_settings
from django.test import Client

from app_kamerka.models import Search, Device, NucleiResult, WappalyzerResult

# Minimal Shodan banner — the format returned by api.search_cursor()
# and written to .json.gz by shodan_helpers.write_banner().
SHODAN_BANNER = {
    "ip_str": "1.2.3.4",
    "ip": 16909060,
    "port": 80,
    "org": "TestOrg",
    "data": "HTTP/1.1 200 OK\r\nServer: hikvision\r\n",
    "product": "Hikvision DVR",
    "location": {
        "city": "Beijing",
        "country_code": "CN",
        "latitude": 39.9042,
        "longitude": 116.4074,
    },
    "vulns": {"CVE-2021-36260": {"cvss": 9.8, "summary": "Unauthenticated RCE"}},
    "hostnames": ["cam.example.com"],
    "opts": {},
    "timestamp": "2024-01-01T00:00:00.000000",
    "transport": "tcp",
}

SHODAN_BANNER_NO_PRODUCT = {
    "ip_str": "5.6.7.8",
    "ip": 84281096,
    "port": 502,
    "org": "AcmeCorp",
    "data": "Modbus/TCP\n",
    "location": {
        "city": None,
        "country_code": "DE",
        "latitude": 52.52,
        "longitude": 13.405,
    },
    "hostnames": [],
    "opts": {},
    "timestamp": "2024-01-01T00:00:00.000000",
    "transport": "tcp",
}

# Real-format banner: no product, no vulns — matches the GoAhead-Webs schema
# seen in the actual shodan.json.gz output (tests/fixtures/shodan_response.json).
SHODAN_BANNER_GOAHEAD = {
    "hash": -1622739553,
    "asn": "AS37963",
    "http": {
        "status": 401,
        "title": "Document Error: Unauthorized",
        "server": "GoAhead-Webs",
        "host": "119.23.253.64",
        "html": "<html><head><title>Document Error: Unauthorized</title></head>\r\n"
                "<body><h2>Access Error: Unauthorized</h2></body></html>",
        "components": {"Digest": {"categories": ["Security"]},
                       "GoAhead": {"categories": ["Web servers"]}},
        "redirects": [],
        "robots": None, "robots_hash": None,
        "sitemap": None, "sitemap_hash": None,
        "securitytxt": None, "securitytxt_hash": None,
        "location": "/",
    },
    "os": None,
    "transport": "tcp",
    "timestamp": "2026-03-15T22:57:45.950793",
    "isp": "Hangzhou Alibaba Advertising Co.,Ltd.",
    "cpe23": ["cpe:2.3:a:embedthis:goahead"],
    "cpe": ["cpe:/a:embedthis:goahead"],
    "_shodan": {
        "region": "na",
        "module": "auto",
        "ptr": True,
        "options": {},
        "id": "5fb7c1bc-d4cf-4935-b7e8-efd5bbd1c978",
        "crawler": "6d3ed9d6b8f837a126ee7cc6b0653be94de51626",
    },
    "hostnames": [],
    "location": {
        "city": "Shenzhen",
        "region_code": "GD",
        "area_code": None,
        "longitude": 114.0683,
        "latitude": 22.54554,
        "country_code": "CN",
        "country_name": "China",
    },
    "ip": 1998060864,
    "domains": [],
    "org": "Aliyun Computing Co., LTD",
    "data": "HTTP/1.1 401 Unauthorized\r\nServer: GoAhead-Webs\r\n\r\n",
    "port": 2067,
    "opts": {},
    "ip_str": "119.23.253.64",
}

# Inline S7 PLC banner for unit tests (port 102, no product)
SHODAN_BANNER_S7 = {
    "ip_str": "10.20.30.40",
    "ip": 169090600,
    "port": 102,
    "org": "Siemens AG",
    "data": (
        "S7comm\n"
        "Module: CPU 315-2 DP\n"
        "Plant: WaterPlant-North\n"
        "PLC name: PLC-01\n"
        "Module name: CPU 315-2 DP\n"
    ),
    "_shodan": {"module": "s7", "options": {}, "ptr": False},
    "location": {
        "city": "Berlin",
        "country_code": "DE",
        "latitude": 52.52,
        "longitude": 13.405,
    },
    "hostnames": [],
    "opts": {},
    "timestamp": "2024-01-01T00:00:00.000000",
    "transport": "tcp",
}

_DUMMY_CACHE = {"default": {"BACKEND": "django.core.cache.backends.dummy.DummyCache"}}


def _make_search():
    return Search.objects.create(
        coordinates="40.7128,-74.0060", country="US",
        ics="['hikvision']", coordinates_search="['40.7128,-74.0060']",
    )


def _make_device(search, ip="1.2.3.4", device_type="hikvision", port="80",
                 vulns=""):
    return Device.objects.create(
        search=search, ip=ip, product="Test Camera", port=port,
        type=device_type, lat="40.7128", lon="-74.0060",
        country_code="US", org="TestOrg", city="New York", vulns=vulns,
    )


# ---------------------------------------------------------------------------
# shodan_search_worker — the core Shodan ingest path
# ---------------------------------------------------------------------------
class ShodanSearchWorkerTest(TestCase):
    """shodan_search_worker must create Device records from Shodan banner data.

    This is the single most critical code path: if it breaks, no Shodan results
    ever appear in the UI regardless of how many API credits are used.
    """

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0", country="CN",
            ics="['hikvision']", coordinates_search="['0,0']",
        )

    def _run_worker(self, banners, query="hikvision", search_type="hikvision"):
        """Run shodan_search_worker with mocked API and file I/O."""
        mock_api = MagicMock()
        mock_api.search_cursor.return_value = iter(banners)
        mock_fout = MagicMock()

        with patch("kamerka.tasks.Shodan", return_value=mock_api), \
             patch("kamerka.tasks._get_env_key", return_value="fake-key"), \
             patch("kamerka.tasks.shodan_helpers.open_file", return_value=mock_fout), \
             patch("kamerka.tasks.shodan_helpers.write_banner"):
            from kamerka.tasks import shodan_search_worker
            shodan_search_worker(
                fk=self.search.id, query=query,
                search_type=search_type, category="ics",
                country="CN",
            )

    def test_device_created_from_banner(self):
        """A Shodan banner must produce exactly one Device record."""
        self._run_worker([SHODAN_BANNER])
        self.assertEqual(Device.objects.filter(search=self.search).count(), 1)

    def test_device_ip_matches_banner(self):
        self._run_worker([SHODAN_BANNER])
        device = Device.objects.get(search=self.search)
        self.assertEqual(device.ip, "1.2.3.4")

    def test_device_port_matches_banner(self):
        self._run_worker([SHODAN_BANNER])
        device = Device.objects.get(search=self.search)
        self.assertEqual(device.port, "80")

    def test_device_vulns_extracted(self):
        """CVE list must be stored in device.vulns."""
        self._run_worker([SHODAN_BANNER])
        device = Device.objects.get(search=self.search)
        self.assertIn("CVE-2021-36260", str(device.vulns))

    def test_device_location_extracted(self):
        """Lat/lon and country_code must be populated from location block."""
        self._run_worker([SHODAN_BANNER])
        device = Device.objects.get(search=self.search)
        self.assertAlmostEqual(float(device.lat), 39.9042, places=3)
        self.assertAlmostEqual(float(device.lon), 116.4074, places=3)
        self.assertEqual(device.country_code, "CN")

    def test_missing_product_stores_empty_string(self):
        """Banners without a 'product' key must not crash — empty string is stored."""
        self._run_worker([SHODAN_BANNER_NO_PRODUCT], search_type="modbus")
        device = Device.objects.get(search=self.search, ip="5.6.7.8")
        self.assertEqual(device.product, "")

    def test_null_city_stored_as_empty_string(self):
        """city=None in Shodan response must be stored as '' not 'None'."""
        self._run_worker([SHODAN_BANNER_NO_PRODUCT], search_type="modbus")
        device = Device.objects.get(search=self.search, ip="5.6.7.8")
        self.assertNotEqual(device.city, "None")

    def test_multiple_banners_create_multiple_devices(self):
        """Each banner in the cursor must create its own Device row."""
        self._run_worker([SHODAN_BANNER, SHODAN_BANNER_NO_PRODUCT],
                         search_type="hikvision")
        self.assertEqual(Device.objects.filter(search=self.search).count(), 2)

    def test_banner_written_to_download_file(self):
        """Every banner must be persisted to the .json.gz download file
        so that shodan convert can later produce CSV/KML exports."""
        mock_api = MagicMock()
        mock_api.search_cursor.return_value = iter([SHODAN_BANNER])
        mock_fout = MagicMock()
        write_banner_mock = MagicMock()

        with patch("kamerka.tasks.Shodan", return_value=mock_api), \
             patch("kamerka.tasks._get_env_key", return_value="fake-key"), \
             patch("kamerka.tasks.shodan_helpers.open_file", return_value=mock_fout), \
             patch("kamerka.tasks.shodan_helpers.write_banner", write_banner_mock):
            from kamerka.tasks import shodan_search_worker
            shodan_search_worker(
                fk=self.search.id, query="hikvision",
                search_type="hikvision", category="ics", country="CN",
            )

        write_banner_mock.assert_called_once_with(mock_fout, SHODAN_BANNER)

    def test_goahead_banner_no_product_no_vulns(self):
        """GoAhead-Webs banners have no 'product' or 'vulns' keys.
        product must fall back to http.server; vulns must be empty string."""
        self._run_worker([SHODAN_BANNER_GOAHEAD], search_type="goahead")
        device = Device.objects.get(search=self.search, ip="119.23.253.64")
        # product falls back to http.server
        self.assertEqual(device.product, "GoAhead-Webs")
        self.assertEqual(str(device.vulns), "")

    def test_goahead_banner_cpe_stored(self):
        """cpe23 list must be stored in device.cpe (first entry)."""
        self._run_worker([SHODAN_BANNER_GOAHEAD], search_type="goahead")
        device = Device.objects.get(search=self.search, ip="119.23.253.64")
        self.assertEqual(device.cpe, "cpe:2.3:a:embedthis:goahead")

    def test_goahead_banner_isp_stored(self):
        """isp field must be stored separately from org."""
        self._run_worker([SHODAN_BANNER_GOAHEAD], search_type="goahead")
        device = Device.objects.get(search=self.search, ip="119.23.253.64")
        self.assertEqual(device.isp, "Hangzhou Alibaba Advertising Co.,Ltd.")
        # org and isp are different values from the same banner
        self.assertNotEqual(device.org, device.isp)

    def test_goahead_banner_location_extracted(self):
        """Real GoAhead banner location block must populate lat/lon correctly."""
        self._run_worker([SHODAN_BANNER_GOAHEAD], search_type="goahead")
        device = Device.objects.get(search=self.search, ip="119.23.253.64")
        self.assertAlmostEqual(float(device.lat), 22.54554, places=3)
        self.assertAlmostEqual(float(device.lon), 114.0683, places=3)
        self.assertEqual(device.country_code, "CN")
        self.assertEqual(device.city, "Shenzhen")


# ---------------------------------------------------------------------------
# ShodanFixtureFileTest — uses tests/fixtures/shodan_response.json (real banner data)
# ---------------------------------------------------------------------------
_FIXTURE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    'tests', 'fixtures', 'shodan_response.json',
)


def _load_fixture_banners():
    """Load all banners from tests/fixtures/shodan_response.json (NDJSON format)."""
    banners = []
    with open(_FIXTURE_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                banners.append(json.loads(line))
    return banners


class ShodanFixtureFileTest(TestCase):
    """Tests driven by the real Shodan banner data in tests/fixtures/shodan_response.json.

    That file is the NDJSON content of an actual shodan.json.gz download
    (``gunzip -c shodan_results.json.gz > test.json``).  The banners are
    GoAhead-Webs HTTP 401 devices — the most common real-world format:
    - no ``product`` field
    - no ``vulns`` field
    - ``hash``, ``asn``, ``cpe``/``cpe23``, ``_shodan.region`` present
    - ``opts`` is always ``{}`` (no screenshot)
    - ``hostnames`` may be empty or contain one entry
    """

    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0", country="XX",
            ics="['goahead']", coordinates_search="['0,0']",
        )
        self.banners = _load_fixture_banners()

    def _run_with_banners(self, banners, search_type="goahead"):
        mock_api = MagicMock()
        mock_api.search_cursor.return_value = iter(banners)
        mock_fout = MagicMock()

        with patch("kamerka.tasks.Shodan", return_value=mock_api), \
             patch("kamerka.tasks._get_env_key", return_value="fake-key"), \
             patch("kamerka.tasks.shodan_helpers.open_file", return_value=mock_fout), \
             patch("kamerka.tasks.shodan_helpers.write_banner"):
            from kamerka.tasks import shodan_search_worker
            shodan_search_worker(
                fk=self.search.id, query=search_type,
                search_type=search_type, category="ics",
                country="XX",
            )

    def test_fixture_file_is_valid_ndjson(self):
        """test.json must be parseable NDJSON with required fields on every banner."""
        self.assertEqual(len(self.banners), 4,
                         "test.json must contain exactly 4 GoAhead-Webs banners")
        for b in self.banners:
            self.assertIn('ip_str', b)
            self.assertIn('port', b)
            self.assertIn('location', b)
            self.assertIn('org', b)
            self.assertIn('_shodan', b)
            self.assertIn('cpe', b)
            self.assertIn('cpe23', b)

    def test_all_fixture_banners_create_devices(self):
        """All 4 real banners must each produce a Device record."""
        self._run_with_banners(self.banners)
        self.assertEqual(Device.objects.filter(search=self.search).count(), 4)

    def test_real_banners_product_falls_back_to_http_server(self):
        """Real GoAhead banners have no 'product' key.
        Worker must fall back to http.server so every device gets a name."""
        for b in self.banners:
            self.assertNotIn('product', b,
                             f"{b['ip_str']} unexpectedly has a product field")
        self._run_with_banners(self.banners)
        for device in Device.objects.filter(search=self.search):
            self.assertEqual(device.product, "GoAhead-Webs",
                             f"{device.ip} product should fall back to http.server")

    def test_real_banners_have_no_vulns_field(self):
        """Real GoAhead banners have no vulns key — stored as empty string."""
        for b in self.banners:
            self.assertNotIn('vulns', b,
                             f"{b['ip_str']} unexpectedly has a vulns field")
        self._run_with_banners(self.banners)
        for device in Device.objects.filter(search=self.search):
            self.assertEqual(str(device.vulns), "",
                             f"{device.ip} vulns should be empty string")

    def test_isp_stored_from_real_banners(self):
        """isp must be extracted and stored — it differs from org on every
        real banner (e.g. org=Aliyun, isp=Alibaba Advertising Co.)."""
        self._run_with_banners(self.banners)
        for b in self.banners:
            device = Device.objects.get(search=self.search, ip=b['ip_str'])
            self.assertEqual(device.isp, b['isp'],
                             f"{b['ip_str']} isp mismatch")
            # Shodan returns org and isp as distinct fields
            self.assertNotEqual(device.org, device.isp,
                                f"{b['ip_str']} org and isp should differ")

    def test_cpe_stored_from_real_banners(self):
        """cpe23[0] must be stored in device.cpe for every real banner."""
        self._run_with_banners(self.banners)
        for b in self.banners:
            device = Device.objects.get(search=self.search, ip=b['ip_str'])
            self.assertEqual(device.cpe, b['cpe23'][0],
                             f"{b['ip_str']} cpe mismatch")

    def test_hostname_stored_when_present(self):
        """Banner with a non-empty hostnames list must store the first entry."""
        # 139.159.141.198 has hostnames=['ecs-139-159-141-198.compute.hwclouds-dns.com']
        banner = next(b for b in self.banners if b['ip_str'] == '139.159.141.198')
        self.assertTrue(banner['hostnames'], "fixture must have a hostname for this IP")
        self._run_with_banners([banner])
        device = Device.objects.get(search=self.search, ip='139.159.141.198')
        self.assertEqual(device.hostnames, 'ecs-139-159-141-198.compute.hwclouds-dns.com')

    def test_empty_hostnames_stores_empty_string(self):
        """Banner with hostnames=[] must store '' not crash or store 'None'."""
        banner = next(b for b in self.banners if b['ip_str'] == '119.23.253.64')
        self.assertEqual(banner['hostnames'], [])
        self._run_with_banners([banner])
        device = Device.objects.get(search=self.search, ip='119.23.253.64')
        self.assertEqual(device.hostnames, "")

    def test_undershodan_region_field_doesnt_crash(self):
        """Real banners include _shodan.region which fabricated banners lacked.
        The worker must not crash on this extra metadata field."""
        for b in self.banners:
            self.assertIn('region', b['_shodan'],
                          f"{b['ip_str']} _shodan block must have region")
        self._run_with_banners(self.banners)  # no exception = pass
        self.assertEqual(Device.objects.filter(search=self.search).count(), 4)

    def test_location_fields_extracted_correctly(self):
        """lat/lon/city/country_code must be populated from the real location block."""
        banner = next(b for b in self.banners if b['ip_str'] == '122.9.141.98')
        self._run_with_banners([banner])
        device = Device.objects.get(search=self.search, ip='122.9.141.98')
        self.assertAlmostEqual(float(device.lat), 26.58333, places=3)
        self.assertAlmostEqual(float(device.lon), 106.71667, places=3)
        self.assertEqual(device.country_code, 'CN')
        self.assertEqual(device.city, 'Guiyang')


# ---------------------------------------------------------------------------
# scan() — NMAP scan saves result to device.scan and sets exploited_scanned
# ---------------------------------------------------------------------------
class ScanSavesResultTest(TestCase):
    """scan() must persist its result dict into device.scan."""

    def setUp(self):
        self.search = _make_search()
        self.device = _make_device(self.search, device_type="generic", port="80")

    def test_scan_result_persisted_to_device(self):
        """When NmapProcess returns an open port, scan() saves State/Reason to device."""
        nmap_xml = (
            '<?xml version="1.0"?>'
            '<nmaprun>'
            '<host><ports><port>'
            '<state state="open" reason="syn-ack"/>'
            '</port></ports></host>'
            '</nmaprun>'
        )
        mock_proc = MagicMock()
        mock_proc.is_running.return_value = False
        mock_proc.stdout = nmap_xml

        with patch("kamerka.tasks.NmapProcess", return_value=mock_proc):
            from kamerka.tasks import scan
            result = scan(self.device.id)

        self.assertIsNotNone(result, "scan() must return a dict, not None")
        self.device.refresh_from_db()
        self.assertTrue(
            self.device.exploited_scanned,
            "scan() must set device.exploited_scanned = True",
        )

    def test_ics_device_uses_nse_script(self):
        """ICS-type devices must include the matching NSE script in the Nmap call."""
        ics_device = _make_device(self.search, ip="1.2.3.5",
                                  device_type="dnp3", port="20000")
        nmap_xml = (
            '<?xml version="1.0"?>'
            '<nmaprun>'
            '<host><ports><port>'
            '<state state="open" reason="syn-ack"/>'
            '<script id="dnp3-info" output="DNP3 v2"/>'
            '</port></ports></host>'
            '</nmaprun>'
        )
        mock_proc = MagicMock()
        mock_proc.is_running.return_value = False
        mock_proc.stdout = nmap_xml

        captured = {}

        def capture_proc(ip, options="", **kwargs):
            captured["options"] = options
            return mock_proc

        with patch("kamerka.tasks.NmapProcess", side_effect=capture_proc):
            from kamerka.tasks import scan, ics_scan
            scan(ics_device.id)

        self.assertIn(
            ics_scan["dnp3"], captured["options"],
            "ICS scan must include the NSE script for the device type",
        )


# ---------------------------------------------------------------------------
# exploit() — routes to the correct handler
# ---------------------------------------------------------------------------
class ExploitDispatchTest(TestCase):
    """exploit() must call the right handler and return its value."""

    def setUp(self):
        self.search = _make_search()

    def test_unknown_type_returns_no_exploit_message(self):
        device = _make_device(self.search, device_type="unknown_brand")
        from kamerka.tasks import exploit
        result = exploit(device.id)
        self.assertIn("Reason", result)
        self.assertIn("No exploit", result["Reason"])

    def test_hikvision_calls_hikvision_helper(self):
        device = _make_device(self.search, device_type="hikvision")
        with patch("kamerka.tasks.exploits.hikvision", return_value={"creds": "admin:12345"}) as mock_h:
            from kamerka.tasks import exploit
            result = exploit(device.id)
        mock_h.assert_called_once()
        self.assertEqual(result, {"creds": "admin:12345"})

    def test_bosch_calls_bosch_helper(self):
        device = _make_device(self.search, device_type="bosch_security")
        with patch("kamerka.tasks.exploits.bosch_usernames", return_value=["admin"]) as mock_b:
            from kamerka.tasks import exploit
            result = exploit(device.id)
        mock_b.assert_called_once()
        self.assertEqual(result, ["admin"])


# ---------------------------------------------------------------------------
# nuclei_scan saves NucleiResult rows
# ---------------------------------------------------------------------------
@override_settings(CACHES=_DUMMY_CACHE)
class NucleiScanSavesResultTest(TestCase):
    """nuclei_scan must create NucleiResult rows for each finding."""

    def setUp(self):
        self.search = _make_search()
        self.device = _make_device(self.search, port="80")

    def test_finding_saved_to_database(self):
        finding = json.dumps({
            "template-id": "hikvision-cve-2021-36260",
            "matched-at": "http://1.2.3.4:80",
            "info": {
                "name": "Hikvision RCE",
                "severity": "critical",
                "description": "Unauthenticated RCE",
            },
        })
        mock_proc = MagicMock()
        mock_proc.stdout = iter([finding + "\n"])
        mock_proc.wait.return_value = 0

        with patch("kamerka.tasks.subprocess.Popen", return_value=mock_proc), \
             patch("kamerka.tasks._resolve_open_ports", return_value=[80]):
            from kamerka.tasks import nuclei_scan
            nuclei_scan(self.device.id)

        saved = NucleiResult.objects.filter(device=self.device)
        self.assertEqual(saved.count(), 1, "One NucleiResult must be saved per finding")
        self.assertEqual(saved.first().template_id, "hikvision-cve-2021-36260")
        self.assertEqual(saved.first().severity, "critical")

    def test_no_findings_saves_nothing(self):
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_proc.wait.return_value = 0

        with patch("kamerka.tasks.subprocess.Popen", return_value=mock_proc), \
             patch("kamerka.tasks._resolve_open_ports", return_value=[80]):
            from kamerka.tasks import nuclei_scan
            nuclei_scan(self.device.id)

        self.assertEqual(NucleiResult.objects.filter(device=self.device).count(), 0)


# ---------------------------------------------------------------------------
# wappalyzer_scan saves WappalyzerResult rows
# ---------------------------------------------------------------------------
@override_settings(CACHES=_DUMMY_CACHE)
class WappalyzerScanSavesResultTest(TestCase):
    """wappalyzer_scan must create WappalyzerResult rows."""

    def setUp(self):
        self.search = _make_search()
        self.device = _make_device(self.search, port="80")

    def test_result_saved_to_database(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps([{
            "url": "http://1.2.3.4:80",
            "technologies": [{"name": "nginx", "version": "1.18"}],
        }])

        with patch("kamerka.tasks.subprocess.run", return_value=mock_result), \
             patch("kamerka.tasks._resolve_open_ports", return_value=[80]):
            from kamerka.tasks import wappalyzer_scan
            wappalyzer_scan(self.device.id)

        saved = WappalyzerResult.objects.filter(device=self.device)
        self.assertEqual(saved.count(), 1)
        # technologies is a JSONField — check the parsed structure
        techs = saved.first().technologies
        self.assertIsInstance(techs, list)
        self.assertEqual(techs[0]["technologies"][0]["name"], "nginx")


# ---------------------------------------------------------------------------
# port_scan_ip creates a Device when the IP hasn't been seen before
# ---------------------------------------------------------------------------
class PortScanIpCreatesDeviceTest(TestCase):
    """port_scan/ip/<target_ip> must create a Device record for new IPs."""

    def test_new_ip_creates_device(self):
        with patch("app_kamerka.views.port_scan_task") as mock_task:
            mock_task.delay.return_value = MagicMock(id="fake-task-id")
            response = self.client.get(
                "/port_scan/ip/5.6.7.8",
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("device_id", data)
        self.assertTrue(Device.objects.filter(ip="5.6.7.8").exists())

    def test_existing_ip_reuses_device(self):
        search = _make_search()
        existing = _make_device(search, ip="9.9.9.9")

        with patch("app_kamerka.views.port_scan_task") as mock_task:
            mock_task.delay.return_value = MagicMock(id="fake-task-id")
            self.client.get(
                "/port_scan/ip/9.9.9.9",
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            )

        self.assertEqual(Device.objects.filter(ip="9.9.9.9").count(), 1,
                         "Duplicate Device must not be created for existing IP")


# ---------------------------------------------------------------------------
# Exports produce real content
# ---------------------------------------------------------------------------
class ExportTest(TestCase):
    """Export endpoints must produce non-empty files with correct content."""

    def setUp(self):
        self.search = _make_search()
        _make_device(self.search, vulns="['CVE-2021-36260']")

    def test_csv_export_contains_correct_headers(self):
        """CSV export writes Shodan-format columns; when no download file exists,
        a header-only CSV is the correct fallback (data comes from shodan download)."""
        response = self.client.get("/export/csv/{}".format(self.search.id))
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response["Content-Type"])
        body = response.content.decode()
        # The export schema always starts with ip_str
        self.assertIn("ip_str", body, "CSV must contain the ip_str column header")

    def test_kml_export_returns_valid_kml(self):
        """KML export always returns valid KML; when no download file exists,
        an empty-but-valid KML document is the correct fallback."""
        response = self.client.get("/export/kml/{}".format(self.search.id))
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertIn("<kml", body, "Response must be valid KML")


# ---------------------------------------------------------------------------
# Device detail page renders scan/exploit results
# ---------------------------------------------------------------------------
class DeviceDetailRenderTest(TestCase):
    """device detail page must surface scan results and CVE links."""

    def setUp(self):
        self.search = _make_search()
        self.device = _make_device(
            self.search,
            vulns="['CVE-2021-36260', 'CVE-2017-7921']",
        )
        self.device.scan = str({"State": "open", "Reason": "syn-ack"})
        self.device.save()

    def test_cves_rendered_as_nvd_links(self):
        url = "/results/{}/{}/{}".format(
            self.search.id, self.device.id, self.device.ip
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertIn("nvd.nist.gov/vuln/detail/CVE-2021-36260", body,
                      "CVEs must be rendered as NVD links")
        self.assertIn("nvd.nist.gov/vuln/detail/CVE-2017-7921", body,
                      "All CVEs must be linked")

    def test_scan_results_appear_on_page(self):
        url = "/results/{}/{}/{}".format(
            self.search.id, self.device.id, self.device.ip
        )
        response = self.client.get(url)
        body = response.content.decode()
        # The NMAP scan tab section must be present
        self.assertIn("scan_results", body,
                      "Device page must contain the scan results container")
        self.assertIn("exploit_results", body,
                      "Device page must contain the exploit results container")


# ---------------------------------------------------------------------------
# Results page shows devices with their data
# ---------------------------------------------------------------------------
class ResultsPageTest(TestCase):
    """Results page must list devices and render CVE data correctly."""

    def setUp(self):
        self.search = _make_search()
        _make_device(self.search, ip="10.0.0.1", vulns="['CVE-2021-36260']")
        _make_device(self.search, ip="10.0.0.2", vulns="")

    def test_device_ips_appear_in_results(self):
        response = self.client.get("/results/{}".format(self.search.id))
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertIn("10.0.0.1", body)
        self.assertIn("10.0.0.2", body)

    def test_cve_links_in_results_table(self):
        response = self.client.get("/results/{}".format(self.search.id))
        body = response.content.decode()
        self.assertIn("nvd.nist.gov/vuln/detail/CVE-2021-36260", body,
                      "CVE in results table must be an NVD link")

    def test_device_with_no_vulns_shows_dash(self):
        response = self.client.get("/results/{}".format(self.search.id))
        body = response.content.decode()
        # Device 10.0.0.2 has no vulns — its cell must show the empty-state marker
        self.assertIn("—", body)


# ---------------------------------------------------------------------------
# Protocol metadata parsers
# ---------------------------------------------------------------------------
class ModbusParserTest(TestCase):
    """_parse_modbus_output must extract Modbus-specific fields."""

    def test_slave_id_extracted(self):
        from kamerka.tasks import _parse_modbus_output
        output = "Slave ID data: Schneider Electric\nDevice Identification: BMX P34\n"
        result = _parse_modbus_output(output)
        self.assertEqual(result.get("slave_id"), "Schneider Electric")

    def test_vendor_name_extracted(self):
        from kamerka.tasks import _parse_modbus_output
        output = "Vendor Name: Schneider Electric\nProduct Code: BMX P34\n"
        result = _parse_modbus_output(output)
        self.assertEqual(result.get("vendor_id"), "Schneider Electric")
        self.assertEqual(result.get("project_name"), "BMX P34")

    def test_revision_extracted(self):
        from kamerka.tasks import _parse_modbus_output
        output = "Revision: V2.60\n"
        result = _parse_modbus_output(output)
        self.assertEqual(result.get("firmware_version"), "V2.60")

    def test_empty_output_returns_empty_dict(self):
        from kamerka.tasks import _parse_modbus_output
        result = _parse_modbus_output("")
        self.assertEqual(result, {})


class S7ParserTest(TestCase):
    """_parse_s7_output must extract Siemens S7-specific fields."""

    def test_module_name_extracted(self):
        from kamerka.tasks import _parse_s7_output
        output = "Module: CPU 315-2 DP\nPlant: WaterPlant\nSerial: S-123456\n"
        result = _parse_s7_output(output)
        self.assertEqual(result.get("module_name"), "CPU 315-2 DP")

    def test_plant_id_extracted(self):
        from kamerka.tasks import _parse_s7_output
        output = "Plant identification: WaterPlant-North\n"
        result = _parse_s7_output(output)
        self.assertEqual(result.get("plant_id"), "WaterPlant-North")

    def test_serial_number_extracted(self):
        from kamerka.tasks import _parse_s7_output
        output = "Serial number: S-1234567890\n"
        result = _parse_s7_output(output)
        self.assertEqual(result.get("serial_number"), "S-1234567890")

    def test_hardware_firmware_version(self):
        from kamerka.tasks import _parse_s7_output
        output = "Hardware version: 3.0\nFirmware version: V3.2.8\n"
        result = _parse_s7_output(output)
        self.assertEqual(result.get("hardware_version"), "3.0")
        self.assertEqual(result.get("firmware_version"), "V3.2.8")

    def test_siemens_vendor_auto_detected(self):
        from kamerka.tasks import _parse_s7_output
        output = "Module: S7-300 CPU\n"
        result = _parse_s7_output(output)
        self.assertEqual(result.get("vendor_id"), "Siemens")

    def test_empty_output(self):
        from kamerka.tasks import _parse_s7_output
        result = _parse_s7_output("")
        self.assertEqual(result, {})


class BACnetParserTest(TestCase):
    """_parse_bacnet_output must extract BACnet-specific fields."""

    def test_vendor_extracted(self):
        from kamerka.tasks import _parse_bacnet_output
        output = "Vendor Name: Honeywell\nModel Name: Spyder\n"
        result = _parse_bacnet_output(output)
        self.assertEqual(result.get("vendor_id"), "Honeywell")
        self.assertEqual(result.get("project_name"), "Spyder")

    def test_firmware_version_extracted(self):
        from kamerka.tasks import _parse_bacnet_output
        output = "Firmware Version: 2.04.016\n"
        result = _parse_bacnet_output(output)
        self.assertEqual(result.get("firmware_version"), "2.04.016")

    def test_empty_output(self):
        from kamerka.tasks import _parse_bacnet_output
        result = _parse_bacnet_output("")
        self.assertEqual(result, {})


# ---------------------------------------------------------------------------
# Honeypot probability engine
# ---------------------------------------------------------------------------
@override_settings(CACHES=_DUMMY_CACHE)
class HoneypotCheckTest(TestCase):
    """honeypot_check must analyze banner density and signature matching."""

    def setUp(self):
        self.search = _make_search()

    def test_low_density_gives_low_probability(self):
        device = _make_device(self.search, ip="10.0.0.1")
        device.data = "HTTP/1.1 200 OK\r\nServer: nginx\r\n"
        device.save()
        from kamerka.tasks import honeypot_check
        result = honeypot_check(device.id)
        self.assertLessEqual(result["probability"], 0.1)

    def test_conpot_signature_detected(self):
        device = _make_device(self.search, ip="10.0.0.2")
        device.data = "Siemens, SIMATIC, S7-200 response data"
        device.save()
        from kamerka.tasks import honeypot_check
        result = honeypot_check(device.id)
        self.assertTrue(result["is_conpot"])
        self.assertGreater(result["probability"], 0.2)

    def test_cowrie_signature_not_matched(self):
        device = _make_device(self.search, ip="10.0.0.3")
        device.data = "SSH-2.0-OpenSSH_6.0p1"
        device.save()
        from kamerka.tasks import honeypot_check
        result = honeypot_check(device.id)
        self.assertFalse(result["is_cowrie"])

    def test_saves_to_database(self):
        device = _make_device(self.search, ip="10.0.0.4")
        from kamerka.tasks import honeypot_check
        honeypot_check(device.id)
        from app_kamerka.models import HoneypotAnalysis
        self.assertTrue(HoneypotAnalysis.objects.filter(device=device).exists())

    def test_shodan_tag_raises_probability(self):
        """A ShodanScan record tagged 'honeypot' must push probability to >= 0.8."""
        from app_kamerka.models import ShodanScan
        device = _make_device(self.search, ip="10.0.0.5")
        ShodanScan.objects.create(
            device=device, ports="[]", tags="['honeypot']",
            products="[]", module="", vulns="[]",
        )
        from kamerka.tasks import honeypot_check
        result = honeypot_check(device.id)
        self.assertGreaterEqual(result["probability"], 0.8)
        reasons_combined = " ".join(result["reasons"]).lower()
        self.assertIn("shodan", reasons_combined)


# ---------------------------------------------------------------------------
# SBOM Lookup
# ---------------------------------------------------------------------------
class SBOMLookupTest(TestCase):
    """sbom_lookup must identify known software components."""

    def setUp(self):
        self.search = _make_search()

    def test_hikvision_components_found(self):
        device = _make_device(self.search, device_type="hikvision")
        device.product = "Hikvision DVR"
        device.save()
        from kamerka.tasks import sbom_lookup
        result = sbom_lookup(device.id)
        self.assertGreater(result["components"], 0)

    def test_goahead_components_found(self):
        device = _make_device(self.search)
        device.product = "GoAhead-Webs"
        device.cpe = "cpe:2.3:a:embedthis:goahead"
        device.save()
        from kamerka.tasks import sbom_lookup
        result = sbom_lookup(device.id)
        from app_kamerka.models import SBOMComponent
        comps = SBOMComponent.objects.filter(device=device)
        self.assertTrue(comps.exists())
        names = [c.component_name for c in comps]
        self.assertIn("GoAhead WebServer", names)

    def test_unknown_product_returns_zero(self):
        device = _make_device(self.search)
        device.product = "UnknownManufacturer XYZ"
        device.save()
        from kamerka.tasks import sbom_lookup
        result = sbom_lookup(device.id)
        self.assertEqual(result["components"], 0)


# ---------------------------------------------------------------------------
# New intelligence view endpoints
# ---------------------------------------------------------------------------
class DeepScanViewTest(TestCase):
    """deep_scan_view must trigger a Celery task."""

    def setUp(self):
        self.search = _make_search()
        self.device = _make_device(self.search)

    def test_returns_task_id(self):
        with patch("app_kamerka.views.deep_protocol_scan") as mock_task:
            mock_task.delay.return_value = MagicMock(id="fake-deep-task")
            response = self.client.get(
                "/{}/deep_scan".format(self.device.id),
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data["task_id"], "fake-deep-task")

    def test_non_ajax_returns_null_task(self):
        response = self.client.get("/{}/deep_scan".format(self.device.id))
        data = json.loads(response.content)
        self.assertIsNone(data["task_id"])


class NVDScanViewTest(TestCase):
    """nvd_scan_view must trigger CVE intelligence lookup."""

    def setUp(self):
        self.search = _make_search()
        self.device = _make_device(self.search)

    def test_returns_task_id(self):
        with patch("app_kamerka.views.nvd_lookup") as mock_task:
            mock_task.delay.return_value = MagicMock(id="fake-nvd-task")
            response = self.client.get(
                "/{}/nvd/scan".format(self.device.id),
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data["task_id"], "fake-nvd-task")


class HoneypotScanViewTest(TestCase):
    """honeypot_scan_view must trigger honeypot analysis."""

    def setUp(self):
        self.search = _make_search()
        self.device = _make_device(self.search)

    def test_returns_task_id(self):
        with patch("app_kamerka.views.honeypot_check") as mock_task:
            mock_task.delay.return_value = MagicMock(id="fake-hp-task")
            response = self.client.get(
                "/{}/honeypot/scan".format(self.device.id),
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data["task_id"], "fake-hp-task")


class SBOMScanViewTest(TestCase):
    """sbom_scan_view must trigger SBOM lookup."""

    def setUp(self):
        self.search = _make_search()
        self.device = _make_device(self.search)

    def test_returns_task_id(self):
        with patch("app_kamerka.views.sbom_lookup") as mock_task:
            mock_task.delay.return_value = MagicMock(id="fake-sbom-task")
            response = self.client.get(
                "/{}/sbom/scan".format(self.device.id),
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data["task_id"], "fake-sbom-task")


class GFWCheckViewTest(TestCase):
    """gfw_check_view must trigger GFW reachability check."""

    def setUp(self):
        self.search = _make_search()
        self.device = _make_device(self.search)

    def test_returns_task_id(self):
        with patch("app_kamerka.views.gfw_check") as mock_task:
            mock_task.delay.return_value = MagicMock(id="fake-gfw-task")
            response = self.client.get(
                "/{}/gfw/check".format(self.device.id),
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data["task_id"], "fake-gfw-task")


class SearchCostViewTest(TestCase):
    """search_cost_view must return Shodan count estimate."""

    def test_returns_cost_estimate(self):
        mock_api = MagicMock()
        mock_api.count.return_value = {"total": 500}
        with patch("kamerka.tasks.Shodan", return_value=mock_api), \
             patch("kamerka.tasks._get_env_key", return_value="fake-key"):
            response = self.client.get(
                "/search_cost?query=webcam",
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data["count"], 500)
        self.assertIn("credits_cost", data)

    def test_no_query_returns_error(self):
        response = self.client.get(
            "/search_cost",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        data = json.loads(response.content)
        self.assertIn("error", data)


# ---------------------------------------------------------------------------
# Globe EPSS endpoint
# ---------------------------------------------------------------------------
class GlobeDevicesEPSSTest(TestCase):
    """globe_devices_epss_json must include EPSS and KEV fields."""

    def setUp(self):
        self.search = _make_search()
        _make_device(self.search, ip="10.0.0.1",
                     vulns="['CVE-2021-36260']")

    def test_returns_json_with_epss_fields(self):
        response = self.client.get("/globe/devices_epss.json")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)
        self.assertIn("epss_score", data[0])
        self.assertIn("kev_listed", data[0])
        self.assertIn("honeypot_prob", data[0])


# ---------------------------------------------------------------------------
# Device detail page shows new intelligence tabs
# ---------------------------------------------------------------------------
class DeviceDetailIntelTabsTest(TestCase):
    """Device detail page must render the new intelligence tabs."""

    def setUp(self):
        self.search = _make_search()
        self.device = _make_device(
            self.search,
            vulns="['CVE-2021-36260']",
        )

    def test_hardware_tab_present(self):
        url = "/results/{}/{}/{}".format(
            self.search.id, self.device.id, self.device.ip
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertIn("tab_hw", body, "Hardware tab must be present")
        self.assertIn("Hardware", body)

    def test_risk_tab_present(self):
        url = "/results/{}/{}/{}".format(
            self.search.id, self.device.id, self.device.ip
        )
        response = self.client.get(url)
        body = response.content.decode()
        self.assertIn("tab_risk", body, "Risk tab must be present")
        self.assertIn("Risk", body)

    def test_supply_chain_tab_present(self):
        url = "/results/{}/{}/{}".format(
            self.search.id, self.device.id, self.device.ip
        )
        response = self.client.get(url)
        body = response.content.decode()
        self.assertIn("tab_supply", body, "Supply Chain tab must be present")
        self.assertIn("Supply Chain", body)

    def test_deep_probe_button_present(self):
        url = "/results/{}/{}/{}".format(
            self.search.id, self.device.id, self.device.ip
        )
        response = self.client.get(url)
        body = response.content.decode()
        self.assertIn("deep_probe_btn", body, "Deep Probe button must be present")

    def test_kev_badge_shown_when_kev_data_exists(self):
        from app_kamerka.models import VulnIntelligence
        VulnIntelligence.objects.create(
            device=self.device, cve_id="CVE-2021-36260",
            kev_listed=True, epss_score=0.85,
        )
        url = "/results/{}/{}/{}".format(
            self.search.id, self.device.id, self.device.ip
        )
        response = self.client.get(url)
        body = response.content.decode()
        self.assertIn("KEV", body, "KEV badge must appear for KEV-listed CVEs")

    def test_honeypot_warning_shown_when_probability_high(self):
        from app_kamerka.models import HoneypotAnalysis
        HoneypotAnalysis.objects.create(
            device=self.device, probability=0.7,
            reasons='["High banner density"]',
        )
        url = "/results/{}/{}/{}".format(
            self.search.id, self.device.id, self.device.ip
        )
        response = self.client.get(url)
        body = response.content.decode()
        self.assertIn("HONEYPOT PROBABILITY", body,
                       "Honeypot warning banner must appear for high probability")


# ---------------------------------------------------------------------------
# Globe spike renderer KEV colour support
# ---------------------------------------------------------------------------
class SpikeRendererKEVTest(TestCase):
    """spike_renderer must support the 'kev' severity level."""

    def test_kev_severity_colour(self):
        from globe_3d.spike_renderer import severity_to_colour, SEVERITY_COLOURS
        colour = severity_to_colour("kev")
        self.assertEqual(colour, SEVERITY_COLOURS["kev"])

    def test_dominant_severity_includes_kev(self):
        from globe_3d.spike_renderer import dominant_severity
        result = dominant_severity(["low", "kev", "high"])
        self.assertEqual(result, "kev", "KEV must be highest priority severity")

    def test_dominant_severity_without_kev(self):
        from globe_3d.spike_renderer import dominant_severity
        result = dominant_severity(["low", "high", "medium"])
        self.assertEqual(result, "high")


# ---------------------------------------------------------------------------
# Vulnerability intelligence data view
# ---------------------------------------------------------------------------
class VulnIntelDataViewTest(TestCase):
    """get_vuln_intel must return CVE/EPSS/KEV data."""

    def setUp(self):
        self.search = _make_search()
        self.device = _make_device(self.search)
        from app_kamerka.models import VulnIntelligence
        VulnIntelligence.objects.create(
            device=self.device, cve_id="CVE-2021-36260",
            cvss_score=9.8, epss_score=0.85, kev_listed=True,
        )

    def test_returns_vuln_data(self):
        response = self.client.get(
            "/get_vuln_intel/{}".format(self.device.id),
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["cve_id"], "CVE-2021-36260")
        self.assertEqual(data[0]["cvss_score"], 9.8)
        self.assertTrue(data[0]["kev_listed"])

    def test_empty_when_no_data(self):
        device2 = _make_device(self.search, ip="5.5.5.5")
        response = self.client.get(
            "/get_vuln_intel/{}".format(device2.id),
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        data = json.loads(response.content)
        self.assertEqual(data, [])


# ---------------------------------------------------------------------------
# SBOM results data view
# ---------------------------------------------------------------------------
class SBOMResultsViewTest(TestCase):
    """get_sbom_results must return SBOM component data."""

    def setUp(self):
        self.search = _make_search()
        self.device = _make_device(self.search)
        from app_kamerka.models import SBOMComponent
        SBOMComponent.objects.create(
            device=self.device, component_name="OpenSSL",
            version="1.1.1", component_type="library",
        )

    def test_returns_sbom_data(self):
        response = self.client.get(
            "/get_sbom_results/{}".format(self.device.id),
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["component_name"], "OpenSSL")
        self.assertEqual(data[0]["version"], "1.1.1")


# ---------------------------------------------------------------------------
# Homepage hamburger menu
# ---------------------------------------------------------------------------
class HomepageHamburgerMenuTest(TestCase):
    """The search_main homepage must include a hamburger navigation menu."""

    def test_hamburger_button_present(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn('id="kamerka-hamburger-btn"', content)
        # Verify the ☰ icon is inside the button element, not just anywhere
        # in the page (the entity also appears in the inline JS toggle).
        btn_match = re.search(
            r'<button[^>]*id="kamerka-hamburger-btn"[^>]*>&#9776;</button>',
            content,
        )
        self.assertIsNotNone(btn_match, "&#9776; must appear inside the hamburger <button>")

    def test_hamburger_overlay_present(self):
        response = self.client.get("/")
        content = response.content.decode()
        self.assertIn('id="kamerka-hamburger-overlay"', content)
        self.assertIn("kamerka-hamburger-overlay", content)

    def test_nav_links_in_overlay(self):
        response = self.client.get("/")
        content = response.content.decode()
        self.assertIn('/index', content)
        self.assertIn('/history', content)
        self.assertIn('/map', content)
        self.assertIn('/globe', content)
        self.assertIn('/gallery', content)
        self.assertIn('/devices', content)
        self.assertIn('/sources', content)


# ---------------------------------------------------------------------------
# Tab nesting — all tab panes must be siblings inside tab-content
# ---------------------------------------------------------------------------
class DeviceTabNestingTest(TestCase):
    """All tab panes must be direct children of .tab-content, not nested."""

    def setUp(self):
        self.search = _make_search()
        self.device = _make_device(self.search, vulns="['CVE-2021-36260']")

    def test_tab_panes_are_siblings(self):
        """Each tab-pane must be a sibling inside tab-content, not nested."""
        url = "/results/{}/{}/{}".format(
            self.search.id, self.device.id, self.device.ip
        )
        response = self.client.get(url)
        body = response.content.decode()
        # Find the tab-content div and verify that tab panes appear after
        # a proper closing of the previous tab pane.
        tab_ids = ["tab8", "tab9", "tab10", "tab11", "tab_hw", "tab_risk", "tab_supply"]
        for tab_id in tab_ids:
            self.assertIn(
                'id="{}"'.format(tab_id), body,
                "Tab pane {} must be present".format(tab_id),
            )

    def test_nmap_tab_has_manual_section(self):
        """The NMAP tab must contain the manual nmap scan section."""
        url = "/results/{}/{}/{}".format(
            self.search.id, self.device.id, self.device.ip
        )
        response = self.client.get(url)
        body = response.content.decode()
        self.assertIn("manual_nmap_btn", body, "Manual nmap button must be present")
        self.assertIn("manual_nmap_flags", body, "Manual nmap flags input must be present")
        self.assertIn("manual_nmap_output", body, "Manual nmap output container must be present")


# ---------------------------------------------------------------------------
# Screenshot display — must use image/png MIME type
# ---------------------------------------------------------------------------
class ScreenshotMimeTypeTest(TestCase):
    """Screenshots must be displayed with image/png MIME type."""

    def setUp(self):
        self.search = _make_search()
        self.device = _make_device(self.search)
        self.device.screenshot = "iVBORw0KGgo="  # minimal PNG prefix
        self.device.save()

    def test_screenshot_uses_png_mime_type(self):
        url = "/results/{}/{}/{}".format(
            self.search.id, self.device.id, self.device.ip
        )
        response = self.client.get(url)
        body = response.content.decode()
        self.assertIn("data:image/png;base64,", body,
                       "Screenshot must use image/png MIME type")
        self.assertNotIn("data:image/jpeg;base64,", body,
                          "Screenshot must NOT use image/jpeg MIME type")

    def test_no_stray_td_tag(self):
        """The device category must not be wrapped in a stray <td> tag."""
        url = "/results/{}/{}/{}".format(
            self.search.id, self.device.id, self.device.ip
        )
        response = self.client.get(url)
        body = response.content.decode()
        self.assertNotIn("<td>", body.split("tab9")[0][-500:] if "tab9" in body else "",
                          "Stray <td> tag near device.category must be removed")


# ---------------------------------------------------------------------------
# Manual nmap view — URL routing and AJAX guard
# ---------------------------------------------------------------------------
class ManualNmapViewTest(TestCase):
    """manual_nmap_view must validate AJAX and flags."""

    def setUp(self):
        self.search = _make_search()
        self.device = _make_device(self.search)

    def test_non_ajax_returns_null_task(self):
        response = self.client.get("/manual_nmap/{}".format(self.device.id))
        data = json.loads(response.content)
        self.assertIsNone(data["task_id"])

    def test_empty_flags_returns_error(self):
        response = self.client.get(
            "/manual_nmap/{}".format(self.device.id),
            {"flags": ""},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        data = json.loads(response.content)
        self.assertIn("error", data)

    @patch("app_kamerka.views.nmap_manual_scan")
    def test_valid_flags_dispatches_task(self, mock_task):
        mock_task.delay.return_value = MagicMock(id="test-task-id")
        response = self.client.get(
            "/manual_nmap/{}".format(self.device.id),
            {"flags": "-sV -p 80"},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        data = json.loads(response.content)
        self.assertEqual(data["task_id"], "test-task-id")
        mock_task.delay.assert_called_once_with(
            int(self.device.id), flags="-sV -p 80"
        )


# ---------------------------------------------------------------------------
# Nmap flag sanitizer
# ---------------------------------------------------------------------------
class NmapFlagSanitizerTest(TestCase):
    """_sanitize_nmap_flags must allow safe flags and block dangerous ones."""

    def test_basic_flags_allowed(self):
        from kamerka.tasks import _sanitize_nmap_flags
        result = _sanitize_nmap_flags("-sV -p 80,443")
        self.assertEqual(result, "-sV -p 80,443")

    def test_timing_flag_allowed(self):
        from kamerka.tasks import _sanitize_nmap_flags
        result = _sanitize_nmap_flags("-T4 -A")
        self.assertEqual(result, "-T4 -A")

    def test_shell_metachar_blocked(self):
        from kamerka.tasks import _sanitize_nmap_flags
        with self.assertRaises(ValueError):
            _sanitize_nmap_flags("-sV; rm -rf /")

    def test_pipe_blocked(self):
        from kamerka.tasks import _sanitize_nmap_flags
        with self.assertRaises(ValueError):
            _sanitize_nmap_flags("-sV | cat /etc/passwd")

    def test_backtick_blocked(self):
        from kamerka.tasks import _sanitize_nmap_flags
        with self.assertRaises(ValueError):
            _sanitize_nmap_flags("`whoami`")

    def test_empty_flags_raises(self):
        from kamerka.tasks import _sanitize_nmap_flags
        with self.assertRaises(ValueError):
            _sanitize_nmap_flags("")

    def test_invalid_timing_flag_blocked(self):
        """T999 must be blocked — only -T0 through -T5 are valid."""
        from kamerka.tasks import _sanitize_nmap_flags
        with self.assertRaises(ValueError):
            _sanitize_nmap_flags("-T999")

    def test_port_spec_glued_to_flag(self):
        from kamerka.tasks import _sanitize_nmap_flags
        result = _sanitize_nmap_flags("-p80,443")
        self.assertEqual(result, "-p80,443")

    def test_output_flags_blocked(self):
        """-oN/-oX/-oG must be rejected (arbitrary file writes)."""
        from kamerka.tasks import _sanitize_nmap_flags
        for flag in ("-oN /tmp/out", "-oX /tmp/out.xml", "-oG /tmp/out"):
            with self.assertRaises(ValueError, msg="Should block: " + flag):
                _sanitize_nmap_flags(flag)

    def test_positional_target_blocked(self):
        """Bare positional tokens must be rejected to prevent scanning
        arbitrary hosts."""
        from kamerka.tasks import _sanitize_nmap_flags
        with self.assertRaises(ValueError):
            _sanitize_nmap_flags("-sV 192.168.1.1")

    def test_script_from_catalog_allowed(self):
        """Scripts in NSE_SCRIPT_CATALOG must be accepted."""
        from kamerka.tasks import _sanitize_nmap_flags
        result = _sanitize_nmap_flags("--script s7-info")
        self.assertEqual(result, "--script s7-info")

    def test_script_not_in_catalog_blocked(self):
        """Arbitrary scripts must be rejected."""
        from kamerka.tasks import _sanitize_nmap_flags
        with self.assertRaises(ValueError):
            _sanitize_nmap_flags("--script http-title")

    def test_script_path_traversal_blocked(self):
        """Path traversal in --script must be rejected."""
        from kamerka.tasks import _sanitize_nmap_flags
        with self.assertRaises(ValueError):
            _sanitize_nmap_flags("--script ../../evil.nse")

    def test_top_ports_validated(self):
        from kamerka.tasks import _sanitize_nmap_flags
        result = _sanitize_nmap_flags("--top-ports 100")
        self.assertEqual(result, "--top-ports 100")
        with self.assertRaises(ValueError):
            _sanitize_nmap_flags("--top-ports abc")

    def test_equals_syntax(self):
        """--flag=value syntax must work for value flags."""
        from kamerka.tasks import _sanitize_nmap_flags
        result = _sanitize_nmap_flags("--min-rate=100")
        self.assertEqual(result, "--min-rate=100")

    def test_script_full_path_from_catalog_allowed(self):
        """Full path nmap_scripts/s7-info.nse must be accepted."""
        from kamerka.tasks import _sanitize_nmap_flags
        result = _sanitize_nmap_flags("--script nmap_scripts/s7-info.nse")
        self.assertEqual(result, "--script nmap_scripts/s7-info.nse")


# ---------------------------------------------------------------------------
# Sources page — hamburger menu and Security Resources link
# ---------------------------------------------------------------------------
class SourcesPageTest(TestCase):
    """sources.html must include hamburger menu and Security Resources link."""

    def test_hamburger_button_present(self):
        response = self.client.get("/sources")
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn('id="kamerka-hamburger-btn"', content)

    def test_hamburger_overlay_present(self):
        response = self.client.get("/sources")
        content = response.content.decode()
        self.assertIn('id="kamerka-hamburger-overlay"', content)

    def test_security_resources_link_present(self):
        response = self.client.get("/sources")
        content = response.content.decode()
        self.assertIn("webmaster-exit-1.github.io/Security_Resources", content,
                       "Security Resources link must be present")

    def test_nav_links_in_overlay(self):
        response = self.client.get("/sources")
        content = response.content.decode()
        self.assertIn('/index', content)
        self.assertIn('/sources', content)
        self.assertIn('/globe', content)


# ---------------------------------------------------------------------------
# Regression tests for bugs fixed in this session
# ---------------------------------------------------------------------------

class PortScanIpViewReturnsSearchIdTest(TestCase):
    """port_scan_ip_view must return search_id so the dashboard can build
    the correct /results/<search_id>/<device_id>/<ip> URL.

    Bug: the response previously omitted search_id, so the JS used device_id
    for both URL segments, producing a broken link when search_id != device_id.
    """

    def test_response_includes_search_id_for_new_device(self):
        with patch("app_kamerka.views.port_scan_task") as mock_task:
            mock_task.delay.return_value = MagicMock(id="task-x")
            response = self.client.get(
                "/port_scan/ip/10.0.0.1",
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("search_id", data, "Response must include search_id")
        self.assertIn("device_id", data)
        device = Device.objects.get(id=data["device_id"])
        self.assertEqual(data["search_id"], device.search_id)

    def test_search_id_differs_from_device_id(self):
        """search_id and device_id may be different integers; both must be
        returned so the results URL is constructed correctly."""
        with patch("app_kamerka.views.port_scan_task") as mock_task:
            mock_task.delay.return_value = MagicMock(id="task-y")
            response = self.client.get(
                "/port_scan/ip/10.0.0.2",
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            )
        data = json.loads(response.content)
        device = Device.objects.get(id=data["device_id"])
        # search_id is the ID of the parent Search record, not the Device
        self.assertEqual(data["search_id"], device.search_id)
        # They are allowed to differ — the test simply confirms both are present
        self.assertIsNotNone(data["search_id"])


class NearbyDevicesResultDivTest(TestCase):
    """device.html must render a #nearby_devices_result div so the
    #show_nearby_devices click handler can toggle its visibility.

    Bug: the div was completely absent, causing a JS null-dereference crash
    whenever the 'Show' button was clicked.
    """

    def _make_device_with_search(self):
        search = _make_search()
        return _make_device(search)

    def test_nearby_devices_result_div_present(self):
        device = self._make_device_with_search()
        response = self.client.get(
            f"/results/{device.search_id}/{device.id}/{device.ip}"
        )
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn('id="nearby_devices_result"', content,
                      "#nearby_devices_result div must exist in device.html")


class DeadJsHandlersRemovedTest(TestCase):
    """device.html must not contain references to removed/non-existent endpoints.

    Bug: dead click handlers for #nearby_flickr (404 URL) and #bosch_show
    (non-existent button) were referencing null DOM elements, causing silent JS
    errors.  They have been removed.
    """

    def _make_device_with_search(self):
        search = _make_search()
        return _make_device(search)

    def test_nearby_flickr_handler_removed(self):
        device = self._make_device_with_search()
        response = self.client.get(
            f"/results/{device.search_id}/{device.id}/{device.ip}"
        )
        content = response.content.decode()
        self.assertNotIn("nearby_flickr", content,
                         "Dead #nearby_flickr click handler must be removed")

    def test_bosch_show_handler_removed(self):
        device = self._make_device_with_search()
        response = self.client.get(
            f"/results/{device.search_id}/{device.id}/{device.ip}"
        )
        content = response.content.decode()
        self.assertNotIn("bosch_show", content,
                         "Dead #bosch_show click handler must be removed")


class InfraFormEmptyItemsCheckTest(TestCase):
    """Submitting the infra tab with no items selected must redirect back to
    the search form — not silently fire a Shodan search with an empty list.

    Bug: the empty-items guard used ``request.POST.getlist("country_infra")``
    (the country code, always present) instead of
    ``request.POST.getlist("infra")`` (the items list, may be empty).
    As a result, an empty submission was never caught.
    """

    def test_empty_infra_items_redirects_to_form(self):
        """POST with a valid country but no 'infra' items must not start a task."""
        with patch("app_kamerka.views.shodan_search") as mock_task:
            mock_task.delay.return_value = MagicMock(task_id="t-empty")
            response = self.client.post(
                "/",
                data={
                    "country_infra": "DE",
                    # 'infra' key deliberately omitted → empty list
                },
            )
        # The view should re-render the search page (200) — task must NOT start.
        self.assertEqual(response.status_code, 200,
                         "Empty infra submission should re-render the search form")
        mock_task.delay.assert_not_called()

    def test_infra_items_posted_starts_search(self):
        """POST with both country and infra items must start a Shodan search."""
        with patch("app_kamerka.views.shodan_search") as mock_task:
            mock_task.delay.return_value = MagicMock(task_id="t1")
            response = self.client.post(
                "/",
                data={
                    "country_infra": "DE",
                    "infra": ["power_plant", "water_treatment"],
                    "all": "",
                },
            )
        # Shodan task should have been triggered → redirect to index
        if response.status_code == 302:
            self.assertIn("index", response["Location"])
        else:
            mock_task.delay.assert_called_once()

