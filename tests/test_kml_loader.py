"""Tests for globe_3d/kml_loader.py

KML files are produced by ``shodan convert <file.json.gz> kml``.
Format per Placemark:
  <name><![CDATA[<h1 ...>IP_ADDRESS</h1>]]></name>
  <description><![CDATA[...HTML with <span>PORT</span> elements...]]></description>
  <Point><coordinates>lon,lat</coordinates></Point>
No <ExtendedData> is written by shodan convert.
"""

import os
import textwrap
import tempfile
import pytest

from globe_3d.kml_loader import (
    load_kml,
    _extract_ip_from_name,
    _extract_ports_from_description,
)


def _write_kml(content):
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".kml", delete=False, encoding="utf-8"
    )
    f.write(textwrap.dedent(content))
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# Minimal valid KML matching shodan convert output (with namespace)
# ---------------------------------------------------------------------------
SHODAN_KML_ONE_HOST = """\
<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <Placemark>
      <name><![CDATA[<h1 style="margin-bottom:0;padding-bottom:0;font-size:1.5em">1.2.3.4</h1>]]></name>
      <description><![CDATA[<h2>Ports</h2><ul>
        <li><span style="color:#FFF;width:48px;">80</span></li>
        <li><span style="color:#FFF;width:48px;">443</span></li>
      </ul>]]></description>
      <Point><coordinates>-74.0060,40.7128</coordinates></Point>
    </Placemark>
  </Document>
</kml>
"""

SHODAN_KML_TWO_HOSTS = """\
<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <Placemark>
      <name><![CDATA[<h1>5.6.7.8</h1>]]></name>
      <description><![CDATA[<span>22</span>]]></description>
      <Point><coordinates>10.0,20.0</coordinates></Point>
    </Placemark>
    <Placemark>
      <name><![CDATA[<h1>9.9.9.9</h1>]]></name>
      <description><![CDATA[<span>53</span><span>853</span>]]></description>
      <Point><coordinates>-0.12,51.5</coordinates></Point>
    </Placemark>
  </Document>
</kml>
"""


class TestExtractIpFromName:
    def test_bare_ip(self):
        assert _extract_ip_from_name("1.2.3.4") == "1.2.3.4"

    def test_h1_wrapped(self):
        assert _extract_ip_from_name('<h1 style="font-size:1.5em">1.2.3.4</h1>') == "1.2.3.4"

    def test_empty_string(self):
        assert _extract_ip_from_name("") == ""

    def test_strips_all_tags(self):
        assert _extract_ip_from_name("<b><i>10.0.0.1</i></b>") == "10.0.0.1"

    def test_ipv6(self):
        assert _extract_ip_from_name("<h1>2001:db8::1</h1>") == "2001:db8::1"


class TestExtractPortsFromDescription:
    def test_single_port(self):
        assert _extract_ports_from_description('<span style="color:#FFF">80</span>') == "80"

    def test_multiple_ports(self):
        result = _extract_ports_from_description(
            '<span style="color:#FFF">80</span>'
            '<span style="color:#FFF">443</span>'
            '<span style="color:#FFF">22</span>'
        )
        assert result == "80,443,22"

    def test_no_ports(self):
        assert _extract_ports_from_description("<p>no ports here</p>") == ""

    def test_empty_string(self):
        assert _extract_ports_from_description("") == ""

    def test_whitespace_around_port_number(self):
        assert _extract_ports_from_description("<span>  8080  </span>") == "8080"


class TestLoadKml:
    def test_nonexistent_file_returns_empty(self):
        assert load_kml("/nonexistent/path/to/file.kml") == []

    def test_malformed_xml_returns_empty(self):
        path = _write_kml("<this is not valid xml><<>>")
        try:
            assert load_kml(path) == []
        finally:
            os.unlink(path)

    def test_single_host_parsed(self):
        path = _write_kml(SHODAN_KML_ONE_HOST)
        try:
            devices = load_kml(path)
        finally:
            os.unlink(path)
        assert len(devices) == 1
        d = devices[0]
        assert d["ip"] == "1.2.3.4"
        assert d["lat"] == pytest.approx(40.7128)
        assert d["lon"] == pytest.approx(-74.0060)
        assert d["_source"] == "kml"

    def test_coordinates_are_lon_lat_order(self):
        # coordinates in file are lon,lat — loader must assign them correctly
        path = _write_kml(SHODAN_KML_ONE_HOST)
        try:
            devices = load_kml(path)
        finally:
            os.unlink(path)
        assert devices[0]["lon"] == pytest.approx(-74.0060)
        assert devices[0]["lat"] == pytest.approx(40.7128)

    def test_ports_extracted_from_description(self):
        path = _write_kml(SHODAN_KML_ONE_HOST)
        try:
            devices = load_kml(path)
        finally:
            os.unlink(path)
        assert "80" in devices[0]["port"]
        assert "443" in devices[0]["port"]

    def test_two_hosts_both_parsed(self):
        path = _write_kml(SHODAN_KML_TWO_HOSTS)
        try:
            devices = load_kml(path)
        finally:
            os.unlink(path)
        assert len(devices) == 2
        ips = {d["ip"] for d in devices}
        assert ips == {"5.6.7.8", "9.9.9.9"}

    def test_second_host_ports(self):
        path = _write_kml(SHODAN_KML_TWO_HOSTS)
        try:
            devices = load_kml(path)
        finally:
            os.unlink(path)
        d = next(d for d in devices if d["ip"] == "9.9.9.9")
        assert "53" in d["port"]
        assert "853" in d["port"]

    def test_placemark_missing_coordinates_skipped(self):
        kml = """\
        <?xml version="1.0" encoding="UTF-8"?>
        <kml xmlns="http://www.opengis.net/kml/2.2">
          <Document>
            <Placemark>
              <name><![CDATA[<h1>1.2.3.4</h1>]]></name>
            </Placemark>
            <Placemark>
              <name><![CDATA[<h1>5.6.7.8</h1>]]></name>
              <Point><coordinates>10.0,20.0</coordinates></Point>
            </Placemark>
          </Document>
        </kml>
        """
        path = _write_kml(kml)
        try:
            devices = load_kml(path)
        finally:
            os.unlink(path)
        assert len(devices) == 1
        assert devices[0]["ip"] == "5.6.7.8"

    def test_placemark_bad_coordinates_skipped(self):
        kml = """\
        <?xml version="1.0" encoding="UTF-8"?>
        <kml xmlns="http://www.opengis.net/kml/2.2">
          <Document>
            <Placemark>
              <name><![CDATA[<h1>bad</h1>]]></name>
              <Point><coordinates>notanumber,alsobad</coordinates></Point>
            </Placemark>
            <Placemark>
              <name><![CDATA[<h1>5.6.7.8</h1>]]></name>
              <Point><coordinates>10.0,20.0</coordinates></Point>
            </Placemark>
          </Document>
        </kml>
        """
        path = _write_kml(kml)
        try:
            devices = load_kml(path)
        finally:
            os.unlink(path)
        assert len(devices) == 1

    def test_required_keys_present(self):
        path = _write_kml(SHODAN_KML_ONE_HOST)
        try:
            devices = load_kml(path)
        finally:
            os.unlink(path)
        required = {"ip", "lat", "lon", "port", "product", "org",
                    "country_code", "city", "type", "vulns", "severity",
                    "nuclei_results", "data", "notes", "_source"}
        assert required.issubset(devices[0].keys())

    def test_severity_is_unknown(self):
        # shodan convert KML has no vulnerability data → always unknown
        path = _write_kml(SHODAN_KML_ONE_HOST)
        try:
            devices = load_kml(path)
        finally:
            os.unlink(path)
        assert devices[0]["severity"] == "unknown"

    def test_nuclei_results_always_empty(self):
        path = _write_kml(SHODAN_KML_ONE_HOST)
        try:
            devices = load_kml(path)
        finally:
            os.unlink(path)
        assert devices[0]["nuclei_results"] == []

