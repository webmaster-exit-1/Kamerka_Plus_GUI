"""Tests for globe_3d/csv_loader.py

Two CSV schemas are supported:

**App export** (``shodan_csv_export`` → ``/export/csv/<id>``):
    IP_Address, Latitude, Longitude, Severity_Count, Vendor_Name,
    Network_Port, Organization, City, Country_Code, Device_Type

**Shodan-CLI** (``shodan convert <file.json.gz> csv``):
    data, hostnames, ip, ip_str, ipv6, org, isp,
    location.country_code, location.city, location.country_name,
    location.latitude, location.longitude,
    os, asn, port, tags, timestamp, transport, product, version, vulns, ...
The ``vulns`` column is a comma-separated list of CVE IDs.
"""

import os
import textwrap
import tempfile
import pytest

from globe_3d.csv_loader import _severity_from_cve_list, _severity_from_count, load_csv

# Minimal header matching shodan convert csv output
_HEADER = (
    "data,hostnames,ip,ip_str,ipv6,org,isp,"
    "location.country_code,location.city,location.country_name,"
    "location.latitude,location.longitude,"
    "os,asn,port,tags,timestamp,transport,product,version,vulns"
)


def _write(content):
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".csv", delete=False, encoding="utf-8"
    )
    f.write(textwrap.dedent(content))
    f.close()
    return f.name


class TestSeverityFromCveList:
    def test_empty_string_is_unknown(self):
        assert _severity_from_cve_list("") == "unknown"

    def test_whitespace_only_is_unknown(self):
        assert _severity_from_cve_list("   ") == "unknown"

    def test_one_cve_is_low(self):
        assert _severity_from_cve_list("CVE-2021-1234") == "low"

    def test_two_cves_is_low(self):
        assert _severity_from_cve_list("CVE-2021-1234,CVE-2021-5678") == "low"

    def test_three_cves_is_medium(self):
        assert _severity_from_cve_list("CVE-1,CVE-2,CVE-3") == "medium"

    def test_five_cves_is_medium(self):
        assert _severity_from_cve_list(",".join(f"CVE-{i}" for i in range(5))) == "medium"

    def test_six_cves_is_high(self):
        assert _severity_from_cve_list(",".join(f"CVE-{i}" for i in range(6))) == "high"

    def test_ten_cves_is_high(self):
        assert _severity_from_cve_list(",".join(f"CVE-{i}" for i in range(10))) == "high"

    def test_eleven_cves_is_critical(self):
        assert _severity_from_cve_list(",".join(f"CVE-{i}" for i in range(11))) == "critical"


class TestLoadCsv:
    def test_nonexistent_file_returns_empty(self):
        assert load_csv("/nonexistent/path/file.csv") == []

    def test_valid_row_parsed_correctly(self):
        path = _write(
            f"{_HEADER}\n"
            "Banner data,host.example.com,1.2.3.4,1.2.3.4,,SomeOrg,SomeISP,"
            "US,New York,United States,"
            "40.7128,-74.0060,"
            'Linux,,80,,2024-01-01T00:00:00,tcp,Apache httpd,2.4.51,'
            '"CVE-2021-1234,CVE-2021-5678,CVE-2021-9999"\n'
        )
        try:
            devices = load_csv(path)
        finally:
            os.unlink(path)
        assert len(devices) == 1
        d = devices[0]
        assert d["ip"] == "1.2.3.4"
        assert d["lat"] == pytest.approx(40.7128)
        assert d["lon"] == pytest.approx(-74.0060)
        assert d["org"] == "SomeOrg"
        assert d["city"] == "New York"
        assert d["country_code"] == "US"
        assert d["port"] == "80"
        assert d["product"] == "Apache httpd"
        assert d["severity"] == "medium"   # 3 CVEs → medium
        assert d["_source"] == "csv"

    def test_row_missing_latitude_skipped(self):
        path = _write(
            f"{_HEADER}\n"
            ",,bad,,,,,"
            ",,,"
            ",,"         # lat and lon empty
            ",,80,,,,,\n"
            ",,5.6.7.8,5.6.7.8,,,,"
            ",,,"
            "10.0,20.0,"
            ",,22,,,,,\n"
        )
        try:
            devices = load_csv(path)
        finally:
            os.unlink(path)
        assert len(devices) == 1
        assert devices[0]["ip"] == "5.6.7.8"

    def test_row_non_numeric_latitude_skipped(self):
        path = _write(
            f"{_HEADER}\n"
            ",,1.2.3.4,1.2.3.4,,,,"
            ",,,"
            "notanumber,20.0,"
            ",,80,,,,,\n"
        )
        try:
            devices = load_csv(path)
        finally:
            os.unlink(path)
        assert devices == []

    def test_empty_vulns_gives_unknown_severity(self):
        path = _write(
            f"{_HEADER}\n"
            ",,1.2.3.4,1.2.3.4,,,,"
            "US,,,10.0,20.0,"
            ",,80,,,,,,\n"
        )
        try:
            devices = load_csv(path)
        finally:
            os.unlink(path)
        assert devices[0]["severity"] == "unknown"

    def test_many_cves_gives_critical_severity(self):
        cves = ",".join(f"CVE-2021-{i:04d}" for i in range(15))
        path = _write(
            f"{_HEADER}\n"
            f',,1.2.3.4,1.2.3.4,,,,'
            f'US,,,10.0,20.0,'
            f',,80,,,,,,"{cves}"\n'
        )
        try:
            devices = load_csv(path)
        finally:
            os.unlink(path)
        assert devices[0]["severity"] == "critical"

    def test_vulns_stored_verbatim(self):
        cves = "CVE-2021-1234,CVE-2021-5678"
        path = _write(
            f"{_HEADER}\n"
            f',,1.2.3.4,1.2.3.4,,,,'
            f',,,'
            f'10.0,20.0,'
            f',,80,,,,,,"{cves}"\n'
        )
        try:
            devices = load_csv(path)
        finally:
            os.unlink(path)
        assert devices[0]["vulns"] == cves

    def test_ip_str_preferred_over_ip(self):
        path = _write(
            f"{_HEADER}\n"
            ",,fallback,1.2.3.4,,,,"
            ",,,"
            "10.0,20.0,"
            ",,80,,,,,\n"
        )
        try:
            devices = load_csv(path)
        finally:
            os.unlink(path)
        assert devices[0]["ip"] == "1.2.3.4"

    def test_empty_file_returns_empty(self):
        path = _write(f"{_HEADER}\n")
        try:
            devices = load_csv(path)
        finally:
            os.unlink(path)
        assert devices == []

    def test_required_keys_present(self):
        path = _write(
            f"{_HEADER}\n"
            ",,1.2.3.4,1.2.3.4,,,,"
            ",,,"
            "10.0,20.0,"
            ",,80,,,,,\n"
        )
        try:
            devices = load_csv(path)
        finally:
            os.unlink(path)
        required = {"ip", "lat", "lon", "port", "product", "org", "city",
                    "country_code", "type", "vulns", "severity", "nuclei_results",
                    "data", "notes", "_source"}
        assert required.issubset(devices[0].keys())

    def test_nuclei_results_always_empty_list(self):
        path = _write(
            f"{_HEADER}\n"
            ",,1.2.3.4,1.2.3.4,,,,"
            ",,,"
            "10.0,20.0,"
            ",,80,,,,,\n"
        )
        try:
            devices = load_csv(path)
        finally:
            os.unlink(path)
        assert devices[0]["nuclei_results"] == []


# ── App export format (shodan_csv_export / /export/csv/<id>) ──────────────────

# Columns written by kamerka.tasks.shodan_csv_export
_APP_HEADER = (
    "IP_Address,Latitude,Longitude,Severity_Count,"
    "Vendor_Name,Network_Port,Organization,City,Country_Code,Device_Type"
)


class TestSeverityFromCount:
    def test_zero_is_unknown(self):
        assert _severity_from_count(0) == "unknown"

    def test_one_is_low(self):
        assert _severity_from_count(1) == "low"

    def test_two_is_low(self):
        assert _severity_from_count(2) == "low"

    def test_three_is_medium(self):
        assert _severity_from_count(3) == "medium"

    def test_five_is_medium(self):
        assert _severity_from_count(5) == "medium"

    def test_six_is_high(self):
        assert _severity_from_count(6) == "high"

    def test_ten_is_high(self):
        assert _severity_from_count(10) == "high"

    def test_eleven_is_critical(self):
        assert _severity_from_count(11) == "critical"


class TestLoadCsvAppExport:
    def test_app_export_row_parsed_correctly(self):
        path = _write(
            f"{_APP_HEADER}\n"
            "1.2.3.4,40.7128,-74.0060,3,"
            "Apache httpd,80,SomeOrg,New York,US,webcam\n"
        )
        try:
            devices = load_csv(path)
        finally:
            os.unlink(path)
        assert len(devices) == 1
        d = devices[0]
        assert d["ip"] == "1.2.3.4"
        assert d["lat"] == pytest.approx(40.7128)
        assert d["lon"] == pytest.approx(-74.0060)
        assert d["port"] == "80"
        assert d["product"] == "Apache httpd"
        assert d["org"] == "SomeOrg"
        assert d["city"] == "New York"
        assert d["country_code"] == "US"
        assert d["type"] == "webcam"
        assert d["severity"] == "medium"   # Severity_Count=3 → medium
        assert d["_source"] == "csv"

    def test_app_export_severity_count_zero_is_unknown(self):
        path = _write(
            f"{_APP_HEADER}\n"
            "1.2.3.4,10.0,20.0,0,Hikvision,554,,,,camera\n"
        )
        try:
            devices = load_csv(path)
        finally:
            os.unlink(path)
        assert devices[0]["severity"] == "unknown"

    def test_app_export_severity_count_high(self):
        path = _write(
            f"{_APP_HEADER}\n"
            "1.2.3.4,10.0,20.0,8,SomeProduct,80,,,,\n"
        )
        try:
            devices = load_csv(path)
        finally:
            os.unlink(path)
        assert devices[0]["severity"] == "high"

    def test_app_export_severity_count_critical(self):
        path = _write(
            f"{_APP_HEADER}\n"
            "1.2.3.4,10.0,20.0,15,SomeProduct,80,,,,\n"
        )
        try:
            devices = load_csv(path)
        finally:
            os.unlink(path)
        assert devices[0]["severity"] == "critical"

    def test_app_export_missing_lat_skipped(self):
        path = _write(
            f"{_APP_HEADER}\n"
            "1.2.3.4,,20.0,0,SomeProduct,80,,,,\n"
            "5.6.7.8,10.0,20.0,0,Other,80,,,,\n"
        )
        try:
            devices = load_csv(path)
        finally:
            os.unlink(path)
        assert len(devices) == 1
        assert devices[0]["ip"] == "5.6.7.8"

    def test_app_export_required_keys_present(self):
        path = _write(
            f"{_APP_HEADER}\n"
            "1.2.3.4,10.0,20.0,2,Prod,443,Org,City,DE,camera\n"
        )
        try:
            devices = load_csv(path)
        finally:
            os.unlink(path)
        required = {"ip", "lat", "lon", "port", "product", "org", "city",
                    "country_code", "type", "vulns", "severity", "nuclei_results",
                    "data", "notes", "_source"}
        assert required.issubset(devices[0].keys())
