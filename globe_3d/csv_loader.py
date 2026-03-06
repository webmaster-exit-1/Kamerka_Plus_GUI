"""
globe_3d/csv_loader.py – Parse CSV exports into globe device dicts.

Two CSV schemas are supported transparently:

**App export** (``kamerka.tasks.shodan_csv_export`` → ``/export/csv/<id>``)::

    IP_Address, Latitude, Longitude, Severity_Count,
    Vendor_Name, Network_Port, Organization, City,
    Country_Code, Device_Type

**Shodan-CLI** (``shodan convert <file.json.gz> csv``)::

    data, hostnames, ip, ip_str, ipv6, org, isp,
    location.country_code, location.city, location.country_name,
    location.latitude, location.longitude,
    os, asn, port, tags, timestamp, transport, product, version, vulns, ...

The schema is detected automatically from the column headers present in the
first row of the file.

Usage
-----
    from globe_3d.csv_loader import load_csv

    devices = load_csv("/path/to/export.csv")
    globe_widget.load_devices(devices)
"""

from __future__ import annotations

import csv
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _severity_from_cve_list(vulns_str: str) -> str:
    """Derive a severity label from the ``vulns`` column value.

    The ``vulns`` column produced by ``shodan convert csv`` is a
    comma-separated string of CVE IDs, e.g. ``"CVE-2021-1234,CVE-2021-5678"``.
    An empty string means no known vulnerabilities.

    Returns
    -------
    str
        ``"unknown"`` / ``"low"`` / ``"medium"`` / ``"high"`` / ``"critical"``
        based on CVE count.
    """
    if not vulns_str or not vulns_str.strip():
        return "unknown"
    cve_count = len([c for c in vulns_str.split(",") if c.strip()])
    return _severity_from_count(cve_count)


def _severity_from_count(count: int) -> str:
    """Derive a severity label from a numeric vulnerability count.

    Used when the CSV was exported via ``shodan_csv_export``
    (``Severity_Count`` column).
    """
    if count <= 0:
        return "unknown"
    if count <= 2:
        return "low"
    if count <= 5:
        return "medium"
    if count <= 10:
        return "high"
    return "critical"


def load_csv(path: str) -> List[Dict[str, Any]]:
    """Parse a ``shodan convert`` CSV file and return a list of device dicts.

    Tolerant of missing columns and skips rows whose latitude/longitude
    cannot be parsed as floats.

    Parameters
    ----------
    path : str
        Absolute path to the ``.csv`` file produced by
        ``shodan convert <export.json.gz> csv``.

    Returns
    -------
    list[dict]
        Device dicts compatible with ``GlobeWidget.load_devices()``.
        Returns an empty list when the file cannot be read or all rows
        are invalid.
    """
    devices: List[Dict[str, Any]] = []
    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                device = _row_to_device(row)
                if device is not None:
                    devices.append(device)
    except OSError as exc:
        logger.warning("csv_loader: could not open %s — %s", path, exc)
    return devices


def _row_to_device(row: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """Convert one CSV row to a device dict.

    Supports two schemas automatically:

    * **App export** (``shodan_csv_export``): column names include
      ``Latitude``, ``Longitude``, ``IP_Address``, ``Network_Port``,
      ``Vendor_Name``, ``Organization``, ``City``, ``Country_Code``,
      ``Device_Type``, ``Severity_Count``.
    * **Shodan-CLI** (``shodan convert csv``): column names include
      ``location.latitude``, ``location.longitude``, ``ip_str``, ``port``,
      ``product``, ``org``, ``location.city``, ``location.country_code``,
      ``os``, ``vulns``.

    For each field the app-export column is tried first; the Shodan-CLI
    column name is used as a fallback.  Returns ``None`` when the row lacks
    valid coordinates.
    """
    # Coordinates — app export uses "Latitude"/"Longitude";
    # Shodan-CLI uses "location.latitude"/"location.longitude"
    lat_raw = row.get("Latitude") or row.get("location.latitude") or ""
    lon_raw = row.get("Longitude") or row.get("location.longitude") or ""
    try:
        lat = float(lat_raw)
        lon = float(lon_raw)
    except ValueError:
        return None

    ip = (
        row.get("IP_Address")
        or row.get("ip_str")
        or row.get("ip")
        or row.get("ipv6")
        or ""
    ).strip()
    port = (row.get("Network_Port") or row.get("port") or "").strip()
    product = (row.get("Vendor_Name") or row.get("product") or "").strip()
    org = (row.get("Organization") or row.get("org") or "").strip()
    city = (row.get("City") or row.get("location.city") or "").strip()
    country_code = (
        row.get("Country_Code") or row.get("location.country_code") or ""
    ).strip()
    device_type = (row.get("Device_Type") or row.get("os") or product).strip()
    vulns_str = (row.get("vulns") or "").strip()
    data = (row.get("data") or "").strip()

    # Severity — prefer Severity_Count integer (app export) over CVE list
    severity_count_raw = row.get("Severity_Count", "").strip()
    if severity_count_raw:
        try:
            severity = _severity_from_count(int(severity_count_raw))
        except ValueError:
            severity = _severity_from_cve_list(vulns_str)
    else:
        severity = _severity_from_cve_list(vulns_str)

    return {
        "ip": ip,
        "lat": lat,
        "lon": lon,
        "port": port,
        "product": product,
        "org": org,
        "city": city,
        "country_code": country_code,
        "type": device_type,
        "vulns": vulns_str,
        "severity": severity,
        "nuclei_results": [],
        "data": data,
        "notes": "",
        "_source": "csv",
    }
