"""
globe_3d/csv_loader.py – Parse ``shodan convert`` CSV exports into globe device dicts.

``shodan convert <file.json.gz> csv`` writes one row per banner with these columns::

    data, hostnames, ip, ip_str, ipv6, org, isp,
    location.country_code, location.city, location.country_name,
    location.latitude, location.longitude,
    os, asn, port, tags, timestamp, transport, product, version, vulns,
    ssl.cipher.version, ssl.cipher.bits, ssl.cipher.name, ssl.alpn,
    ssl.versions, ssl.cert.serial, ssl.cert.fingerprint.sha1,
    ssl.cert.fingerprint.sha256, html, title

The ``vulns`` column is a comma-separated list of CVE IDs produced by
``list(banner['vulns'].keys())``.

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
    if cve_count <= 0:
        return "unknown"
    if cve_count <= 2:
        return "low"
    if cve_count <= 5:
        return "medium"
    if cve_count <= 10:
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
    """Convert one CSV row from ``shodan convert csv`` output to a device dict.

    Returns ``None`` when the row lacks valid coordinates.
    """
    try:
        lat = float(row.get("location.latitude") or "")
        lon = float(row.get("location.longitude") or "")
    except ValueError:
        return None

    ip = (row.get("ip_str") or row.get("ip") or row.get("ipv6") or "").strip()
    port = (row.get("port") or "").strip()
    product = (row.get("product") or "").strip()
    org = (row.get("org") or "").strip()
    city = (row.get("location.city") or "").strip()
    country_code = (row.get("location.country_code") or "").strip()
    vulns_str = (row.get("vulns") or "").strip()
    data = (row.get("data") or "").strip()
    device_type = (row.get("os") or product).strip()

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
        "severity": _severity_from_cve_list(vulns_str),
        "nuclei_results": [],
        "data": data,
        "notes": "",
        "_source": "csv",
    }
