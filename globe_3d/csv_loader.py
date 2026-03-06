"""
globe_3d/csv_loader.py – Parse Kamerka CSV exports into globe device dicts.

The CSV files produced by ``shodan_csv_export`` have these columns::

    IP_Address, Latitude, Longitude, Severity_Count, Vendor_Name,
    Network_Port, Organization, City, Country_Code, Device_Type

This module converts each row into the dict schema expected by
``GlobeWidget.load_devices()``.

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

# ---------------------------------------------------------------------------
# Severity mapping from the numeric ``Severity_Count`` column
# ---------------------------------------------------------------------------

def _severity_from_count(count: int) -> str:
    """Map a CVE count to a severity label used by the spike renderer."""
    if count <= 0:
        return "unknown"
    if count <= 2:
        return "low"
    if count <= 5:
        return "medium"
    if count <= 10:
        return "high"
    return "critical"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_csv(path: str) -> List[Dict[str, Any]]:
    """Parse a Kamerka CSV export file and return a list of device dicts.

    The function is tolerant of missing or extra columns and skips rows
    whose ``Latitude`` / ``Longitude`` values cannot be parsed as floats.

    Parameters
    ----------
    path : str
        Absolute path to the ``.csv`` file produced by
        ``kamerka.tasks.shodan_csv_export``.

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
    """Convert one CSV row dict to a device dict.

    Returns ``None`` when the row lacks valid coordinates.
    """
    try:
        lat = float(row.get("Latitude") or row.get("lat") or "")
        lon = float(row.get("Longitude") or row.get("lon") or "")
    except ValueError:
        return None

    severity_count_raw = row.get("Severity_Count", "0") or "0"
    try:
        severity_count = int(float(severity_count_raw))
    except ValueError:
        severity_count = 0

    severity = _severity_from_count(severity_count)

    ip = (row.get("IP_Address") or row.get("ip") or "").strip()
    port = (row.get("Network_Port") or row.get("port") or "").strip()
    product = (row.get("Vendor_Name") or row.get("product") or "").strip()
    org = (row.get("Organization") or row.get("org") or "").strip()
    city = (row.get("City") or row.get("city") or "").strip()
    country_code = (row.get("Country_Code") or row.get("country_code") or "").strip()
    device_type = (row.get("Device_Type") or row.get("type") or product).strip()

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
        "vulns": "",
        "severity": severity,
        "nuclei_results": [],
        "data": "",
        "notes": "",
        # Source tag so the UI can show where the record came from.
        "_source": "csv",
    }
