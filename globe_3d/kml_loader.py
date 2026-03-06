"""
globe_3d/kml_loader.py – Parse Kamerka KML exports into globe device dicts.

The KML files produced by ``shodan_kml_export`` contain one ``<Placemark>``
per device.  Each Placemark has:

* ``<name>``          – ``"<product> - <ip>"``
* ``<Point><coordinates>``  – ``lon,lat[,alt]``
* ``<ExtendedData>``  – ``ip``, ``port``, ``product``, ``org``,
                          ``country_code``, ``vulns``

This module converts those placemarks into the dict schema expected by
``GlobeWidget.load_devices()`` and ``GlobeWidget.load_file()``.

Usage
-----
    from globe_3d.kml_loader import load_kml

    devices = load_kml("/path/to/export.kml")
    globe_widget.load_devices(devices)
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional


# KML namespace used by simplekml output.
_KML_NS = "http://www.opengis.net/kml/2.2"
# Alternate namespace some exporters use.
_KML_NS_ALT = ""


def _ns(tag: str, ns: str = _KML_NS) -> str:
    return "{%s}%s" % (ns, tag) if ns else tag


def _find_text(element: ET.Element, *tags: str, ns: str = _KML_NS) -> Optional[str]:
    """Descend through *tags* and return the text of the final element."""
    current = element
    for tag in tags:
        nxt = current.find(_ns(tag, ns))
        if nxt is None:
            # Retry without namespace (some minimal KML has no namespace)
            nxt = current.find(tag)
        if nxt is None:
            return None
        current = nxt
    return (current.text or "").strip() or None


def _parse_extended_data(placemark: ET.Element, ns: str) -> Dict[str, str]:
    """Extract all ``<Data name="…"><value>`` entries into a flat dict."""
    result: Dict[str, str] = {}
    ed = placemark.find(_ns("ExtendedData", ns)) or placemark.find("ExtendedData")
    if ed is None:
        return result
    for data_el in list(ed):
        name = data_el.get("name", "")
        val_el = data_el.find(_ns("value", ns)) or data_el.find("value")
        value = (val_el.text or "").strip() if val_el is not None else ""
        if name:
            result[name] = value
    return result


def _parse_placemark(placemark: ET.Element, ns: str) -> Optional[Dict[str, Any]]:
    """Convert one ``<Placemark>`` element to a device dict.

    Returns ``None`` when the placemark lacks valid coordinates.
    """
    # Coordinates: "lon,lat[,alt]"
    coords_text = _find_text(placemark, "Point", "coordinates", ns=ns)
    if not coords_text:
        return None
    parts = coords_text.split(",")
    try:
        lon = float(parts[0])
        lat = float(parts[1])
    except (IndexError, ValueError):
        return None

    ext = _parse_extended_data(placemark, ns)
    ip = ext.get("ip", "")
    port = ext.get("port", "")
    product = ext.get("product", "")
    org = ext.get("org", "")
    country_code = ext.get("country_code", "")
    vulns_raw = ext.get("vulns", "")

    # Derive a simple severity proxy from the vuln string length.
    vuln_count = 0
    if vulns_raw and vulns_raw.lower() not in ("none", ""):
        vuln_count = vulns_raw.count("CVE-")

    if vuln_count == 0:
        severity = "unknown"
    elif vuln_count <= 2:
        severity = "low"
    elif vuln_count <= 5:
        severity = "medium"
    elif vuln_count <= 10:
        severity = "high"
    else:
        severity = "critical"

    return {
        "ip": ip,
        "lat": lat,
        "lon": lon,
        "port": port,
        "product": product,
        "org": org,
        "country_code": country_code,
        "city": "",
        "type": product,
        "vulns": vulns_raw,
        "severity": severity,
        "nuclei_results": [],
        "data": "",
        "notes": "",
        # Source tag so the UI can show where the record came from.
        "_source": "kml",
    }


def load_kml(path: str) -> List[Dict[str, Any]]:
    """Parse a Kamerka KML export file and return a list of device dicts.

    Parameters
    ----------
    path : str
        Absolute path to the ``.kml`` file produced by
        ``kamerka.tasks.shodan_kml_export``.

    Returns
    -------
    list[dict]
        Device dicts compatible with ``GlobeWidget.load_devices()``.
        An empty list is returned when the file cannot be read or parsed.
    """
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError) as exc:
        import logging
        logging.getLogger(__name__).warning("kml_loader: could not parse %s — %s", path, exc)
        return []

    root = tree.getroot()

    # Detect namespace from root tag.
    ns = _KML_NS
    if root.tag.startswith("{"):
        ns = root.tag[1:root.tag.index("}")]
    else:
        ns = ""

    devices: List[Dict[str, Any]] = []
    for placemark in root.iter(_ns("Placemark", ns) if ns else "Placemark"):
        device = _parse_placemark(placemark, ns)
        if device is not None:
            devices.append(device)

    return devices
