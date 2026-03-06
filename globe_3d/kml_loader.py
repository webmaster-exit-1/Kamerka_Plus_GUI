"""
globe_3d/kml_loader.py – Parse ``shodan convert`` KML exports into globe device dicts.

``shodan convert <file.json.gz> kml`` writes one ``<Placemark>`` per host:

* ``<name>``
      CDATA block containing ``<h1 ...>IP_ADDRESS</h1>``
* ``<description>``
      CDATA block with HTML.  Open ports appear as
      ``<span ...>PORT</span>`` elements inside a ``<ul>``.
* ``<Point><coordinates>``
      ``lon,lat`` (longitude first, then latitude).

There is **no** ``<ExtendedData>`` section in ``shodan convert`` output.

Usage
-----
    from globe_3d.kml_loader import load_kml

    devices = load_kml("/path/to/export.kml")
    globe_widget.load_devices(devices)
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# KML namespace written by the Shodan CLI converter.
_KML_NS = "http://www.opengis.net/kml/2.2"

# Matches a single port number inside a <span> element in the description HTML.
_PORT_RE = re.compile(r"<span[^>]*>\s*(\d+)\s*</span>")

# Matches any HTML tag (used to strip tags from the <name> CDATA).
_TAG_RE = re.compile(r"<[^>]+>")


def _ns(tag: str, ns: str = _KML_NS) -> str:
    return "{%s}%s" % (ns, tag) if ns else tag


def _find_text(element: ET.Element, *tags: str, ns: str = _KML_NS) -> Optional[str]:
    """Descend through *tags* and return the stripped text of the final element."""
    current = element
    for tag in tags:
        nxt = current.find(_ns(tag, ns))
        if nxt is None:
            nxt = current.find(tag)
        if nxt is None:
            return None
        current = nxt
    return (current.text or "").strip() or None


def _extract_ip_from_name(raw: str) -> str:
    """Strip HTML tags from the ``<name>`` CDATA and return the bare IP string.

    ``shodan convert`` wraps the IP in ``<h1 ...>IP</h1>``.  ElementTree
    returns the CDATA content as plain text so we just strip the tags.
    """
    return _TAG_RE.sub("", raw).strip()


def _extract_ports_from_description(raw: str) -> str:
    """Extract open port numbers from the ``<description>`` CDATA HTML.

    Returns a comma-separated string, e.g. ``"80,443,22"``, or ``""`` when
    no ports are found.
    """
    ports = _PORT_RE.findall(raw)
    return ",".join(ports)


def _parse_placemark(placemark: ET.Element, ns: str) -> Optional[Dict[str, Any]]:
    """Convert one ``<Placemark>`` element produced by ``shodan convert`` to a
    device dict.

    Returns ``None`` when the placemark lacks valid coordinates.
    """
    # --- coordinates (lon,lat order in Shodan KML) ---
    coords_text = _find_text(placemark, "Point", "coordinates", ns=ns)
    if not coords_text:
        return None
    parts = coords_text.split(",")
    try:
        lon = float(parts[0])
        lat = float(parts[1])
    except (IndexError, ValueError):
        return None

    # --- IP from <name> CDATA ---
    name_el = placemark.find(_ns("name", ns))
    if name_el is None:
        name_el = placemark.find("name")
    raw_name = (name_el.text or "") if name_el is not None else ""
    ip = _extract_ip_from_name(raw_name)

    # --- ports from <description> CDATA ---
    desc_el = placemark.find(_ns("description", ns))
    if desc_el is None:
        desc_el = placemark.find("description")
    raw_desc = (desc_el.text or "") if desc_el is not None else ""
    port = _extract_ports_from_description(raw_desc)

    return {
        "ip": ip,
        "lat": lat,
        "lon": lon,
        "port": port,
        "product": "",
        "org": "",
        "country_code": "",
        "city": "",
        "type": "",
        "vulns": "",
        "severity": "unknown",
        "nuclei_results": [],
        "data": raw_desc,
        "notes": "",
        "_source": "kml",
    }


def load_kml(path: str) -> List[Dict[str, Any]]:
    """Parse a ``shodan convert`` KML file and return a list of device dicts.

    Parameters
    ----------
    path : str
        Absolute path to the ``.kml`` file produced by
        ``shodan convert <export.json.gz> kml``.

    Returns
    -------
    list[dict]
        Device dicts compatible with ``GlobeWidget.load_devices()``.
        Returns an empty list when the file cannot be read or parsed.
    """
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError) as exc:
        logger.warning("kml_loader: could not parse %s — %s", path, exc)
        return []

    root = tree.getroot()

    # Detect namespace from the root tag.
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
