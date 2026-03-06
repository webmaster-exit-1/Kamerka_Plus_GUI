"""
globe_3d/kml_loader.py – Parse KML exports into globe device dicts.

Two KML schemas are supported transparently:

**App export** (``kamerka.tasks.shodan_kml_export`` → ``/export/kml/<id>``):

* ``<name>`` contains ``"<product> - <ip>"``
* ``<description>`` is a plain-text summary
* ``<ExtendedData>`` contains ``<Data name="ip">``, ``<Data name="port">``,
  ``<Data name="product">``, ``<Data name="org">``,
  ``<Data name="country_code">``, ``<Data name="vulns">``
* ``<Point><coordinates>`` is ``lon,lat``

**Shodan-CLI** (``shodan convert <file.json.gz> kml``):

* ``<name>`` CDATA block containing ``<h1 ...>IP_ADDRESS</h1>``
* ``<description>`` CDATA with HTML; open ports appear as
  ``<span ...>PORT</span>`` elements inside a ``<ul>``
* No ``<ExtendedData>`` section
* ``<Point><coordinates>`` is ``lon,lat``

The schema is detected automatically by the presence of ``<ExtendedData>``.

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

# KML namespace written by both the app exporter and the Shodan CLI converter.
_KML_NS = "http://www.opengis.net/kml/2.2"

# Matches a single port number inside a <span> element in the description HTML.
_PORT_RE = re.compile(r"<span[^>]*>\s*(\d+)\s*</span>")

# Matches any HTML tag (used to strip tags from the <name> CDATA).
_TAG_RE = re.compile(r"<[^>]+>")

# Matches CVE identifiers in a vulns string (handles Python list literal format
# such as "['CVE-2021-1234', 'CVE-2022-5678']" or plain CSV "CVE-2021-1234,...").
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _severity_from_vulns_str(vulns: str) -> str:
    """Derive a severity label from the ``vulns`` ExtendedData field.

    The app's KML export stores ``Device.vulns`` verbatim, which may be:
    * an empty string / ``""``
    * a Python list literal like ``"['CVE-2021-1234', 'CVE-2021-5678']"``
    * a plain comma-separated list of CVE IDs

    Returns ``"unknown"`` / ``"low"`` / ``"medium"`` / ``"high"`` / ``"critical"``.
    """
    if not vulns or vulns.strip() in ("", "None", "[]"):
        return "unknown"
    count = len(_CVE_RE.findall(vulns))
    if count == 0:
        return "unknown"
    if count <= 2:
        return "low"
    if count <= 5:
        return "medium"
    if count <= 10:
        return "high"
    return "critical"


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
    """Convert one ``<Placemark>`` to a device dict.

    Supports two KML schemas detected automatically:

    **App export** (``shodan_kml_export``):
      * ``<ExtendedData>`` contains ``<Data name="ip">``, ``port``,
        ``product``, ``org``, ``country_code``, ``vulns``
      * ``<Point><coordinates>`` is ``lon,lat``

    **Shodan-CLI** (``shodan convert kml``):
      * ``<name>`` CDATA contains ``<h1 ...>IP_ADDRESS</h1>``
      * ``<description>`` CDATA contains ``<span>PORT</span>`` elements
      * No ``<ExtendedData>``
      * ``<Point><coordinates>`` is ``lon,lat``

    Returns ``None`` when the placemark lacks valid coordinates.
    """
    # --- coordinates (lon,lat order in both formats) ---
    coords_text = _find_text(placemark, "Point", "coordinates", ns=ns)
    if not coords_text:
        return None
    parts = coords_text.split(",")
    try:
        lon = float(parts[0])
        lat = float(parts[1])
    except (IndexError, ValueError):
        return None

    # --- detect schema by presence of <ExtendedData> ---
    ext_data = placemark.find(_ns("ExtendedData", ns))
    if ext_data is None:
        ext_data = placemark.find("ExtendedData")

    if ext_data is not None:
        # ── App export format ────────────────────────────────────────────────
        # Collect all <Data name="..."><value>...</value></Data> entries.
        fields: Dict[str, str] = {}
        for data_el in ext_data.iter():
            name_attr = data_el.get("name")
            if name_attr:
                val_el = data_el.find(_ns("value", ns))
                if val_el is None:
                    val_el = data_el.find("value")
                fields[name_attr] = (
                    (val_el.text or "").strip() if val_el is not None else ""
                )

        ip = fields.get("ip", "")
        port = fields.get("port", "")
        product = fields.get("product", "")
        org = fields.get("org", "")
        country_code = fields.get("country_code", "")
        vulns_str = fields.get("vulns", "")
        severity = _severity_from_vulns_str(vulns_str)

        desc_el = placemark.find(_ns("description", ns))
        if desc_el is None:
            desc_el = placemark.find("description")
        raw_desc = (desc_el.text or "") if desc_el is not None else ""

        return {
            "ip": ip,
            "lat": lat,
            "lon": lon,
            "port": port,
            "product": product,
            "org": org,
            "country_code": country_code,
            "city": "",
            "type": "",
            "vulns": vulns_str,
            "severity": severity,
            "nuclei_results": [],
            "data": raw_desc,
            "notes": "",
            "_source": "kml",
        }

    # ── Shodan-CLI format ────────────────────────────────────────────────────
    # IP in <name> CDATA (possibly wrapped in <h1 ...>), ports in <description>.
    name_el = placemark.find(_ns("name", ns))
    if name_el is None:
        name_el = placemark.find("name")
    raw_name = (name_el.text or "") if name_el is not None else ""
    ip = _extract_ip_from_name(raw_name)

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
    """Parse a KML file and return a list of device dicts.

    Supports both the app's own KML export (``/export/kml/<id>``) and
    Shodan-CLI ``shodan convert kml`` output.

    Parameters
    ----------
    path : str
        Absolute path to the ``.kml`` file.

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
