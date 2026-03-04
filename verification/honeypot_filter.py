"""
honeypot_filter.py – High-entropy cluster detection and exclusion.

Honeypots and bulk hosting providers often expose hundreds of identical HTTP
banners from a single /24 subnet.  This module detects such clusters and flags
them so the 3-D rendering pipeline can exclude them.

Detection rule
--------------
A *honeypot cluster* is defined as:
    ≥ ``HONEYPOT_THRESHOLD`` devices in the **same /24 subnet** that share
    **exactly the same banner string**.

The default threshold is 500, matching the directive's example.

Usage
-----
    from verification.honeypot_filter import filter_honeypots

    clean_devices = filter_honeypots(all_devices)
    # Returns only devices that are not part of a suspected honeypot cluster.
"""

from __future__ import annotations

import ipaddress
import logging
from collections import defaultdict
from typing import Any, Dict, List, Sequence, Tuple

logger = logging.getLogger(__name__)

#: Minimum number of devices with an identical banner in one /24 to trigger
#: the honeypot flag.
HONEYPOT_THRESHOLD: int = 500


def _subnet24(ip: str) -> str:
    """Return the /24 network string for *ip* (e.g. ``'1.2.3.0/24'``).

    Returns an empty string for invalid or non-IPv4 addresses.
    """
    try:
        network = ipaddress.ip_network(
            "{}/24".format(ip), strict=False
        )
        return str(network)
    except ValueError:
        return ""


def detect_honeypot_clusters(
    devices: Sequence[Dict[str, Any]],
    threshold: int = HONEYPOT_THRESHOLD,
) -> List[Tuple[str, str]]:
    """Identify (subnet, banner) pairs that exceed the honeypot threshold.

    Parameters
    ----------
    devices : sequence of dict
        Device dicts.  Each must have ``ip`` (str) and ``data`` (str, the
        raw banner / ``Device.data`` field).
    threshold : int, optional
        Minimum identical-banner count per /24 to flag as a honeypot cluster
        (default ``HONEYPOT_THRESHOLD``).

    Returns
    -------
    list[tuple[str, str]]
        Each element is ``(subnet_cidr, banner_text)`` identifying a suspected
        honeypot cluster.

    Examples
    --------
    >>> flagged = detect_honeypot_clusters(devices, threshold=500)
    >>> print(flagged)
    [('1.2.3.0/24', 'HTTP/1.1 200 OK\\r\\nServer: Apache...')]
    """
    # Map (subnet, banner) → count
    counter: Dict[Tuple[str, str], int] = defaultdict(int)

    for device in devices:
        ip = str(device.get("ip", ""))
        banner = str(device.get("data", ""))
        subnet = _subnet24(ip)
        if subnet and banner:
            counter[(subnet, banner)] += 1

    flagged = [
        (subnet, banner)
        for (subnet, banner), count in counter.items()
        if count >= threshold
    ]

    if flagged:
        logger.info(
            "Honeypot filter: flagged %d cluster(s) with ≥%d identical banners",
            len(flagged),
            threshold,
        )

    return flagged


def is_honeypot_device(
    device: Dict[str, Any],
    flagged_clusters: List[Tuple[str, str]],
) -> bool:
    """Return ``True`` if *device* belongs to a flagged honeypot cluster.

    Parameters
    ----------
    device : dict
        Device record with ``ip`` and ``data`` keys.
    flagged_clusters : list[tuple[str, str]]
        Output of :func:`detect_honeypot_clusters`.

    Returns
    -------
    bool
    """
    if not flagged_clusters:
        return False
    ip = str(device.get("ip", ""))
    banner = str(device.get("data", ""))
    subnet = _subnet24(ip)
    return (subnet, banner) in flagged_clusters


def filter_honeypots(
    devices: Sequence[Dict[str, Any]],
    threshold: int = HONEYPOT_THRESHOLD,
) -> List[Dict[str, Any]]:
    """Remove honeypot devices from *devices* and return the clean list.

    Parameters
    ----------
    devices : sequence of dict
        Full device list.
    threshold : int, optional
        Identical-banner count per /24 that triggers removal (default 500).

    Returns
    -------
    list[dict]
        Devices that are *not* part of a suspected honeypot cluster.
    """
    flagged = detect_honeypot_clusters(devices, threshold=threshold)
    if not flagged:
        return list(devices)

    flagged_set = set(flagged)
    clean = [
        d for d in devices if not is_honeypot_device(d, list(flagged_set))
    ]
    removed = len(devices) - len(clean)
    logger.info(
        "Honeypot filter: removed %d device(s) from %d total",
        removed,
        len(devices),
    )
    return clean
