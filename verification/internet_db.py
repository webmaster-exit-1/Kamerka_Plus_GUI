"""
internet_db.py – Free InternetDB look-up for basic IP intelligence.

InternetDB (https://internetdb.shodan.io) provides open port, tag, CPE and
vulnerability data for any IP address at no cost and without authentication.
It is used as the *first* tier of the verification pipeline before any Shodan
API credits are spent.

API endpoint
------------
    GET https://internetdb.shodan.io/{ip}

    Success response (200) example::

        {
            "ip": "1.2.3.4",
            "ports": [80, 443, 8080],
            "tags": ["honeypot"],
            "cpes": ["cpe:/a:nginx:nginx"],
            "vulns": ["CVE-2021-44228"],
            "hostnames": ["example.com"]
        }

    Returns 404 for IPs with no data.

Usage
-----
    from verification.internet_db import check_internetdb

    result = check_internetdb("1.2.3.4")
    if result and result.get("ports"):
        print("Open ports:", result["ports"])
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)

#: Base URL for the free InternetDB service.
INTERNETDB_BASE_URL = "https://internetdb.shodan.io"

#: Default connect + read timeout in seconds.
DEFAULT_TIMEOUT: int = 10


def _validate_ip(ip: str) -> bool:
    """Return ``True`` if *ip* is a valid public unicast IPv4 or IPv6 address."""
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_multicast)
    except ValueError:
        return False


def check_internetdb(
    ip: str,
    timeout: int = DEFAULT_TIMEOUT,
    session: Optional[requests.Session] = None,
) -> Optional[Dict[str, Any]]:
    """Query InternetDB for basic port and vulnerability data on *ip*.

    Parameters
    ----------
    ip : str
        Target IPv4 or IPv6 address.  Private/loopback/multicast addresses are
        rejected immediately and ``None`` is returned.
    timeout : int, optional
        Request timeout in seconds (default ``DEFAULT_TIMEOUT``).
    session : requests.Session, optional
        Pre-configured session for connection reuse / testing.

    Returns
    -------
    dict or None
        Parsed JSON response, or ``None`` if the IP is private, not found
        (HTTP 404), or the request failed.

    Examples
    --------
    >>> result = check_internetdb("8.8.8.8")
    >>> result["ports"]
    [53]
    """
    if not _validate_ip(ip):
        logger.debug("Skipping private/invalid IP: %s", ip)
        return None

    url = "{}/{}".format(INTERNETDB_BASE_URL, ip)
    requester = session or requests

    try:
        response = requester.get(url, timeout=timeout)
        if response.status_code == 404:
            logger.debug("InternetDB: no data for %s", ip)
            return None
        response.raise_for_status()
        return response.json()
    except requests.exceptions.Timeout:
        logger.warning("InternetDB request timed out for %s", ip)
        return None
    except requests.exceptions.RequestException as exc:
        logger.warning("InternetDB request failed for %s: %s", ip, exc)
        return None


def is_alive_internetdb(ip: str, **kwargs: Any) -> bool:
    """Return ``True`` if InternetDB reports at least one open port for *ip*.

    This is a convenience wrapper used by the tiered verification pipeline
    to perform a fast, free liveness check before invoking Naabu.

    Parameters
    ----------
    ip : str
        Target IP address.
    **kwargs
        Forwarded to :func:`check_internetdb`.

    Returns
    -------
    bool
        ``True`` if any open ports are reported; ``False`` otherwise.
    """
    result = check_internetdb(ip, **kwargs)
    if not result:
        return False
    return bool(result.get("ports"))
