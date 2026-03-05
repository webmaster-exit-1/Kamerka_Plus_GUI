"""
naabu_scanner.py – Thin wrapper around the FOSS Naabu port-scanner.

Naabu (https://github.com/projectdiscovery/naabu) is a free, open-source port
scanner written in Go.  It is used as the *second* tier in the verification
pipeline to confirm that a target is *currently alive and reachable* before
spending Shodan API credits and rendering 3-D spikes.

The wrapper calls Naabu via ``subprocess.run`` (no ``shell=True``) and parses
its line-delimited JSON output.

Binary path configuration
--------------------------
The Naabu binary path is resolved at call-time in the following priority order:

1. **Django settings** (``settings.NAABU_BIN``) – set automatically from
   ``kamerka/tool_settings.py`` when running inside the Django / Celery stack.
2. **kamerka/tool_settings.py** – the authoritative config file; edit
   ``NAABU_BIN`` there, or set the ``KAMERKA_NAABU_BIN`` environment variable.
3. **Hardcoded fallback** – ``"naabu"`` (resolved via ``$PATH``), used only
   when this module is imported outside any Django context.

Prerequisites
-------------
    naabu must be installed and available on ``$PATH`` (or configured above):
        go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

Usage
-----
    from verification.naabu_scanner import run_naabu, is_alive_naabu

    # Confirm host is reachable (fast top-ports scan)
    if is_alive_naabu("1.2.3.4"):
        print("Target is alive")

    # Full scan result
    results = run_naabu("1.2.3.4", ports="80,443,8080")
    for entry in results:
        print(entry["ip"], entry["port"])
"""

from __future__ import annotations

import json
import logging
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Runtime path resolution
# ---------------------------------------------------------------------------

def _get_naabu_bin() -> str:
    """Return the configured Naabu binary path.

    Resolution order:
    1. ``django.conf.settings.NAABU_BIN`` (set from ``kamerka/tool_settings.py``)
    2. ``kamerka.tool_settings.NAABU_BIN`` (direct import, non-Django context)
    3. ``"naabu"`` hard-coded fallback (system ``$PATH`` lookup)
    """
    try:
        from django.conf import settings
        return getattr(settings, "NAABU_BIN", "naabu")
    except Exception:
        pass
    try:
        from kamerka.tool_settings import NAABU_BIN
        return NAABU_BIN
    except Exception:
        return "naabu"


def _get_default_ports() -> str:
    """Return the configured default port spec for Naabu scans."""
    try:
        from django.conf import settings
        return getattr(settings, "NAABU_DEFAULT_PORTS", "top-100")
    except Exception:
        pass
    try:
        from kamerka.tool_settings import NAABU_DEFAULT_PORTS
        return NAABU_DEFAULT_PORTS
    except Exception:
        return "top-100"


def _get_default_timeout() -> int:
    """Return the configured Naabu scan timeout in seconds."""
    try:
        from django.conf import settings
        return int(getattr(settings, "NAABU_DEFAULT_TIMEOUT", 60))
    except Exception:
        pass
    try:
        from kamerka.tool_settings import NAABU_DEFAULT_TIMEOUT
        return NAABU_DEFAULT_TIMEOUT
    except Exception:
        return 60


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_naabu(
    ip: str,
    ports: Optional[str] = None,
    timeout: Optional[int] = None,
    extra_args: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Run Naabu against *ip* and return parsed scan results.

    The Naabu binary used is read from ``settings.NAABU_BIN`` (configured in
    ``kamerka/tool_settings.py``).  It defaults to ``"naabu"`` so the system
    ``$PATH`` is used, but can be overridden with the ``KAMERKA_NAABU_BIN``
    environment variable or by editing ``kamerka/tool_settings.py`` directly.

    Parameters
    ----------
    ip : str
        Target IPv4 or IPv6 address (validated by Naabu itself).
    ports : str, optional
        Port specification accepted by Naabu: a comma-separated list
        (``"80,443"``), a range (``"1-1024"``), or a preset
        (``"top-100"``).  Defaults to ``settings.NAABU_DEFAULT_PORTS``.
    timeout : int, optional
        Maximum seconds to wait for Naabu to finish.  Defaults to
        ``settings.NAABU_DEFAULT_TIMEOUT``.
    extra_args : list of str, optional
        Additional CLI flags forwarded to Naabu verbatim.

    Returns
    -------
    list[dict]
        Each element has at least:
        ``ip`` : str    Target IP.
        ``port`` : int  Open port number.

        Returns ``[]`` when Naabu is not installed, the host is unreachable,
        or an error occurs.

    Raises
    ------
    None – all exceptions are caught and logged.
    """
    naabu_bin = _get_naabu_bin()
    effective_ports = ports if ports is not None else _get_default_ports()
    effective_timeout = timeout if timeout is not None else _get_default_timeout()

    cmd = [
        naabu_bin,
        "-host", ip,
        "-p", effective_ports,
        "-json",
        "-silent",
    ]
    if extra_args:
        cmd.extend(extra_args)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=effective_timeout,
        )
    except FileNotFoundError:
        logger.error(
            "Naabu binary '%s' not found. "
            "Install: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest  "
            "or set KAMERKA_NAABU_BIN to the correct path.",
            naabu_bin,
        )
        return []
    except subprocess.TimeoutExpired:
        logger.warning("Naabu scan timed out for %s", ip)
        return []
    except OSError as exc:
        logger.error("Naabu execution failed for %s: %s", ip, exc)
        return []

    return _parse_naabu_output(result.stdout)


def _parse_naabu_output(stdout: str) -> List[Dict[str, Any]]:
    """Parse Naabu's line-delimited JSON output into a list of dicts."""
    entries: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            # Naabu JSON: {"ip": "...", "port": N, ...}
            entries.append(
                {
                    "ip": str(data.get("ip", "")),
                    "port": int(data.get("port", 0)),
                    "raw": data,
                }
            )
        except (json.JSONDecodeError, ValueError, KeyError):
            # Fall back to "ip:port" plain-text format
            if ":" in line:
                parts = line.rsplit(":", 1)
                try:
                    entries.append({"ip": parts[0], "port": int(parts[1]), "raw": {}})
                except (ValueError, IndexError):
                    logger.debug("Skipping unparseable Naabu line: %s", line)
    return entries


def is_alive_naabu(
    ip: str,
    ports: Optional[str] = None,
    timeout: Optional[int] = None,
) -> bool:
    """Return ``True`` if Naabu finds at least one open port on *ip*.

    Parameters
    ----------
    ip : str
        Target IP address.
    ports : str, optional
        Port specification.  Defaults to ``settings.NAABU_DEFAULT_PORTS``.
    timeout : int, optional
        Scan timeout in seconds.  Defaults to ``settings.NAABU_DEFAULT_TIMEOUT``.

    Returns
    -------
    bool
        ``True`` when at least one open port is reported; ``False`` otherwise.
    """
    return bool(run_naabu(ip, ports=ports, timeout=timeout))
