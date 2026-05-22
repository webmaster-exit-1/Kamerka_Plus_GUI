"""
Tool Plugin Registry
====================
Central registry that describes every tool Kamerka can run against a device.

Adding a new tool
-----------------
1. Define a ToolPlugin instance below.
2. Call ``register(plugin)`` at module level.
3. The tool will automatically appear in:
   - The bulk-run UI (if bulk_supported=True).
   - The /api/tools/ discovery endpoint.
   - The /healthz/setup/ status page (binary + secret checks).

Enabling / disabling a tool globally
--------------------------------------
Set the environment variable ``KAMERKA_TOOL_<NAME>_ENABLED=false`` to
disable a tool for all users without code changes.  The tool remains in the
registry but ``plugin.enabled`` returns False and the dispatcher will refuse
to enqueue it.

Call modes
----------
Each plugin declares how its Celery task accepts the device identifier:

- ``"args"``          → task.delay(device_id)
- ``"kwargs_id"``     → task.delay(id=device_id)
- ``"kwargs_device_id"`` → task.delay(device_id=device_id)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ToolPlugin:
    """Describes one runnable tool in the Kamerka plugin system."""

    # Registry key — must match the corresponding TaskRun.TOOL_* constant.
    name: str

    # Human-readable name shown in UI dropdowns and the system-status page.
    label: str

    # One-line description shown in tool panels and developer docs.
    description: str

    # Dotted Celery task name, e.g. "kamerka.tasks.capture_screenshot".
    celery_task_name: str

    # How the task expects the device primary-key argument.
    # One of: "args" | "kwargs_id" | "kwargs_device_id"
    call_mode: str

    # External binaries that must be on PATH for this tool to work.
    required_binaries: list = field(default_factory=list)

    # Environment variable names whose values must be non-empty.
    required_secrets: list = field(default_factory=list)

    # Whether the tool should appear in the bulk-run UI.
    bulk_supported: bool = True

    # Whether the tool is enabled when no override env-var is set.
    enabled_by_default: bool = True

    # ------------------------------------------------------------------ #
    @property
    def enabled(self) -> bool:
        """Return False when the tool is disabled via environment variable."""
        env_key = "KAMERKA_TOOL_{}_ENABLED".format(self.name.upper())
        val = os.environ.get(env_key, "").strip().lower()
        if val in ("false", "0", "no", "off"):
            return False
        return self.enabled_by_default

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dict for the discovery API."""
        return {
            "name": self.name,
            "label": self.label,
            "description": self.description,
            "required_binaries": list(self.required_binaries),
            "required_secrets": list(self.required_secrets),
            "bulk_supported": self.bulk_supported,
            "enabled": self.enabled,
        }


# ---------------------------------------------------------------------------
# Internal registry storage
# ---------------------------------------------------------------------------
_REGISTRY: dict[str, ToolPlugin] = {}


def register(plugin: ToolPlugin) -> ToolPlugin:
    """Add *plugin* to the global registry and return it."""
    if plugin.name in _REGISTRY:
        raise ValueError("Tool {!r} is already registered".format(plugin.name))
    _REGISTRY[plugin.name] = plugin
    return plugin


def get_tool(name: str) -> Optional[ToolPlugin]:
    """Return the ToolPlugin for *name*, or None if not found."""
    return _REGISTRY.get(name)


def all_tools() -> list[ToolPlugin]:
    """Return all registered tools in insertion order."""
    return list(_REGISTRY.values())


def enabled_tools() -> list[ToolPlugin]:
    """Return only enabled tools."""
    return [p for p in _REGISTRY.values() if p.enabled]


def bulk_tools() -> list[ToolPlugin]:
    """Return tools that are enabled and support bulk execution."""
    return [p for p in _REGISTRY.values() if p.enabled and p.bulk_supported]


# ---------------------------------------------------------------------------
# Tool registrations
# ---------------------------------------------------------------------------

register(ToolPlugin(
    name="screenshot",
    label="Screenshot",
    description="Capture a screenshot of the device web interface via headless Chrome.",
    celery_task_name="kamerka.tasks.capture_screenshot",
    call_mode="args",
    required_binaries=["chromium"],  # chromedriver also needed; google-chrome is an alternative name
    bulk_supported=True,
))

register(ToolPlugin(
    name="nuclei",
    label="Nuclei",
    description="Run Nuclei vulnerability templates against the device open ports.",
    celery_task_name="kamerka.tasks.nuclei_scan",
    call_mode="kwargs_id",
    required_binaries=["nuclei"],
    bulk_supported=True,
))

register(ToolPlugin(
    name="nmap",
    label="Nmap",
    description="Run an Nmap scan with optional NSE script against the device.",
    celery_task_name="kamerka.tasks.nmap_device_scan",
    call_mode="args",
    required_binaries=["nmap"],
    bulk_supported=True,
))

register(ToolPlugin(
    name="wappalyzer",
    label="Wappalyzer",
    description="Identify web technologies running on the device HTTP ports.",
    celery_task_name="kamerka.tasks.wappalyzer_scan",
    call_mode="kwargs_id",
    required_binaries=["wappalyzer"],
    bulk_supported=False,
))

register(ToolPlugin(
    name="exploitdb",
    label="ExploitDB",
    description="Search ExploitDB for public exploits matching the device CVEs.",
    celery_task_name="kamerka.tasks.exploitdb_search",
    call_mode="args",
    required_binaries=["searchsploit"],
    bulk_supported=False,
))

register(ToolPlugin(
    name="whois",
    label="WHOIS",
    description="Perform a WHOIS / RDAP lookup for the device IP.",
    celery_task_name="kamerka.tasks.whoisxml",
    call_mode="kwargs_id",
    required_binaries=[],
    bulk_supported=False,
))

register(ToolPlugin(
    name="gfw",
    label="GFW Check",
    description="Check if the device is blocked by the Great Firewall via OONI.",
    celery_task_name="kamerka.tasks.gfw_check",
    call_mode="kwargs_device_id",
    required_binaries=[],
    required_secrets=[],
    bulk_supported=False,
))

register(ToolPlugin(
    name="honeypot",
    label="Honeypot Analysis",
    description="Analyse banner density, signatures and Shodan Honeyscore to detect honeypots.",
    celery_task_name="kamerka.tasks.honeypot_check",
    call_mode="kwargs_device_id",
    required_binaries=[],
    required_secrets=[],
    bulk_supported=False,
))

register(ToolPlugin(
    name="sbom",
    label="SBOM Lookup",
    description="Identify known firmware/software components for the device.",
    celery_task_name="kamerka.tasks.sbom_lookup",
    call_mode="kwargs_device_id",
    required_binaries=[],
    required_secrets=[],
    bulk_supported=False,
))

register(ToolPlugin(
    name="port_scan",
    label="Port Scan",
    description="Discover open ports on the device using Naabu.",
    celery_task_name="kamerka.tasks.port_scan_task",
    call_mode="args",
    required_binaries=["naabu"],
    bulk_supported=True,
))

register(ToolPlugin(
    name="nvd",
    label="NVD Lookup",
    description="Enrich device CVEs with EPSS, KEV and NVD advisory details.",
    celery_task_name="kamerka.tasks.nvd_lookup",
    call_mode="kwargs_device_id",
    required_binaries=[],
    required_secrets=[],
    bulk_supported=False,
))

register(ToolPlugin(
    name="nrich",
    label="nrich / InternetDB",
    description="Fast CVE enrichment using the free Shodan InternetDB endpoint.",
    celery_task_name="kamerka.tasks.nrich_lookup",
    call_mode="kwargs_device_id",
    required_binaries=[],
    bulk_supported=False,
))

register(ToolPlugin(
    name="cvedb",
    label="CVEDB Enrich",
    description="Enrich device vulnerabilities via the Shodan CVEDB API.",
    celery_task_name="kamerka.tasks.cvedb_enrich",
    call_mode="kwargs_device_id",
    required_binaries=[],
    required_secrets=["SHODAN_API_KEY"],
    bulk_supported=False,
))

register(ToolPlugin(
    name="intel",
    label="Shodan Intel",
    description="Combined nrich + CVEDB Shodan intelligence scan.",
    celery_task_name="kamerka.tasks.shodan_intel_scan",
    call_mode="kwargs_device_id",
    required_binaries=[],
    required_secrets=["SHODAN_API_KEY"],
    bulk_supported=False,
))

register(ToolPlugin(
    name="deep_scan",
    label="Deep Protocol Scan",
    description="Run ICS/IoT deep-protocol fingerprinting (Modbus, S7, DNP3, …).",
    celery_task_name="kamerka.tasks.deep_protocol_scan",
    call_mode="kwargs_device_id",
    required_binaries=["nmap"],
    bulk_supported=False,
))

register(ToolPlugin(
    name="rtsp",
    label="RTSP Scan",
    description="Enumerate RTSP camera streams on the device.",
    celery_task_name="kamerka.tasks.nmap_rtsp_scan",
    call_mode="kwargs_id",
    required_binaries=["nmap"],
    bulk_supported=False,
))
