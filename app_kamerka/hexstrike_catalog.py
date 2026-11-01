"""Static catalog of HexStrike AI ``/api/tools/`` endpoints for the HexSploit console.

HexStrike does not expose a machine-readable listing endpoint, so this module
ships the known tool catalog (slug, category and primary input parameter) that
mirrors the ``@app.route("/api/tools/<slug>")`` handlers in ``hexstrike_server.py``.

The HexSploit tool picker uses this catalog to render a grouped, searchable list
and to send the *correct* primary parameter for each tool (``target``/``url``/
``domain`` auto-filled from the active target, ``manual`` tools expose a field),
which is what makes the dynamic pass-through in :mod:`app_kamerka.hexstrike_client`
succeed instead of blindly sending ``target`` to every endpoint.

``input`` values:
- ``target`` → auto-filled with the console target (host or IPv4).
- ``url``    → auto-filled with ``http://<target>`` (operator may edit).
- ``domain`` → auto-filled with the console target (hostname).
- ``manual`` → operator must supply a value (file path, module, interface, ...);
               these tools generally act on local artifacts, not a remote host.
"""

from __future__ import annotations

from typing import Any, Dict, List

TOOL_CATALOG = [
    {"slug": "amass", "group": "Network & Recon", "param": "domain", "input": "domain"},
    {"slug": "arp-scan", "group": "Network & Recon", "param": "target", "input": "target"},
    {"slug": "autorecon", "group": "Network & Recon", "param": "target", "input": "target"},
    {"slug": "dnsenum", "group": "Network & Recon", "param": "domain", "input": "domain"},
    {"slug": "enum4linux", "group": "Network & Recon", "param": "target", "input": "target"},
    {"slug": "enum4linux-ng", "group": "Network & Recon", "param": "target", "input": "target"},
    {"slug": "fierce", "group": "Network & Recon", "param": "domain", "input": "domain"},
    {"slug": "httpx", "group": "Network & Recon", "param": "target", "input": "target"},
    {"slug": "masscan", "group": "Network & Recon", "param": "target", "input": "target"},
    {"slug": "nbtscan", "group": "Network & Recon", "param": "target", "input": "target"},
    {"slug": "netexec", "group": "Network & Recon", "param": "target", "input": "target"},
    {"slug": "nmap", "group": "Network & Recon", "param": "target", "input": "target"},
    {"slug": "nmap-advanced", "group": "Network & Recon", "param": "target", "input": "target"},
    {"slug": "responder", "group": "Network & Recon", "param": "interface", "input": "manual"},
    {"slug": "rpcclient", "group": "Network & Recon", "param": "target", "input": "target"},
    {"slug": "rustscan", "group": "Network & Recon", "param": "target", "input": "target"},
    {"slug": "smbmap", "group": "Network & Recon", "param": "target", "input": "target"},
    {"slug": "subfinder", "group": "Network & Recon", "param": "domain", "input": "domain"},
    {"slug": "wafw00f", "group": "Network & Recon", "param": "target", "input": "target"},
    {"slug": "anew", "group": "Web Application", "param": "input_data", "input": "manual"},
    {"slug": "api_fuzzer", "group": "Web Application", "param": "base_url", "input": "url"},
    {"slug": "api_schema_analyzer", "group": "Web Application", "param": "schema_url", "input": "url"},
    {"slug": "arjun", "group": "Web Application", "param": "url", "input": "url"},
    {"slug": "browser-agent", "group": "Web Application", "param": "url", "input": "url"},
    {"slug": "burpsuite-alternative", "group": "Web Application", "param": "target", "input": "target"},
    {"slug": "dalfox", "group": "Web Application", "param": "url", "input": "url"},
    {"slug": "dirb", "group": "Web Application", "param": "url", "input": "url"},
    {"slug": "dirsearch", "group": "Web Application", "param": "url", "input": "url"},
    {"slug": "dotdotpwn", "group": "Web Application", "param": "target", "input": "target"},
    {"slug": "feroxbuster", "group": "Web Application", "param": "url", "input": "url"},
    {"slug": "ffuf", "group": "Web Application", "param": "url", "input": "url"},
    {"slug": "gau", "group": "Web Application", "param": "domain", "input": "domain"},
    {"slug": "gobuster", "group": "Web Application", "param": "url", "input": "url"},
    {"slug": "graphql_scanner", "group": "Web Application", "param": "endpoint", "input": "url"},
    {"slug": "hakrawler", "group": "Web Application", "param": "url", "input": "url"},
    {"slug": "http-framework", "group": "Web Application", "param": "url", "input": "url"},
    {"slug": "jaeles", "group": "Web Application", "param": "url", "input": "url"},
    {"slug": "jwt_analyzer", "group": "Web Application", "param": "jwt_token", "input": "manual"},
    {"slug": "katana", "group": "Web Application", "param": "url", "input": "url"},
    {"slug": "nikto", "group": "Web Application", "param": "target", "input": "target"},
    {"slug": "nuclei", "group": "Web Application", "param": "target", "input": "target"},
    {"slug": "paramspider", "group": "Web Application", "param": "domain", "input": "domain"},
    {"slug": "qsreplace", "group": "Web Application", "param": "urls", "input": "manual"},
    {"slug": "sqlmap", "group": "Web Application", "param": "url", "input": "url"},
    {"slug": "uro", "group": "Web Application", "param": "urls", "input": "manual"},
    {"slug": "waybackurls", "group": "Web Application", "param": "domain", "input": "domain"},
    {"slug": "wfuzz", "group": "Web Application", "param": "url", "input": "url"},
    {"slug": "wpscan", "group": "Web Application", "param": "url", "input": "url"},
    {"slug": "x8", "group": "Web Application", "param": "url", "input": "url"},
    {"slug": "xsser", "group": "Web Application", "param": "url", "input": "url"},
    {"slug": "zap", "group": "Web Application", "param": "target", "input": "target"},
    {"slug": "hashcat", "group": "Passwords & Auth", "param": "hash_file", "input": "manual"},
    {"slug": "hashpump", "group": "Passwords & Auth", "param": "signature", "input": "manual"},
    {"slug": "hydra", "group": "Passwords & Auth", "param": "target", "input": "target"},
    {"slug": "john", "group": "Passwords & Auth", "param": "hash_file", "input": "manual"},
    {"slug": "angr", "group": "Binary / RE / Pwn", "param": "binary", "input": "manual"},
    {"slug": "checksec", "group": "Binary / RE / Pwn", "param": "binary", "input": "manual"},
    {"slug": "gdb", "group": "Binary / RE / Pwn", "param": "binary", "input": "manual"},
    {"slug": "gdb-peda", "group": "Binary / RE / Pwn", "param": "binary", "input": "manual"},
    {"slug": "ghidra", "group": "Binary / RE / Pwn", "param": "binary", "input": "manual"},
    {"slug": "libc-database", "group": "Binary / RE / Pwn", "param": "action", "input": "manual"},
    {"slug": "metasploit", "group": "Binary / RE / Pwn", "param": "module", "input": "manual"},
    {"slug": "msfvenom", "group": "Binary / RE / Pwn", "param": "payload", "input": "manual"},
    {"slug": "objdump", "group": "Binary / RE / Pwn", "param": "binary", "input": "manual"},
    {"slug": "one-gadget", "group": "Binary / RE / Pwn", "param": "libc_path", "input": "manual"},
    {"slug": "pwninit", "group": "Binary / RE / Pwn", "param": "binary", "input": "manual"},
    {"slug": "pwntools", "group": "Binary / RE / Pwn", "param": "script_content", "input": "manual"},
    {"slug": "radare2", "group": "Binary / RE / Pwn", "param": "binary", "input": "manual"},
    {"slug": "ropgadget", "group": "Binary / RE / Pwn", "param": "binary", "input": "manual"},
    {"slug": "ropper", "group": "Binary / RE / Pwn", "param": "binary", "input": "manual"},
    {"slug": "strings", "group": "Binary / RE / Pwn", "param": "file_path", "input": "manual"},
    {"slug": "xxd", "group": "Binary / RE / Pwn", "param": "file_path", "input": "manual"},
    {"slug": "binwalk", "group": "Forensics & Stego", "param": "file_path", "input": "manual"},
    {"slug": "exiftool", "group": "Forensics & Stego", "param": "file_path", "input": "manual"},
    {"slug": "foremost", "group": "Forensics & Stego", "param": "input_file", "input": "manual"},
    {"slug": "steghide", "group": "Forensics & Stego", "param": "action", "input": "manual"},
    {"slug": "volatility", "group": "Forensics & Stego", "param": "memory_file", "input": "manual"},
    {"slug": "volatility3", "group": "Forensics & Stego", "param": "memory_file", "input": "manual"},
    {"slug": "checkov", "group": "Cloud & Container", "param": "directory", "input": "manual"},
    {"slug": "clair", "group": "Cloud & Container", "param": "image", "input": "manual"},
    {"slug": "cloudmapper", "group": "Cloud & Container", "param": "action", "input": "manual"},
    {"slug": "docker-bench-security", "group": "Cloud & Container", "param": "checks", "input": "manual"},
    {"slug": "falco", "group": "Cloud & Container", "param": "config_file", "input": "manual"},
    {"slug": "kube-bench", "group": "Cloud & Container", "param": "targets", "input": "manual"},
    {"slug": "kube-hunter", "group": "Cloud & Container", "param": "target", "input": "target"},
    {"slug": "pacu", "group": "Cloud & Container", "param": "session_name", "input": "manual"},
    {"slug": "prowler", "group": "Cloud & Container", "param": "provider", "input": "manual"},
    {"slug": "scout-suite", "group": "Cloud & Container", "param": "provider", "input": "manual"},
    {"slug": "terrascan", "group": "Cloud & Container", "param": "scan_type", "input": "manual"},
    {"slug": "trivy", "group": "Cloud & Container", "param": "image", "input": "manual"},
]

# Preserve declaration order of groups for stable UI rendering.
GROUP_ORDER = [
    "Network & Recon",
    "Web Application",
    "Passwords & Auth",
    "Binary / RE / Pwn",
    "Forensics & Stego",
    "Cloud & Container",
]


def _label(slug: str) -> str:
    return slug.replace("-", " ").replace("_", " ")


def catalog_by_group() -> List[Dict[str, Any]]:
    """Return the catalog grouped for the picker UI, preserving GROUP_ORDER."""
    buckets: Dict[str, List[Dict[str, Any]]] = {g: [] for g in GROUP_ORDER}
    for tool in TOOL_CATALOG:
        entry = dict(tool)
        entry["label"] = _label(tool["slug"])
        buckets.setdefault(tool["group"], []).append(entry)
    groups = []
    for name in GROUP_ORDER:
        tools = buckets.get(name) or []
        if tools:
            groups.append({"group": name, "tools": tools})
    # Any groups not in GROUP_ORDER (defensive) appended last.
    for name, tools in buckets.items():
        if name not in GROUP_ORDER and tools:
            groups.append({"group": name, "tools": tools})
    return groups
