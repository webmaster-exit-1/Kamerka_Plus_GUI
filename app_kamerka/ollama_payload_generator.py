"""AI-driven payload generation using Ollama for smart tool selection and parameter crafting."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

import requests
from django.conf import settings

from app_kamerka.hexstrike_client import HexStrikeClient
from app_kamerka.models import Device, VulnIntelligence


def ollama_url() -> str:
    """Get Ollama server URL from settings."""
    return (getattr(settings, "HEXSPLOIT_OLLAMA_SERVER_URL", "") or "http://127.0.0.1:11434").rstrip("/")


def ollama_model() -> str:
    """Get Ollama model name from settings."""
    return getattr(settings, "HEXSPLOIT_OLLAMA_MODEL", "deephat")


def query_ollama(prompt: str, timeout: int = 30) -> Optional[str]:
    """Query Ollama for AI recommendations."""
    try:
        resp = requests.post(
            f"{ollama_url()}/api/generate",
            json={"model": ollama_model(), "prompt": prompt, "stream": False},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("response", "").strip()
    except Exception as e:
        return None


def build_target_profile(target: str, device: Optional[Device] = None) -> Dict[str, Any]:
    """Build a profile of the target from device metadata and CVEs."""
    profile = {"target": target, "device_type": "unknown", "open_ports": [], "services": [], "cves": [], "risk_level": "unknown"}

    if device:
        profile["device_type"] = device.type or "unknown"
        profile["device_product"] = device.product or ""
        profile["port"] = device.port or ""
        profile["isp"] = device.isp or ""
        profile["cpe"] = device.cpe or ""

        # Collect CVEs
        if device.vulns:
            try:
                import ast

                cves = ast.literal_eval(device.vulns)
                if isinstance(cves, list):
                    profile["cves"].extend(cves[:10])  # Top 10
            except Exception:
                pass

        # Get VulnIntelligence for more CVEs and CVSS scores
        for vuln in VulnIntelligence.objects.filter(device=device).order_by("-cvss_score")[:5]:
            if vuln.cve_id and vuln.cve_id not in profile["cves"]:
                profile["cves"].append(vuln.cve_id)

        # Risk level from CVEs
        max_cvss = (
            VulnIntelligence.objects.filter(device=device)
            .order_by("-cvss_score")
            .values_list("cvss_score", flat=True)
            .first()
            or 0
        )
        if max_cvss >= 9:
            profile["risk_level"] = "critical"
        elif max_cvss >= 7:
            profile["risk_level"] = "high"
        elif max_cvss >= 4:
            profile["risk_level"] = "medium"
        else:
            profile["risk_level"] = "low"

    return profile


def craft_tool_recommendation_prompt(target_profile: Dict[str, Any]) -> str:
    """Create a prompt for Ollama to recommend tools and parameters."""
    cves_text = ", ".join(target_profile.get("cves", [])[:5]) or "none found"
    device_type = target_profile.get("device_type", "unknown")
    risk_level = target_profile.get("risk_level", "unknown")

    prompt = f"""You are a security expert recommending attack chain tools from HexStrike.

Target Profile:
- IP/Hostname: {target_profile.get('target')}
- Type: {device_type}
- Product: {target_profile.get('device_product', 'unknown')}
- Port: {target_profile.get('port', '?')}
- Risk Level: {risk_level}
- CVEs: {cves_text}
- CPE: {target_profile.get('cpe', 'unknown')}

Based on this target, recommend an attack chain with diverse tools and optimized parameters.
Recommend 8-12 tools from: 
- autorecon, rustscan, nmap_advanced, enum4linux_ng, responder, nuclei, metasploit, smart_scan, select_tools

For each tool, provide:
1. Tool name
2. Why it's good for this target
3. Suggested parameters as JSON (e.g., {{"threads": 50, "timeout": 60, "aggressive": true}})

Format your response as JSON array:
[
  {{
    "tool": "tool_name",
    "reason": "why this tool",
    "parameters": {{"param1": "value1", "param2": "value2"}}
  }},
  ...
]

Focus on:
- Service fingerprinting tools for unknown services
- Exploitation tools for known CVEs  
- Intensive scanning for critical risk targets
- Stealth for lower-risk reconnaissance
"""
    return prompt


def extract_json_from_response(text: str) -> Optional[List[Dict[str, Any]]]:
    """Extract JSON from Ollama response (may include reasoning text)."""
    # Try to find JSON array in response
    match = re.search(r"\[[\s\S]*\]", text)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    return None


def _fallback_select_tools_chain(target: str, error: Optional[str] = None) -> Dict[str, Any]:
    """Fall back to HexStrike's built-in select_tools to produce an executable chain."""
    result = HexStrikeClient().run_action("select_tools", {"target": target})
    steps: List[Dict[str, Any]] = []
    if result.get("success") is not False and "error" not in result:
        # Convert select_tools response into chain steps.
        # The response may contain a "tools" list or similar structure.
        raw_tools = result.get("tools") or result.get("recommended_tools") or []
        if isinstance(raw_tools, list):
            for item in raw_tools:
                if isinstance(item, dict):
                    tool_name = item.get("tool") or item.get("name") or ""
                    params = item.get("parameters") or {}
                elif isinstance(item, str):
                    tool_name = item
                    params = {}
                else:
                    continue
                if tool_name:
                    steps.append({"tool": tool_name, "parameters": params, "reason": "Selected by HexStrike fallback"})
    base: Dict[str, Any] = {
        "attack_chain": {"steps": steps, "tool": "select_tools", "target": target},
        "ollama_used": False,
    }
    if error:
        base["error"] = error
    return base


def generate_smart_attack_chain(
    target: str, device_id: Optional[int] = None, use_ollama: bool = True
) -> Dict[str, Any]:
    """Generate an intelligent attack chain using Ollama and hexstrike intelligence."""
    device = None
    if device_id:
        try:
            device = Device.objects.get(pk=device_id)
        except Device.DoesNotExist:
            pass

    # Build target profile
    profile = build_target_profile(target, device)

    # If Ollama is disabled, fall back to hexstrike's select_tools
    if not use_ollama:
        return _fallback_select_tools_chain(target)

    # Query Ollama for recommendations
    prompt = craft_tool_recommendation_prompt(profile)
    ollama_response = query_ollama(prompt, timeout=60)

    if not ollama_response:
        return _fallback_select_tools_chain(target, error="Ollama unavailable")

    # Extract JSON from response
    recommendations = extract_json_from_response(ollama_response)

    if not recommendations:
        return _fallback_select_tools_chain(target, error="Could not parse Ollama recommendations")

    # Convert Ollama recommendations to hexstrike attack chain format
    steps = []
    for rec in recommendations:
        tool_name = rec.get("tool", "").strip()
        params = rec.get("parameters") or {}

        # Map tool names to hexstrike format
        tool_map = {
            "autorecon": "autorecon",
            "rustscan": "rustscan",
            "nmap_advanced": "nmap-advanced",
            "nmap": "nmap-advanced",
            "enum4linux_ng": "enum4linux-ng",
            "enum4linux-ng": "enum4linux-ng",
            "responder": "responder",
            "nuclei": "nuclei",
            "smart_scan": "smart_scan",
            "select_tools": "select_tools",
            "metasploit": "metasploit",
        }

        mapped_tool = tool_map.get(tool_name.lower(), tool_name)

        steps.append(
            {
                "tool": mapped_tool,
                "parameters": params,
                "reason": rec.get("reason", ""),
            }
        )

    # Calculate chain metadata — coerce timeout to int with safe default
    total_time = sum(int(s.get("parameters", {}).get("timeout") or 30) for s in steps)

    return {
        "attack_chain": {
            "steps": steps[:12],  # Limit to 12 tools
            "estimated_time": total_time,
            "risk_level": profile.get("risk_level"),
            "target_profile": profile,
            "tool": "ollama",
        },
        "ollama_used": True,
        "tool_count": len(steps),
        "reasoning": ollama_response[:500],  # First 500 chars of reasoning
    }
