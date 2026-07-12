"""AI-driven payload generation using Ollama for smart tool selection and parameter crafting."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

import requests
from django.conf import settings

import app_kamerka.tool_registry as tool_registry
from app_kamerka.hexstrike_client import HexStrikeClient
from app_kamerka.models import Device, Playbook, VulnIntelligence, Watchlist


def ollama_url() -> str:
    """Get Ollama server URL from settings."""
    return (getattr(settings, "HEXSPLOIT_OLLAMA_SERVER_URL", "") or "http://192.168.1.103:11434").rstrip("/")


def ollama_model() -> str:
    """Get Ollama model name from settings."""
    return getattr(settings, "HEXSPLOIT_OLLAMA_MODEL", "DeepHat/DeepHat-V1-7B:latest")


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
    profile = {
        "target": target,
        "device_type": "unknown",
        "open_ports": [],
        "services": [],
        "cves": [],
        "risk_level": "unknown",
    }

    if device:
        profile["device_type"] = device.type or "unknown"
        profile["device_product"] = device.product or ""
        profile["port"] = device.port or ""
        profile["isp"] = device.isp or ""
        profile["cpe"] = device.cpe or ""
        profile["country_code"] = (device.country_code or "").upper()
        if device.lat is not None and device.lon is not None:
            profile["coordinates"] = "{},{}".format(device.lat, device.lon)

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
Use the full HexStrike toolset, not a small fixed shortlist.
Choose however many tools are appropriate for this target. Do not cap at 10-12 unless it is truly optimal.
Prefer deeper coverage on high-risk targets and narrower, stealthier chains on low-risk targets.

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
Use exact HexStrike endpoint slugs for tool names, matching documentation syntax.
Examples: nmap-advanced, enum4linux-ng, http-framework, one-gadget, api_fuzzer, graphql_scanner.

Only return JSON. No markdown, no prose outside the JSON array.
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


def extract_json_object_from_response(text: str) -> Optional[Dict[str, Any]]:
    """Extract top-level JSON object from Ollama response."""
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        try:
            parsed = json.loads(match.group())
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return None
    return None


def _fallback_select_tools_chain(target: str, error: Optional[str] = None) -> Dict[str, Any]:
    """Fall back to HexStrike's built-in select_tools to produce an executable chain."""
    result = HexStrikeClient().run_action("select_tools", {"target": target})
    steps: List[Dict[str, Any]] = []
    if result.get("success") is not False and "error" not in result:
        # Convert select_tools response into chain steps.
        # The response may contain a "tools" list or similar structure.
        raw_tools = (
            result.get("tools")
            or result.get("recommended_tools")
            or result.get("selected_tools")
            or []
        )
        if isinstance(raw_tools, list):
            for item in raw_tools:
                if isinstance(item, dict):
                    tool_name = (
                        item.get("tool")
                        or item.get("name")
                        or item.get("tool_name")
                        or ""
                    )
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
        tool_name = str(rec.get("tool", "")).strip().lower()
        params = rec.get("parameters") or {}
        if not tool_name:
            continue
        # Keep HexStrike-native endpoint slug format from docs/model output.
        mapped_tool = re.sub(r"\s+", "-", tool_name)

        steps.append(
            {
                "tool": mapped_tool,
                "parameters": params,
                "reason": rec.get("reason", ""),
            }
        )

    # Calculate chain metadata with safe timeout coercion.
    total_time = 0
    for step in steps:
        timeout_value = step.get("parameters", {}).get("timeout")
        try:
            total_time += int(timeout_value or 30)
        except (TypeError, ValueError):
            total_time += 30

    return {
        "attack_chain": {
            "steps": steps,
            "estimated_time": total_time,
            "risk_level": profile.get("risk_level"),
            "target_profile": profile,
            "tool": "ollama",
        },
        "ollama_used": True,
        "tool_count": len(steps),
        "reasoning": ollama_response[:1500],
    }


def _unique_name(base_name: str, model_cls) -> str:
    name = (base_name or "").strip()[:120]
    if not name:
        name = "hexsploit-generated"
    if not model_cls.objects.filter(name=name).exists():
        return name
    for i in range(2, 200):
        candidate = "{}-{}".format(name[:116], i)
        if not model_cls.objects.filter(name=candidate).exists():
            return candidate
    return "{}-{}".format(name[:108], model_cls.objects.count() + 1)


def _normalize_query_items(raw_items: Any) -> List[str]:
    if not isinstance(raw_items, list):
        return []
    cleaned: List[str] = []
    for item in raw_items:
        value = str(item).strip()
        if value and value not in cleaned:
            cleaned.append(value[:100])
    return cleaned[:25]


def _default_playbook_steps_from_success(successful_results: List[Dict[str, Any]]) -> List[str]:
    tool_map = {
        "nmap-advanced": "nmap",
        "nmap": "nmap",
        "rustscan": "port_scan",
        "masscan": "port_scan",
        "autorecon": "nmap",
        "nuclei": "nuclei",
        "wafw00f": "wappalyzer",
        "enum4linux-ng": "deep_scan",
        "enum4linux": "deep_scan",
    }
    selected: List[str] = []
    for item in successful_results:
        tool = str(item.get("tool") or "").strip().lower()
        action = str(item.get("action") or "").strip().lower()
        mapped = tool_map.get(tool) or tool_map.get(action)
        if mapped and mapped not in selected:
            selected.append(mapped)
    return selected


def craft_artifact_prompt(
    target_profile: Dict[str, Any],
    successful_results: List[Dict[str, Any]],
    available_playbook_tools: List[str],
) -> str:
    executions_preview = []
    for row in successful_results[:12]:
        executions_preview.append(
            {
                "tool": row.get("tool", ""),
                "action": row.get("action", ""),
                "parameters": row.get("parameters", {}),
            }
        )
    return """You are DeepHat generating SOC automation artifacts from successful HexStrike execution output.

Target Profile JSON:
{}

Successful Execution Preview JSON:
{}

Create exactly one watchlist and one Kamerka playbook.
The playbook MUST use only tools from this allowed list:
{}

Return a single JSON object with this exact schema:
{{
  "watchlist": {{
    "name": "string",
    "query_type": "country|coordinates",
    "country": "US",
    "coordinates": "lat,lon",
    "query_items": ["string"],
    "category": "ics",
    "healthcare": false,
    "all_results": false,
    "refresh_interval_minutes": 60,
    "rationale": "short explanation"
  }},
  "playbook": {{
    "name": "string",
    "description": "string",
    "steps": [
      {{"tool": "nuclei", "order": 1, "exec_type": "chain"}}
    ]
  }}
}}

Constraints:
- query_type must be country or coordinates only.
- If query_type=country, provide ISO country code in country.
- If query_type=coordinates, provide coordinates as "lat,lon".
- query_items should be high-signal tags only.
- Include 2-8 playbook steps in practical order.
- playbook steps must use ONLY the allowed tool names list.
- Return JSON only, no markdown.
""".format(
        json.dumps(target_profile, ensure_ascii=True),
        json.dumps(executions_preview, ensure_ascii=True),
        json.dumps(available_playbook_tools, ensure_ascii=True),
    )


def generate_watchlist_and_playbook(
    target: str,
    successful_results: List[Dict[str, Any]],
    chain_steps: Optional[List[Dict[str, Any]]] = None,
    device_id: Optional[int] = None,
    use_ollama: bool = True,
) -> Dict[str, Any]:
    """Generate and persist a Watchlist + Playbook from successful HexStrike execution."""
    device = None
    if device_id:
        try:
            device = Device.objects.get(pk=device_id)
        except Device.DoesNotExist:
            device = None

    profile = build_target_profile(target, device)
    available_tools = [p.name for p in tool_registry.enabled_tools()]
    llm_json: Dict[str, Any] = {}
    reasoning = ""
    ollama_used = False

    if use_ollama:
        prompt = craft_artifact_prompt(profile, successful_results, available_tools)
        response = query_ollama(prompt, timeout=75)
        if response:
            parsed = extract_json_object_from_response(response)
            if parsed:
                llm_json = parsed
                reasoning = response[:1500]
                ollama_used = True

    watch_cfg = llm_json.get("watchlist", {}) if isinstance(llm_json, dict) else {}
    query_type = str(watch_cfg.get("query_type") or "").strip().lower()
    if query_type not in {Watchlist.QUERY_COUNTRY, Watchlist.QUERY_COORDINATES}:
        query_type = (
            Watchlist.QUERY_COORDINATES
            if profile.get("coordinates")
            else Watchlist.QUERY_COUNTRY
        )
    country_code = str(watch_cfg.get("country") or profile.get("country_code") or "").strip().upper()[:100]
    coordinates = str(watch_cfg.get("coordinates") or profile.get("coordinates") or "").strip()[:100]
    query_items = _normalize_query_items(watch_cfg.get("query_items"))
    category = str(watch_cfg.get("category") or "ics").strip()[:100] or "ics"
    healthcare = bool(watch_cfg.get("healthcare", False))
    all_results = bool(watch_cfg.get("all_results", False))
    try:
        refresh_minutes = int(watch_cfg.get("refresh_interval_minutes", 60))
    except (TypeError, ValueError):
        refresh_minutes = 60
    refresh_minutes = max(5, min(refresh_minutes, 1440))

    watch_name = _unique_name(
        str(watch_cfg.get("name") or "hexsploit-watchlist-{}".format(target)),
        Watchlist,
    )
    watchlist = Watchlist.objects.create(
        name=watch_name,
        query_type=query_type,
        country=country_code,
        coordinates=coordinates,
        query_items=query_items,
        category=category,
        healthcare=healthcare,
        all_results=all_results,
        enabled=True,
        refresh_interval_minutes=refresh_minutes,
    )
    watchlist.next_run_at = watchlist.compute_next_run_at()
    watchlist.save(update_fields=["next_run_at", "updated_at"])

    playbook_cfg = llm_json.get("playbook", {}) if isinstance(llm_json, dict) else {}
    raw_steps = playbook_cfg.get("steps") if isinstance(playbook_cfg, dict) else []
    valid_steps: List[Dict[str, Any]] = []
    if isinstance(raw_steps, list):
        seen = set()
        for idx, step in enumerate(raw_steps, start=1):
            if not isinstance(step, dict):
                continue
            tool = str(step.get("tool") or "").strip()
            if not tool or tool not in available_tools or tool in seen:
                continue
            seen.add(tool)
            valid_steps.append(
                {
                    "tool": tool,
                    "order": idx,
                    "exec_type": "chain",
                }
            )

    if not valid_steps:
        fallback_tools = _default_playbook_steps_from_success(successful_results)
        seen = set()
        for idx, tool in enumerate(fallback_tools, start=1):
            if tool in available_tools and tool not in seen:
                seen.add(tool)
                valid_steps.append({"tool": tool, "order": idx, "exec_type": "chain"})
        if not valid_steps and "nuclei" in available_tools:
            valid_steps = [{"tool": "nuclei", "order": 1, "exec_type": "chain"}]

    playbook_name = _unique_name(
        str(playbook_cfg.get("name") or "hexsploit-playbook-{}".format(target)),
        Playbook,
    )
    playbook_desc = str(
        playbook_cfg.get("description")
        or "Auto-generated from successful HexStrike execution on {}".format(target)
    ).strip()
    playbook = Playbook.objects.create(
        name=playbook_name,
        description=playbook_desc[:2000],
        steps=valid_steps,
    )

    return {
        "success": True,
        "ollama_used": ollama_used,
        "watchlist": {
            "id": watchlist.pk,
            "name": watchlist.name,
            "query_type": watchlist.query_type,
        },
        "playbook": {
            "id": playbook.pk,
            "name": playbook.name,
            "step_count": len(valid_steps),
        },
        "reasoning": reasoning,
        "message": "Watchlist and playbook created from successful execution.",
    }
