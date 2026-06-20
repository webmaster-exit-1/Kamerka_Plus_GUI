"""HTTP client for the local HexStrike AI tools server (not MCP — use REST like hexstrike_mcp.py)."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple

import requests
from django.conf import settings

_TARGET_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$|^(?:\d{1,3}\.){3}\d{1,3}$"
)
_ACTION_RE = re.compile(r"^[a-zA-Z0-9_-]{1,80}$")

# Whitelisted proxy actions: name -> (method, path, required payload keys)
ALLOWED_ACTIONS: Dict[str, Tuple[str, str, Tuple[str, ...]]] = {
    "health": ("GET", "health", ()),
    "analyze_target": ("POST", "api/intelligence/analyze-target", ("target",)),
    "smart_scan": ("POST", "api/intelligence/smart-scan", ("target",)),
    "select_tools": ("POST", "api/intelligence/select-tools", ("target",)),
    "attack_chain": ("POST", "api/intelligence/create-attack-chain", ("target",)),
    "process_dashboard": ("GET", "api/processes/dashboard", ()),
    "nuclei": ("POST", "api/tools/nuclei", ("target",)),
    "metasploit": ("POST", "api/tools/metasploit", ("module",)),
    "autorecon": ("POST", "api/tools/autorecon", ("target",)),
    "rustscan": ("POST", "api/tools/rustscan", ("target",)),
    "nmap_advanced": ("POST", "api/tools/nmap-advanced", ("target",)),
    "enum4linux_ng": ("POST", "api/tools/enum4linux-ng", ("target",)),
    "responder": ("POST", "api/tools/responder", ("target",)),
}


def server_url() -> str:
    return (getattr(settings, "HEXSTRIKE_SERVER_URL", "") or "http://127.0.0.1:8888").rstrip("/")


def validate_target(value: str) -> Optional[str]:
    target = (value or "").strip()
    if not target or len(target) > 253:
        return None
    if " " in target or any(c in target for c in ";|&$`<>"):
        return None
    if _TARGET_RE.match(target):
        return target
    return None


class HexStrikeClient:
    def __init__(self, base_url: Optional[str] = None, timeout: Optional[int] = None):
        self.base_url = (base_url or server_url()).rstrip("/")
        self.timeout = timeout or int(getattr(settings, "HEXSTRIKE_TIMEOUT", 300))
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Kamerka-HexSploit/1.0"})

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def request(self, method: str, path: str, json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            if method.upper() == "GET":
                resp = self.session.get(self._url(path), params=json_data or {}, timeout=min(self.timeout, 30))
            else:
                resp = self.session.post(self._url(path), json=json_data or {}, timeout=self.timeout)
            resp.raise_for_status()
            if resp.content:
                return resp.json()
            return {"success": True}
        except requests.exceptions.ConnectionError:
            return {
                "success": False,
                "error": "Cannot reach HexStrike server at {}. Start it with: "
                "cd ~/hexstrike-ai && source venv/bin/activate && python3 hexstrike_server.py".format(
                    self.base_url
                ),
                "offline": True,
            }
        except requests.exceptions.Timeout:
            return {"success": False, "error": "HexStrike request timed out", "offline": False}
        except requests.exceptions.HTTPError as exc:
            body = ""
            try:
                body = exc.response.text[:500]
            except Exception:
                pass
            return {"success": False, "error": f"HexStrike HTTP {exc.response.status_code}: {body}"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def run_action(self, action: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        action = (action or "").strip()
        spec = ALLOWED_ACTIONS.get(action)
        dynamic_action = False
        dynamic_action_alt_path = ""
        if not spec:
            # Dynamic pass-through for HexStrike tool endpoints.
            # This lets the UI execute the full HexStrike catalog without hardcoding every tool.
            if not _ACTION_RE.match(action):
                return {"success": False, "error": f"Unknown action: {action}"}
            dynamic_action = True
            spec = ("POST", f"api/tools/{action}", ())
            if "_" in action:
                dynamic_action_alt_path = f"api/tools/{action.replace('_', '-')}"
            elif "-" in action:
                dynamic_action_alt_path = f"api/tools/{action.replace('-', '_')}"

        method, path, required = spec
        data = dict(payload or {})

        for key in required:
            if key not in data or data[key] in (None, ""):
                return {"success": False, "error": f"Missing required field: {key}"}

        if "target" in data:
            validated = validate_target(str(data["target"]))
            if not validated:
                return {"success": False, "error": "Invalid target (use hostname or IPv4)"}
            data["target"] = validated

        if action == "metasploit":
            module = str(data.get("module", "")).strip()
            if not re.match(r"^[a-zA-Z0-9_/\-]+$", module):
                return {"success": False, "error": "Invalid Metasploit module path"}

        result = self.request(method, path, data)
        if (
            dynamic_action
            and dynamic_action_alt_path
            and result.get("success") is False
            and "HTTP 404" in str(result.get("error", ""))
        ):
            result = self.request("POST", dynamic_action_alt_path, data)
        result.setdefault("action", action)
        return result

    def health(self) -> Dict[str, Any]:
        return self.run_action("health")