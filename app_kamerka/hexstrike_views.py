"""HexSploit C2 console — bridges Kamerka devices to the local HexStrike server."""

from __future__ import annotations

import ast
import json

from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_GET, require_POST

from app_kamerka.hexstrike_client import HexStrikeClient, server_url, validate_target
from app_kamerka.models import Device, VulnIntelligence
from app_kamerka.ollama_payload_generator import (
    generate_smart_attack_chain,
    generate_watchlist_and_playbook,
)
from app_kamerka.views import _CVE_TO_MSF


def _device_vuln_ids(device: Device) -> list:
    if not device.vulns:
        return []
    try:
        parsed = ast.literal_eval(device.vulns)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def _hexsploit_context(device: Device | None) -> dict:
    cves = []
    msf_modules = []
    if device:
        cves = _device_vuln_ids(device)
        for cve in cves:
            cve_upper = cve.upper()
            mod = _CVE_TO_MSF.get(cve_upper)
            if mod:
                msf_modules.append({"cve_id": cve_upper, "module": mod})

        vi_rows = VulnIntelligence.objects.filter(device=device).order_by("-cvss_score")[:10]
        for vi in vi_rows:
            if vi.cve_id and vi.cve_id.upper() not in {m["cve_id"] for m in msf_modules}:
                mod = _CVE_TO_MSF.get(vi.cve_id.upper())
                if mod:
                    msf_modules.append({"cve_id": vi.cve_id.upper(), "module": mod})

    return {
        "device": device,
        "target": device.ip if device else "",
        "device_type": device.type if device else "",
        "device_product": device.product if device else "",
        "device_port": device.port if device else "",
        "cves": cves,
        "msf_modules": msf_modules,
        "hexstrike_url": server_url(),
    }


@ensure_csrf_cookie
@require_GET
def hexsploit_view(request):
    device = None
    device_id = request.GET.get("device_id")
    if device_id:
        device = get_object_or_404(Device, pk=device_id)

    health = HexStrikeClient().health()
    context = _hexsploit_context(device)
    context["hexstrike_online"] = health.get("status") == "healthy"
    context["health_version"] = health.get("version", "")
    context["health_error"] = health.get("error", "")
    crumbs = [{"label": "Launch", "url": "/"}, {"label": "HexSploit", "url": None}]
    if device:
        crumbs.insert(
            2,
            {
                "label": device.ip,
                "url": "/results/{}/{}/{}".format(
                    device.search_id, device.id, device.ip
                ),
            },
        )
    context["breadcrumbs"] = crumbs
    return render(request, "hexsploit.html", context)


@require_GET
def hexstrike_health_api(request):
    if request.headers.get("X-Requested-With") != "XMLHttpRequest":
        return JsonResponse({"error": "Invalid request"}, status=400)
    return JsonResponse(HexStrikeClient().health())


@require_POST
def hexstrike_action_api(request):
    if request.headers.get("X-Requested-With") != "XMLHttpRequest":
        return JsonResponse({"error": "Invalid request"}, status=400)

    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid JSON"}, status=400)

    action = (body.get("action") or "").strip()
    payload = body.get("payload") or {}

    device_id = body.get("device_id")
    if device_id and "target" not in payload:
        device = Device.objects.filter(pk=device_id).first()
        if device and device.ip:
            payload["target"] = device.ip

    # Use smart AI-driven chain planning for attack_chain action
    if action == "attack_chain" and payload.get("target"):
        raw_target = str(payload["target"])
        safe_target = validate_target(raw_target)
        if not safe_target:
            return JsonResponse({"success": False, "error": "Invalid target (use hostname or IPv4)"}, status=400)
        result = generate_smart_attack_chain(safe_target, device_id=device_id, use_ollama=True)
        status = 200
    elif action == "derive_watchlist_playbook" and payload.get("target"):
        raw_target = str(payload["target"])
        safe_target = validate_target(raw_target)
        if not safe_target:
            return JsonResponse({"success": False, "error": "Invalid target (use hostname or IPv4)"}, status=400)
        successful_results = payload.get("successful_results") or []
        chain_steps = payload.get("chain_steps") or []
        if not isinstance(successful_results, list):
            return JsonResponse({"success": False, "error": "successful_results must be a list"}, status=400)
        if not isinstance(chain_steps, list):
            return JsonResponse({"success": False, "error": "chain_steps must be a list"}, status=400)
        result = generate_watchlist_and_playbook(
            safe_target,
            successful_results=successful_results,
            chain_steps=chain_steps,
            device_id=device_id,
            use_ollama=True,
        )
        status = 200
    elif action == "derive_watchlist_playbook":
        return JsonResponse({"success": False, "error": "Missing required field: target"}, status=400)
    else:
        result = HexStrikeClient().run_action(action, payload)
        status = 200 if result.get("success") is not False and "error" not in result else 502
        if result.get("offline"):
            status = 503
    return JsonResponse(result, status=status)