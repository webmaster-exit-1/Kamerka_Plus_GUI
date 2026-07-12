#!/usr/bin/env python3
"""Run remaining Kamerka device workbench tools (recon/OSINT, not exploit).

Prefer GUI-driven validation:  ./.venv/bin/python scripts/gui_e2e_playwright.py workbench <device_id>
"""
import json
import os
import sys
import time
import http.cookiejar
from urllib.parse import quote
from urllib.request import Request, build_opener, HTTPCookieProcessor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
BASE = os.environ.get("KAMERKA_BASE_URL", "http://127.0.0.1:8000")
AJAX = {"X-Requested-With": "XMLHttpRequest"}
DEVICE_ID = int(os.environ.get("KAMERKA_DEVICE_ID", "499"))


def poll(opener, task_id, label, max_wait=600):
    if not task_id:
        return None
    for _ in range(max_wait // 2):
        req = Request(f"{BASE}/get-task-info/?task_id={task_id}", headers=AJAX)
        data = json.loads(opener.open(req, timeout=60).read().decode())
        state = data.get("state")
        if state in ("SUCCESS", "FAILURE"):
            res = data.get("result")
            snippet = str(res)[:180] if res is not None else ""
            print(f"  {label}: {state} {snippet}")
            return data
        time.sleep(2)
    print(f"  {label}: TIMEOUT")
    return None


def enqueue_get(opener, path, label, ajax=True, max_wait=600):
    headers = AJAX if ajax else {}
    try:
        req = Request(BASE + path, headers=headers)
        raw = opener.open(req, timeout=60).read().decode()
        if raw.strip().startswith("{") or raw.strip().startswith("["):
            data = json.loads(raw)
            if data.get("Error"):
                print(f"  {label}: SKIP {data.get('Error')}")
                return data
            tid = data.get("task_id")
            if tid:
                print(f"  {label}: queued {tid[:8]}...")
                return poll(opener, tid, label, max_wait)
            print(f"  {label}: {str(data)[:120]}")
            return data
        print(f"  {label}: OK ({len(raw)} bytes)")
        return {"raw": True}
    except Exception as exc:
        print(f"  {label}: ERROR {exc}")
        return None


def main():
    did = int(sys.argv[1]) if len(sys.argv) > 1 else DEVICE_ID
    cj = http.cookiejar.CookieJar()
    opener = build_opener(HTTPCookieProcessor(cj))

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "kamerka.settings")
    import django

    django.setup()
    from app_kamerka.models import Device

    dev = Device.objects.get(id=did)
    ip = dev.ip
    case = dev.search_id
    print(f"=== Rest of suite: device {did} {ip} (case {case}) ===\n")

    jobs = [
        (f"/{did}/wappalyzer/scan", "wappalyzer", True, 120),
        (
            f"/{did}/nuclei/scan?templates_dir=nuclei_templates/china-iot",
            "nuclei_china-iot",
            True,
            300,
        ),
        (f"/{did}/rtsp/scan", "rtsp", False, 180),
        (f"/{did}/deep_scan?protocol=s7", "deep_scan_s7", True, 300),
        (f"/scan/{did}?nse_script=nmap_scripts/s7-info.nse", "nmap_s7_nse", True, 300),
        (
            f"/scan/{did}?nse_script=nmap_scripts/modbus-discover.nse",
            "nmap_modbus_nse",
            True,
            300,
        ),
        (f"/{did}/nrich/scan", "nrich", True, 120),
        (f"/{did}/cvedb/enrich", "cvedb", True, 120),
        (f"/{did}/shodan/intel", "shodan_intel", True, 120),
        (f"/{did}/honeypot/scan", "honeypot", True, 180),
        (f"/{did}/sbom/scan", "sbom", True, 120),
        (f"/{did}/screenshot", "screenshot", True, 120),
        (f"/{did}/exploitdb/search", "exploitdb", True, 120),
        (f"/{did}/shodan/trends", "shodan_trends", True, 120),
        (f"/{did}/msf/resource", "msf_resource", True, 60),
        (f"/{did}/recon-ng/script", "recon_ng", True, 60),
    ]

    for path, label, ajax, wait in jobs:
        print(f"[{label}]")
        enqueue_get(opener, path, label, ajax=ajax, max_wait=wait)
        time.sleep(1)

    print(f"\n[report]")
    enqueue_get(opener, f"/report/device/{did}", "report", ajax=False, max_wait=30)

    # Summary from DB
    from app_kamerka.models import (
        WappalyzerResult,
        NucleiResult,
        ProtocolFingerprint,
        HoneypotAnalysis,
        SBOMComponent,
        VulnIntelligence,
    )

    print("\n=== DB summary ===")
    print("Wappalyzer:", WappalyzerResult.objects.filter(device_id=did).count())
    print("Nuclei:", NucleiResult.objects.filter(device_id=did).count())
    print("Fingerprints:", ProtocolFingerprint.objects.filter(device_id=did).count())
    for fp in ProtocolFingerprint.objects.filter(device_id=did)[:5]:
        print(f"  - {fp.protocol}: {fp.vendor_id or fp.module_name or fp.firmware_version or 'ok'}")
    print("VulnIntel:", VulnIntelligence.objects.filter(device_id=did).count())
    hp = HoneypotAnalysis.objects.filter(device_id=did).first()
    if hp:
        print("Honeypot score:", hp.honeypot_score, "verdict:", hp.verdict)
    print("SBOM:", SBOMComponent.objects.filter(device_id=did).count())
    print(f"\nWorkbench: {BASE}/results/{case}/{did}/{ip}")
    return 0


if __name__ == "__main__":
    sys.exit(main())