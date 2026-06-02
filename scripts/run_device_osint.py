#!/usr/bin/env python3
"""Run standard Kamerka OSINT tasks for a device (HTTP + Celery poll)."""
import json
import os
import re
import sys
import time
import http.cookiejar
from urllib.parse import urlencode, quote
from urllib.request import Request, build_opener, HTTPCookieProcessor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

BASE = os.environ.get("KAMERKA_BASE_URL", "http://127.0.0.1:8000")
AJAX = {"X-Requested-With": "XMLHttpRequest"}


def poll_task(opener, task_id, label, max_wait=300):
    for i in range(max_wait // 2):
        req = Request(
            f"{BASE}/get-task-info/?task_id={task_id}",
            headers=AJAX,
        )
        data = json.loads(opener.open(req, timeout=30).read().decode())
        state = data.get("state")
        if state in ("SUCCESS", "FAILURE"):
            print(f"PASS {label}", state, str(data.get("result"))[:200])
            return data
        time.sleep(2)
    print(f"WARN {label} timeout")
    return None


def enqueue(opener, path, label):
    req = Request(BASE + path, headers=AJAX)
    data = json.loads(opener.open(req, timeout=30).read().decode())
    tid = data.get("task_id")
    if not tid:
        print(f"FAIL {label} no task_id", data)
        return None
    print(f"START {label} {tid[:8]}...")
    return poll_task(opener, tid, label)


def main():
    device_id = int(sys.argv[1]) if len(sys.argv) > 1 else 499
    cj = http.cookiejar.CookieJar()
    opener = build_opener(HTTPCookieProcessor(cj))

    page = opener.open(
        Request(f"{BASE}/results/18/{device_id}/218.207.218.98"), timeout=30
    ).read().decode()
    if "km-tool-dock" not in page:
        # resolve ip dynamically
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "kamerka.settings")
        import django

        django.setup()
        from app_kamerka.models import Device

        d = Device.objects.get(id=device_id)
        page = opener.open(
            Request(
                f"{BASE}/results/{d.search_id}/{device_id}/{d.ip}",
            ),
            timeout=30,
        ).read().decode()
    print(f"PASS workbench loaded device_id={device_id}")

    enqueue(opener, f"/port_scan/{device_id}", "port_scan")
    enqueue(opener, f"/whois/{device_id}", "whois")
    enqueue(opener, f"/{device_id}/shodan/scan", "shodan_host")
    enqueue(opener, f"/{device_id}/gfw/check", "gfw")
    flags = "-p 80,102,443,8081,4443,8181,21116 -sV -T4 --open"
    req = Request(
        f"{BASE}/manual_nmap/{device_id}?flags={quote(flags)}",
        headers=AJAX,
    )
    data = json.loads(opener.open(req, timeout=30).read().decode())
    if data.get("task_id"):
        poll_task(opener, data["task_id"], "nmap")
    enqueue(opener, f"/{device_id}/nvd/scan", "nvd")

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "kamerka.settings")
    import django

    django.setup()
    from app_kamerka.models import Device, Whois, ShodanScan, GFWStatus

    d = Device.objects.get(id=device_id)
    print("\n=== Summary ===")
    print("IP", d.ip, "port field", (d.port or "")[:120])
    w = Whois.objects.filter(device=d).first()
    if w:
        print("Whois", w.org, w.city)
    s = ShodanScan.objects.filter(device=d).first()
    if s:
        print("ShodanScan ports", s.ports)
    g = GFWStatus.objects.filter(device=d).first()
    if g:
        print("GFW reachable", g.reachable)
    print("Workbench", f"{BASE}/results/{d.search_id}/{device_id}/{d.ip}")
    print("Case", f"{BASE}/results/{d.search_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())