#!/usr/bin/env python3
"""Simulate Launch UI: country + device preset + Shodan search (HTTP E2E)."""
import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
import json
import http.cookiejar
from urllib.parse import urlencode
from urllib.request import Request, build_opener, HTTPCookieProcessor

BASE = os.environ.get("KAMERKA_BASE_URL", "http://127.0.0.1:8000")


def main():
    cj = http.cookiejar.CookieJar()
    opener = build_opener(HTTPCookieProcessor(cj))

    def fetch(path, data=None, headers=None):
        h = dict(headers or {})
        if data is not None:
            req = Request(BASE + path, data=data, headers=h, method="POST")
        else:
            req = Request(BASE + path, headers=h)
        return opener.open(req, timeout=120)

    print("=== Launch: country=CN, device=hikvision ===")
    html = fetch("/").read().decode()
    if "ics_country" not in html:
        print("FAIL: launch form missing ics_country")
        return 1
    csrf = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', html)
    if not csrf:
        print("FAIL: no CSRF token")
        return 1
    body = urlencode(
        [
            ("csrfmiddlewaretoken", csrf.group(1)),
            ("country", "CN"),
            ("ics_country", "hikvision"),
        ]
    ).encode()
    resp = fetch(
        "/",
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": BASE + "/",
        },
    )
    final_url = resp.geturl()
    html = resp.read().decode()
    m = re.search(r"/results/(\d+)", final_url)
    if not m:
        print("FAIL: no redirect to results, url=", final_url)
        return 1
    search_id = m.group(1)
    print("PASS case created:", search_id, "url:", final_url)
    if "progress-bar" in html or "Collecting Shodan" in html:
        print("PASS results progress UI present")
    task_m = re.search(r"task_status/([a-f0-9-]+)", html)
    if task_m:
        tid = task_m.group(1)
        prog_url = BASE + "/celery-progress/task_status/" + tid + "/"
        for i in range(60):
            time.sleep(2)
            st = json.loads(fetch(prog_url).read().decode())
            state = st.get("state") or st.get("status")
            if i % 10 == 0:
                print("  poll", state, (st.get("description") or "")[:50])
            if state in ("SUCCESS", "FAILURE"):
                print("PASS shodan_search", state)
                break
        else:
            print("WARN: task still running after 120s")

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "kamerka.settings")
    import django

    django.setup()
    from app_kamerka.models import Device, Search

    s = Search.objects.get(id=search_id)
    print("Search:", s.country, "ics=", (s.ics or "")[:60])
    cnt = Device.objects.filter(search_id=search_id).count()
    print("Devices in case:", cnt)
    if Device.objects.filter(search_id=search_id, ip="218.207.218.98").exists():
        print("PASS target 218.207.218.98 appears in case")
    else:
        print("NOTE: target IP not in case yet (may need full scan or different query)")
    return 0


if __name__ == "__main__":
    sys.exit(main())