#!/usr/bin/env python3
"""
Drive Kamerka through the real web UI (same buttons/flows a user clicks).

Usage:
    ./.venv/bin/python scripts/gui_e2e_playwright.py workbench 499
    ./.venv/bin/python scripts/gui_e2e_playwright.py launch CN s7
    python scripts/gui_e2e_playwright.py smoke
    python scripts/gui_e2e_playwright.py smoke --base-url http://127.0.0.1:8000 --device-path /results/1/1/192.0.2.1

Requires: pip install playwright && playwright install chromium

Smoke uses live local pages, but blocks external browser requests and mocks action
and export requests. It never submits searches or starts real scans. Set
PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH to override the smoke browser executable.
The legacy launch/workbench commands DO perform real actions.
"""
from __future__ import annotations

import sys
import time

ROOT = __file__

def run_workbench(device_id: int, ip: str = "218.207.218.98", case_id: int = 18):
    from playwright.sync_api import sync_playwright

    base = "http://127.0.0.1:8000"
    url = f"{base}/results/{case_id}/{device_id}/{ip}"
    results = []

    def log(msg):
        print(msg)
        results.append(msg)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(url, wait_until="networkidle", timeout=60000)
        assert page.locator(".km-tool-dock").is_visible()
        log(f"PASS workbench loaded {url}")

        def click_dock(tab_label):
            page.locator(f'.km-tool-dock button:has-text("{tab_label}")').click()
            time.sleep(0.3)

        def wait_gui_activity(timeout_s=45):
            """Wait for km-tool-output or noty (same feedback the user sees)."""
            before = page.locator("#km-tool-output").inner_text()
            end = time.time() + timeout_s
            while time.time() < end:
                out = page.locator("#km-tool-output").inner_text()
                if out != before and "→ ok" in out:
                    return True
                if page.locator(".noty_type__success, .noty_type__error").count() > 0:
                    time.sleep(0.5)
                    return True
                time.sleep(0.5)
            return False

        # --- Intel tab (GUI) ---
        click_dock("Intel")
        page.locator('a[href="#tab9"]').click()
        time.sleep(0.5)

        if page.locator("#shodan_scan").is_visible():
            page.locator("#shodan_scan").click()
            log("CLICK Shodan Scan (Intel)")
            wait_gui_activity(60)

        if page.locator("#whois_scan").is_visible():
            page.locator("#whois_scan").click()
            log("CLICK WHOIS Scan")
            wait_gui_activity(45)

        page.locator("#whois_show").click()
        log("CLICK WHOIS Display")
        wait_gui_activity(15)

        # --- Risk tab (GUI) ---
        click_dock("Risk")
        page.locator('a[href="#tab_risk"]').click()
        time.sleep(0.5)

        for btn_id, name in [
            ("#gfw_check_btn", "GFW"),
            ("#honeypot_scan_btn", "Honeypot"),
            ("#nrich_scan_btn", "nrich"),
        ]:
            if page.locator(btn_id).is_visible():
                page.locator(btn_id).click()
                log(f"CLICK {name}")
                wait_gui_activity(45)

        # --- Nmap tab (GUI) ---
        click_dock("Nmap")
        page.locator('a[href="#tab10"]').click()
        time.sleep(0.5)
        page.locator("#manual_nmap_flags").fill("-p 80,161 -sV --open")
        page.locator("#manual_nmap_btn").click()
        log("CLICK Manual Nmap")
        wait_gui_activity(90)

        out = page.locator("#km-tool-output").inner_text()
        log(f"GUI output pane lines: {len(out.splitlines())}")
        browser.close()

    return 0


def run_launch(country: str, preset: str):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto("http://127.0.0.1:8000/", wait_until="networkidle", timeout=60000)

        # ICS tab is default; set country + device preset via DOM
        page.evaluate(
            """([country, preset]) => {
            const c = document.querySelector('select[name="country"]');
            if (c) { c.value = country; c.dispatchEvent(new Event('change')); }
            const ics = document.getElementById('ics_country');
            if (ics) {
              Array.from(ics.options).forEach(o => { o.selected = (o.value === preset); });
              ics.dispatchEvent(new Event('change'));
            }
        }""",
            [country, preset],
        )
        page.locator('form[method="POST"] button.btn-submit').first.click()

        # Credit cost modal → Confirm
        page.wait_for_selector("#credit-cost-modal", state="visible", timeout=10000)
        page.locator("#credit-cost-confirm").click()
        page.wait_for_url("**/results/**", timeout=30000)
        print(f"PASS Launch submitted country={country} preset={preset}")
        print("URL", page.url)
        browser.close()
    return 0


def run_smoke(base_url: str, device_path: str):
    import os
    import re
    import tempfile
    from collections import Counter
    from pathlib import Path
    from urllib.parse import parse_qs, urlsplit

    from playwright.sync_api import expect, sync_playwright

    base_url = base_url.rstrip("/")
    origin = urlsplit(base_url)
    if origin.scheme not in ("http", "https") or origin.hostname not in (
        "127.0.0.1", "localhost", "::1"
    ) or origin.path or origin.query or origin.fragment:
        raise ValueError("Smoke requires a loopback base URL without a path.")
    match = re.fullmatch(r"/results/(\d+)/(\d+)/([^/?#]+)", device_path)
    if not match:
        raise ValueError("--device-path must be /results/CASE/DEVICE/IP")
    case_id, device_id, _ = match.groups()
    case_path = f"/results/{case_id}"
    main_paths = (
        "/", "/index", "/history", "/devices", "/map", "/map3d",
        "/camera-wall", "/gallery", "/feeds-briefing", "/tasks",
        "/playbooks/", "/watchlists", "/hexsploit/", "/healthz/setup/", "/sources",
    )
    live_paths = {*main_paths, case_path, device_path}
    export_paths = (
        f"/export/csv/{case_id}", f"/export/kml/{case_id}",
        f"/export/json/{case_id}", f"/api/export/geojson/{case_id}",
        f"/report/device/{device_id}", f"/{device_id}/msf/resource",
        f"/{device_id}/recon-ng/script",
    )
    mocked_actions = {
        f"/{device_id}/shodan/scan", f"/manual_nmap/{device_id}",
        f"/{device_id}/nrich/scan",
    }
    traffic = Counter()
    failures = []
    passed = 0

    def guard(route):
        request = route.request
        target = urlsplit(request.url)
        if (target.scheme, target.netloc) != (origin.scheme, origin.netloc):
            traffic["blocked external"] += 1
            route.abort()
        elif target.path in mocked_actions:
            traffic[f"mocked action {target.path}"] += 1
            route.fulfill(status=503, json={"Error": "SMOKE: no scan executed"})
        elif target.path in export_paths:
            traffic[f"mocked export {target.path}"] += 1
            route.fulfill(content_type="text/html", body="<p>Smoke export fixture</p>")
        elif request.method == "GET" and (
            target.path in live_paths or target.path.startswith("/static/")
        ):
            traffic["live local GET"] += 1
            route.continue_()
        else:
            # Deny by default: several existing scan endpoints mutate state on GET.
            traffic[f"blocked {request.method} {target.path}"] += 1
            route.fulfill(status=503, json={"Error": "SMOKE: request blocked"})

    def check(name, test, width=1440):
        nonlocal passed
        page = context.new_page()
        page.set_viewport_size({"width": width, "height": 900})
        page.set_default_timeout(7000)
        page.set_default_navigation_timeout(30000)
        try:
            test(page)
            passed += 1
            print(f"PASS {name}", flush=True)
        except Exception as exc:
            failures.append(name)
            print(f"FAIL {name}: {exc}", flush=True)
        finally:
            page.close()

    def visit(page, path):
        response = page.goto(base_url + path, wait_until="networkidle")
        assert response and response.ok, f"{path}: HTTP {response.status if response else 'none'}"
        expect(page.locator("#main-content")).to_be_visible()
        expect(page.locator("#km-navigation")).to_have_count(1)

    def no_overflow(page):
        dimensions = page.evaluate("""() => ({
            viewport: document.documentElement.clientWidth,
            document: document.documentElement.scrollWidth,
            body: document.body.scrollWidth
        })""")
        assert max(dimensions["document"], dimensions["body"]) <= dimensions["viewport"] + 1, dimensions

    def navigation(page, path, mobile):
        visit(page, "/")
        if mobile:
            page.locator("#km-nav-toggle").click()
        selector = f'#km-navigation nav a[href="{path}"], #km-navigation nav a[href^="{path}?"]'
        link = page.locator(selector)
        expect(link).to_have_count(1)
        with page.expect_navigation(wait_until="networkidle") as navigation_response:
            link.click(timeout=30000)
        response = navigation_response.value
        assert response and response.ok, f"{path}: HTTP {response.status if response else 'none'}"
        assert urlsplit(page.url).path == path, page.url
        expect(page.locator("#main-content")).to_be_visible()
        expect(page.locator(selector)).to_have_attribute("aria-current", "page")
        if mobile:
            expect(page.locator("#km-nav-toggle")).to_have_attribute("aria-expanded", "false")
            expect(page.locator(".km-nav-backdrop")).to_be_hidden()
        no_overflow(page)

    def drawer(page):
        visit(page, "/")
        toggle = page.locator("#km-nav-toggle")
        sidebar = page.locator("#km-navigation")
        backdrop = page.locator(".km-nav-backdrop")

        def assert_closed():
            expect(toggle).to_have_attribute("aria-expanded", "false")
            expect(backdrop).to_be_hidden()
            assert not page.locator(".page-content").evaluate("(el) => el.inert")

        def open_drawer():
            toggle.click()
            expect(toggle).to_have_attribute("aria-expanded", "true")
            expect(backdrop).to_be_visible()
            expect(sidebar.locator("[data-km-nav-close]")).to_be_focused()
            assert page.locator(".page-content").evaluate("(el) => el.inert")

        assert_closed()
        open_drawer()
        focusables = sidebar.locator('a[href]:visible, button:not([disabled]):visible, [tabindex="0"]:visible')
        focusables.first.focus()
        page.keyboard.press("Shift+Tab")
        expect(focusables.last).to_be_focused()
        page.keyboard.press("Tab")
        expect(focusables.first).to_be_focused()
        page.keyboard.press("Escape")
        assert_closed()
        expect(toggle).to_be_focused()
        open_drawer()
        sidebar.locator("[data-km-nav-close]").click()
        assert_closed()
        expect(toggle).to_be_focused()
        open_drawer()
        # The left portion of the backdrop is intentionally covered by the drawer.
        backdrop.click(position={"x": 385, "y": 450})
        assert_closed()
        expect(toggle).to_be_focused()
        open_drawer()
        page.set_viewport_size({"width": 1440, "height": 900})
        assert_closed()
        expect(toggle).to_be_hidden()
        expect(sidebar.locator('a[href="/history"]')).to_be_visible()
        no_overflow(page)
        page.set_viewport_size({"width": 390, "height": 900})
        assert_closed()
        open_drawer()
        page.keyboard.press("Escape")
        assert_closed()
        no_overflow(page)

    dock_tabs = {
        "Locate": "#tab8", "Intel": "#tab9", "Nmap": "#tab10",
        "Exploit": "#tab11", "Hardware": "#tab_hw",
        "Risk": "#tab_risk", "Supply": "#tab_supply",
    }

    def dock(page, label, target):
        visit(page, device_path)
        expect(page.locator("[data-km-dock-tab]")).to_have_count(7)
        button = page.get_by_role("button", name=label, exact=True)
        button.click()

        def assert_active():
            expect(button).to_have_attribute("aria-pressed", "true")
            expect(page.locator('[data-km-dock-tab][aria-pressed="true"]')).to_have_count(1)
            expect(page.locator('[data-km-dock-tab][aria-pressed="false"]')).to_have_count(6)
            expect(page.locator(target)).to_be_visible()
            expect(page.locator(".km-device-tab-content > .tab-pane:visible")).to_have_count(1)
            assert urlsplit(page.url).fragment == target[1:], page.url
            no_overflow(page)

        assert_active()
        page.reload(wait_until="networkidle")
        assert_active()
        alternate = "#tab9" if target == "#tab8" else "#tab8"
        page.evaluate("(hash) => { location.hash = hash; }", alternate)
        expect(page.locator(f'[data-km-dock-tab="{alternate}"]')).to_have_attribute("aria-pressed", "true")
        page.evaluate("(hash) => { location.hash = hash; }", target)
        assert_active()

    def exports(page):
        visit(page, device_path)
        toggle = page.locator("[data-km-export-toggle]")
        panel = page.locator("#km-export-drawer")
        expect(panel).to_be_hidden()
        toggle.click()
        expect(panel).to_be_visible()
        expect(toggle).to_have_attribute("aria-expanded", "true")
        assert panel.locator("a").evaluate_all("(links) => links.map(a => a.getAttribute('href'))") == list(export_paths)
        no_overflow(page)
        toggle.click()
        expect(panel).to_be_hidden()
        expect(toggle).to_have_attribute("aria-expanded", "false")
        toggle.click()
        page.keyboard.press("Escape")
        expect(panel).to_be_hidden()
        expect(toggle).to_be_focused()
        for path in export_paths:
            toggle.click()
            link = panel.locator(f'a[href="{path}"]')
            if link.get_attribute("target") == "_blank":
                with page.expect_popup() as opened:
                    link.click()
                popup = opened.value
                popup.wait_for_load_state()
                assert urlsplit(popup.url).path == path, popup.url
                expect(popup.get_by_text("Smoke export fixture")).to_be_visible()
                popup.close()
                toggle.click()
            else:
                with page.expect_navigation(wait_until="networkidle"):
                    link.click()
                assert urlsplit(page.url).path == path, page.url
                expect(page.get_by_text("Smoke export fixture")).to_be_visible()
                visit(page, device_path)
            assert traffic[f"mocked export {path}"] > 0

    def filters(page):
        visit(page, "/tasks")
        tools = page.locator('select[name="tool"] option').evaluate_all("(options) => options.map(o => o.value)")
        statuses = page.locator('select[name="status"] option').evaluate_all("(options) => options.map(o => o.value)")
        assert len(tools) > 1 and len(statuses) > 1, "Missing task filter choices"
        for status in statuses:
            tool = tools[1] if status else ""
            user = "smoke-no-such-user" if status else ""
            page.get_by_label("Filter by tool").select_option(tool)
            page.get_by_label("Filter by status").select_option(status)
            page.get_by_label("Filter by user").fill(user)
            with page.expect_navigation(wait_until="networkidle") as result:
                page.get_by_role("button", name="Filter", exact=True).click()
            assert result.value and result.value.ok
            query = parse_qs(urlsplit(page.url).query, keep_blank_values=True)
            assert query == {"tool": [tool], "status": [status], "user": [user]}, query
            expect(page.get_by_label("Filter by tool")).to_have_value(tool)
            expect(page.get_by_label("Filter by status")).to_have_value(status)
            expect(page.get_by_label("Filter by user")).to_have_value(user)
            no_overflow(page)

    def scan_error(page, tab, selector, endpoint):
        visit(page, device_path)
        page.locator(f'[data-km-dock-tab="{tab}"]').click()
        if selector == "#manual_nmap_btn":
            page.locator("#manual_nmap_flags").fill("-sV -p 80")
        before = traffic[f"mocked action {endpoint}"]
        with page.expect_response(lambda response: urlsplit(response.url).path == endpoint) as result:
            page.locator(selector).click()
        assert result.value.status == 503
        assert traffic[f"mocked action {endpoint}"] == before + 1
        expect(page.locator(".noty_type_error").last).to_be_visible()
        expect(page.locator(selector)).to_be_enabled()
        expect(page.locator("#km-tool-output")).to_contain_text(f"{endpoint}")
        expect(page.locator("#km-tool-output")).to_contain_text("error 503")

    print("LIVE: loopback page navigation/static assets and GET task filters.")
    print("MOCKED: export destinations and scan-error UI. All other browser requests, including external assets/APIs, are blocked.")
    print("Live page rendering may still perform existing server-side health checks/task reconciliation.")
    print("Not tested: real scans, paid APIs, export contents, search forms/credit modal (separate coverage).", flush=True)
    executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH")
    if not executable and Path("/usr/bin/google-chrome").is_file():
        executable = "/usr/bin/google-chrome"
    previous_tmpdir = os.environ.get("TMPDIR")
    # Keep the local scratch path short enough for Chromium's Unix socket.
    with tempfile.TemporaryDirectory(prefix="kamerka-ui-", dir="/tmp") as scratch:
        os.environ["TMPDIR"] = str(Path(scratch).resolve())
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True, executable_path=executable)
                context = browser.new_context(service_workers="block")
                context.route("**/*", guard)
                for width in (1440, 390):
                    for path in main_paths:
                        check(f"LIVE navigation + overflow {width}px {path}",
                              lambda page, path=path: navigation(page, path, width == 390), width)
                    for path in (case_path, device_path):
                        check(f"LIVE page + overflow {width}px {path}",
                              lambda page, path=path: (visit(page, path), no_overflow(page)), width)
                    for label, target in dock_tabs.items():
                        check(f"LIVE dock/hash {width}px {label}",
                              lambda page, label=label, target=target: dock(page, label, target), width)
                    check(f"MOCKED export links + LIVE drawer {width}px", exports, width)
                    check(f"LIVE task filters {width}px", filters, width)
                check("LIVE mobile drawer keyboard/backdrop/resize", drawer, 390)
                for tab, selector, endpoint in (
                    ("#tab9", "#shodan_scan", f"/{device_id}/shodan/scan"),
                    ("#tab10", "#manual_nmap_btn", f"/manual_nmap/{device_id}"),
                    ("#tab_risk", "#nrich_scan_btn", f"/{device_id}/nrich/scan"),
                ):
                    check(f"MOCKED scan error UI {selector}",
                          lambda page, tab=tab, selector=selector, endpoint=endpoint:
                          scan_error(page, tab, selector, endpoint))
                context.close()
                browser.close()
        finally:
            if previous_tmpdir is None:
                os.environ.pop("TMPDIR", None)
            else:
                os.environ["TMPDIR"] = previous_tmpdir
    print(f"\nSmoke: {passed} passed, {len(failures)} failed.")
    for name, count in sorted(traffic.items()):
        print(f"  {name}: {count}")
    return 1 if failures else 0


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd = sys.argv[1]
    if cmd == "smoke":
        import argparse

        parser = argparse.ArgumentParser(description="Safe local UI smoke checks; all action requests are mocked.")
        parser.add_argument("--base-url", default="http://127.0.0.1:8000")
        parser.add_argument("--device-path", default="/results/1/1/192.0.2.1")
        args = parser.parse_args(sys.argv[2:])
        return run_smoke(args.base_url, args.device_path)
    if cmd == "workbench":
        did = int(sys.argv[2]) if len(sys.argv) > 2 else 499
        return run_workbench(did)
    if cmd == "launch":
        country = sys.argv[2] if len(sys.argv) > 2 else "CN"
        preset = sys.argv[3] if len(sys.argv) > 3 else "s7"
        return run_launch(country, preset)
    print("Unknown command:", cmd)
    return 1


if __name__ == "__main__":
    sys.exit(main())