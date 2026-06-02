#!/usr/bin/env python3
"""
Drive Kamerka through the real web UI (same buttons/flows a user clicks).

Usage:
  fish -l -c './venv/bin/python scripts/gui_e2e_playwright.py workbench 499'
  fish -l -c './venv/bin/python scripts/gui_e2e_playwright.py launch CN s7'

Requires: pip install playwright && playwright install chromium
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


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd = sys.argv[1]
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