"""Regression coverage for the shared application shell."""

from html.parser import HTMLParser
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest import skipUnless

from django.contrib.messages.storage.fallback import FallbackStorage
from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase

from app_kamerka.context_processors import kamerka_shell
from app_kamerka.models import Device


@skipUnless(shutil.which("fish"), "Fish is required for launcher tests")
class ScriptLauncherTests(SimpleTestCase):
    def setUp(self):
        self.fish = shutil.which("fish")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        source = Path(__file__).resolve().parents[1] / "scripts"
        for name in ("kamerka.fish", "start_stack.fish", "tmux_kamerka_stack.fish"):
            shutil.copy(source / name, self.scripts / name)
        self.log = self.root / "commands.log"
        self.env = {
            **os.environ,
            "HOME": str(self.root),
            "COMMAND_LOG": str(self.log),
            "MIGRATE_EXIT": "0",
            "SERVICE_EXIT": "0",
        }
        self.python_stub = (
            '#!/bin/sh\n'
            'printf "%s\\n" "$*" >> "$COMMAND_LOG"\n'
            'if [ "$2" = migrate ]; then exit "$MIGRATE_EXIT"; fi\n'
            'exit "$SERVICE_EXIT"\n'
        )
        self.write_executable(".venv/bin/python", self.python_stub)

    def write_executable(self, name, content):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        target.chmod(0o755)

    def run_script(self, name, *args):
        return subprocess.run(
            [self.fish, "--no-config", str(self.scripts / name), *args],
            cwd="/tmp",
            env=self.env,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def commands(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_runserver_migrates_before_starting(self):
        for args in (("runserver",), ("manage", "runserver", "127.0.0.1:9000")):
            with self.subTest(args=args):
                self.log.unlink(missing_ok=True)
                result = self.run_script("kamerka.fish", *args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.commands()[0], "manage.py migrate --noinput")
                self.assertTrue(self.commands()[1].startswith("manage.py runserver "))

    def test_migration_failure_prevents_runserver(self):
        self.env["MIGRATE_EXIT"] = "1"
        result = self.run_script("kamerka.fish", "runserver")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.commands(), ["manage.py migrate --noinput"])
        self.assertIn("Database setup failed", result.stderr)

    def test_worker_and_beat_require_migrations(self):
        for args in (("worker",), ("celery", "worker"), ("celery", "beat")):
            for migration_exit in ("0", "1"):
                with self.subTest(args=args, migration_exit=migration_exit):
                    self.log.unlink(missing_ok=True)
                    self.env["MIGRATE_EXIT"] = migration_exit
                    result = self.run_script("kamerka.fish", *args)
                    self.assertEqual(self.commands()[0], "manage.py migrate --check")
                    self.assertEqual(result.returncode, int(migration_exit))
                    self.assertEqual(len(self.commands()), 2 if migration_exit == "0" else 1)

    def test_manage_migrate_does_not_recurse(self):
        result = self.run_script("kamerka.fish", "manage", "migrate", "--noinput")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.commands(), ["manage.py migrate --noinput"])

    def test_venv_fallback_and_service_exit_status(self):
        (self.root / ".venv/bin/python").unlink()
        self.write_executable("venv/bin/python", self.python_stub)
        self.env["SERVICE_EXIT"] = "7"
        result = self.run_script("kamerka.fish", "runserver")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(len(self.commands()), 2)

    def test_stack_migration_failure_does_not_interrupt_or_launch_services(self):
        self.write_executable(
            "bin/fish",
            '#!/bin/sh\nprintf "fish %s\\n" "$*" >> "$COMMAND_LOG"\nexit 1\n',
        )
        for command in ("pkill", "tmux", "nohup"):
            self.write_executable(
                f"bin/{command}",
                '#!/bin/sh\nprintf "%s %s\\n" "${0##*/}" "$*" >> "$COMMAND_LOG"\nexit 1\n',
            )
        self.env["PATH"] = str(self.root / "bin") + os.pathsep + os.environ["PATH"]
        for name in ("start_stack.fish", "tmux_kamerka_stack.fish"):
            with self.subTest(script=name):
                self.log.unlink(missing_ok=True)
                result = self.run_script(name)
                self.assertEqual(result.returncode, 1, result.stderr)
                calls = self.commands()
                self.assertTrue(calls[-1].endswith("kamerka.fish manage migrate --noinput"))
                self.assertFalse(any(c.startswith(("pkill ", "nohup ", "tmux new-session")) for c in calls))
                self.assertIn("Database setup failed", result.stderr)


class ShellElements(HTMLParser):
    def __init__(self, markup):
        super().__init__()
        self.elements = []
        self.containers = []
        self.unmatched_containers = []
        self.tab_parents = {}
        self.feed(markup)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.elements.append((tag, attrs))
        if "tab-pane" in attrs.get("class", "").split():
            self.tab_parents[attrs.get("id")] = self.containers[-1][1]
        if tag in ("div", "main"):
            self.containers.append((tag, attrs))

    def handle_endtag(self, tag):
        if tag not in ("div", "main"):
            return
        if not self.containers or self.containers[-1][0] != tag:
            self.unmatched_containers.append(tag)
        else:
            self.containers.pop()


class ApplicationShellTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def request(self, path="/", case=None):
        request = self.factory.get(path)
        request.session = {}
        if case is not None:
            request.session["km_active_case_id"] = case
        return request

    def render_shell(self, request, context=None):
        return render_to_string("base.html", context or {}, request=request)

    def test_routes_have_consistent_titles_and_active_navigation(self):
        routes = {
            "/": "launch",
            "/index": "overview",
            "/history": "cases",
            "/results/7": "case",
            "/results/7/9/192.0.2.1": "target",
            "/devices": "devices",
            "/map": "map",
            "/map3d": "map3d",
            "/globe": "map3d",
            "/camera-wall": "camera",
            "/gallery": "gallery",
            "/feeds-briefing": "briefing",
            "/tasks/7": "tasks",
            "/playbooks/": "playbooks",
            "/watchlists": "watchlists",
            "/hexsploit/": "hexsploit",
            "/healthz/setup/": "setup",
            "/sources": "sources",
        }
        for path, active in routes.items():
            with self.subTest(path=path):
                context = kamerka_shell(self.request(path))
                self.assertEqual(context["nav_active"], active)
                self.assertNotEqual(context["nav_title"], "Investigation")

    def test_single_navigation_and_accessible_workspace(self):
        markup = self.render_shell(self.request("/history"))
        elements = ShellElements(markup).elements
        ids = [attrs["id"] for _, attrs in elements if "id" in attrs]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids.count("km-navigation"), 1)
        self.assertIn(("main", {"id": "main-content", "class": "km-workspace", "tabindex": "-1"}), elements)
        active_links = [attrs["href"] for tag, attrs in elements if tag == "a" and attrs.get("aria-current") == "page"]
        self.assertEqual(active_links, ["/history"])
        self.assertNotIn("kamerka-hamburger", markup)
        self.assertNotIn("hamburger-nav.css", markup)
        self.assertIn('href="#main-content"', markup)

    def test_active_case_is_preserved_in_map_navigation(self):
        context = kamerka_shell(self.request("/map3d", case=42))
        links = [item for group in context["navigation"] for item in group["items"]]
        self.assertEqual(next(item["url"] for item in links if item["key"] == "map3d"), "/map3d?search=42")
        markup = self.render_shell(self.request("/results/42", case=42))
        self.assertIn('href="/results/42" aria-current="page"', markup)

    def test_target_link_only_appears_when_available(self):
        request = self.request("/results/7/9/192.0.2.1", case=7)
        self.assertNotIn("Current target", self.render_shell(request))
        request.km_active_target_url = "/results/7/9/192.0.2.1"
        self.assertIn('href="/results/7/9/192.0.2.1" aria-current="page"', self.render_shell(request))

    def test_shell_assets_load_once_in_order(self):
        markup = self.render_shell(self.request())
        for asset in ("jquery.min.js", "bootstrap.min.js", "kamerka-shell.js", "cyberpunk.css"):
            self.assertEqual(markup.count(asset), 1)
        self.assertLess(markup.index("theme-default.css"), markup.index("cyberpunk.css"))
        self.assertLess(markup.index("cyberpunk.css"), markup.index("kamerka-shell.css"))

    def test_notification_content_is_escaped(self):
        request = self.request()
        request._messages = FallbackStorage(request)
        request._messages.add(20, "<script>alert('test')</script>")
        markup = self.render_shell(request)
        self.assertIn("&lt;script&gt;", markup)
        self.assertNotIn("<script>alert", markup)

    def test_export_controls_reference_hidden_region(self):
        markup = render_to_string("includes/case_toolbar.html", {"search_id": 7})
        self.assertIn('aria-controls="km-export-drawer"', markup)
        self.assertIn('role="region" aria-label="Case exports" hidden', markup)
        for export in ("csv", "kml", "json"):
            self.assertIn(f'href="/export/{export}/7"', markup)

    def test_unknown_routes_can_render_error_shell(self):
        request = self.request("/not-a-page")
        self.assertEqual(kamerka_shell(request)["nav_title"], "Investigation")
        self.assertIn("Skip to workspace", self.render_shell(request))

    def test_device_tabs_remain_inside_the_workbench(self):
        device = Device(id=1, search_id=1, ip="192.0.2.1", lat=0, lon=0, type="Test device")
        markup = render_to_string("device.html", {
            "device": device, "device_id": 1, "search_id": 1,
            "device_ip": device.ip, "safe_lat": 0, "safe_lon": 0,
        }, request=self.request("/results/1/1/192.0.2.1", case=1))
        parsed = ShellElements(markup)
        self.assertFalse(parsed.unmatched_containers)
        self.assertFalse(parsed.containers)
        self.assertEqual(set(parsed.tab_parents), {
            "tab8", "tab9", "tab10", "tab11", "tab_hw", "tab_risk", "tab_supply",
        })
        for parent in parsed.tab_parents.values():
            self.assertIn("km-device-tab-content", parent["class"])

    def test_globe_does_not_close_the_application_shell(self):
        markup = render_to_string("globe.html", {}, request=self.request("/globe"))
        parsed = ShellElements(markup)
        self.assertFalse(parsed.unmatched_containers)
        self.assertFalse(parsed.containers)
