"""Regression coverage for the shared application shell."""

from html.parser import HTMLParser
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from unittest import skipUnless

from django.contrib.messages.storage.fallback import FallbackStorage
from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase

from app_kamerka.context_processors import kamerka_shell
from app_kamerka.models import Device


class WsgiStartupTests(SimpleTestCase):
    def test_wsgi_initializes_django_in_a_fresh_process(self):
        env = os.environ.copy()
        env.pop("DJANGO_SETTINGS_MODULE", None)
        result = subprocess.run(
            [sys.executable, "-c",
             "from kamerka.wsgi import application; assert callable(application)"],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


@skipUnless(shutil.which("bash"), "Bash is required for launcher tests")
class ScriptLauncherTests(SimpleTestCase):
    def setUp(self):
        self.bash = shutil.which("bash")
        self.temp = tempfile.TemporaryDirectory(prefix="kamerka scripts ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        source = Path(__file__).resolve().parents[1] / "scripts"
        for name in ("kamerka.sh", "start_stack.sh", "tmux_kamerka_stack.sh", "start_hexstrike.sh", "setup_postgres.sh"):
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
            'case " $* " in *" migrate "*) exit "$MIGRATE_EXIT";; esac\n'
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
            [self.bash, "--noprofile", "--norc", str(self.scripts / name), *args],
            cwd=self.root.parent,
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
                result = self.run_script("kamerka.sh", *args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.commands()[0], "manage.py migrate --noinput")
                self.assertTrue(self.commands()[1].startswith("manage.py runserver "))

    def test_runserver_migration_uses_django_settings_options(self):
        option_cases = (
            (("--settings=custom_settings", "--pythonpath=/custom/path"),
             "manage.py --settings=custom_settings --pythonpath=/custom/path migrate --noinput"),
            (("--settings", "custom_settings", "--pythonpath", "/custom/path"),
             "manage.py --settings custom_settings --pythonpath /custom/path migrate --noinput"),
        )
        for options, expected_migration in option_cases:
            with self.subTest(options=options):
                self.log.unlink(missing_ok=True)
                result = self.run_script("kamerka.sh", "manage", "runserver", *options)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.commands()[0], expected_migration)
                self.assertTrue(self.commands()[1].startswith("manage.py runserver "))

    def test_migration_failure_prevents_runserver(self):
        self.env["MIGRATE_EXIT"] = "1"
        result = self.run_script("kamerka.sh", "runserver")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.commands(), ["manage.py migrate --noinput"])
        self.assertIn("Database setup failed", result.stderr)

    def test_worker_and_beat_require_migrations(self):
        for args in (("worker",), ("celery", "worker"), ("celery", "beat")):
            for migration_exit in ("0", "1"):
                with self.subTest(args=args, migration_exit=migration_exit):
                    self.log.unlink(missing_ok=True)
                    self.env["MIGRATE_EXIT"] = migration_exit
                    result = self.run_script("kamerka.sh", *args)
                    self.assertEqual(self.commands()[0], "manage.py migrate --check")
                    self.assertEqual(result.returncode, int(migration_exit))
                    self.assertEqual(len(self.commands()), 2 if migration_exit == "0" else 1)

    def test_manage_migrate_does_not_recurse(self):
        result = self.run_script("kamerka.sh", "manage", "migrate", "--noinput")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.commands(), ["manage.py migrate --noinput"])

    def test_manage_migrate_propagates_failure(self):
        self.env["MIGRATE_EXIT"] = "3"
        result = self.run_script("kamerka.sh", "manage", "migrate", "--noinput")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(self.commands(), ["manage.py migrate --noinput"])

    def test_missing_environment_reports_install_command(self):
        (self.root / ".venv/bin/python").unlink()
        result = self.run_script("kamerka.sh", "runserver")
        self.assertEqual(result.returncode, 1)
        self.assertIn("install_kamerka.py", result.stderr)
        self.assertEqual(self.commands(), [])

    def test_venv_fallback_and_service_exit_status(self):
        (self.root / ".venv/bin/python").unlink()
        self.write_executable("venv/bin/python", self.python_stub)
        self.env["SERVICE_EXIT"] = "7"
        result = self.run_script("kamerka.sh", "runserver")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(len(self.commands()), 2)

    def test_stack_migration_failure_does_not_interrupt_or_launch_services(self):
        self.write_executable(
            "bin/bash",
            '#!/bin/sh\nprintf "bash %s\\n" "$*" >> "$COMMAND_LOG"\nexit 1\n',
        )
        for command in ("pkill", "tmux", "nohup"):
            self.write_executable(
                f"bin/{command}",
                '#!/bin/sh\nprintf "%s %s\\n" "${0##*/}" "$*" >> "$COMMAND_LOG"\nexit 1\n',
            )
        self.env["PATH"] = str(self.root / "bin") + os.pathsep + os.environ["PATH"]
        for name in ("start_stack.sh", "tmux_kamerka_stack.sh"):
            with self.subTest(script=name):
                self.log.unlink(missing_ok=True)
                result = self.run_script(name)
                self.assertEqual(result.returncode, 1, result.stderr)
                calls = self.commands()
                self.assertTrue(calls[-1].endswith("kamerka.sh manage migrate --noinput"))
                self.assertFalse(any(c.startswith(("pkill ", "nohup ", "tmux new-session")) for c in calls))
                self.assertIn("Database setup failed", result.stderr)

    def test_hexstrike_preserves_arguments_and_exit_status(self):
        self.write_executable(
            "hexstrike-ai/venv/bin/python3",
            '#!/bin/sh\nprintf "%s\\n" "$@" > "$COMMAND_LOG"\nexit 7\n',
        )
        result = self.run_script("start_hexstrike.sh", "--port", "8888")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(self.commands(), [
            str(self.root / "hexstrike-ai/hexstrike_server.py"), "--port", "8888",
        ])

    @skipUnless(shutil.which("tmux"), "tmux is required for pane integration tests")
    def test_tmux_starts_commands_with_one_based_panes_and_can_restart(self):
        tmux = shutil.which("tmux")
        socket = str(self.root / "tmux.socket")
        config = self.root / "tmux.conf"
        config.write_text("set -g base-index 1\nsetw -g pane-base-index 1\n")
        self.write_executable(
            "bin/tmux",
            f'#!/bin/sh\nexec "{tmux}" -S "{socket}" -f "{config}" "$@"\n',
        )
        self.env["PATH"] = str(self.root / "bin") + os.pathsep + os.environ["PATH"]
        self.env.pop("TMUX", None)
        self.addCleanup(subprocess.run, [tmux, "-S", socket, "kill-server"], capture_output=True)
        subprocess.run([tmux, "-S", socket, "set-environment", "-g", "DB_NAME", "stale-db"], check=True)
        subprocess.run([tmux, "-S", socket, "set-environment", "-g", "DB_USER", "stale-user"], check=True)
        subprocess.run([tmux, "-S", socket, "set-environment", "-g", "DB_PASSWORD", "stale-password"], check=True)
        subprocess.run([tmux, "-S", socket, "set-environment", "-g", "DB_CONNECT_TIMEOUT", "stale-timeout"], check=True)
        self.env.update(DB_NAME="caller-db", DB_USER="caller-user", DB_HOST="caller-host", DB_PORT="5444")
        self.env.pop("DB_PASSWORD", None)
        subprocess.run([
            tmux, "-S", socket, "new-session", "-d", "-s", "kamerka-dev", "-c", str(self.root),
        ], check=True)
        self.env["SERVICE_EXIT"] = "7"
        for args in ((), ("--restart",)):
            with self.subTest(args=args):
                result = self.run_script("tmux_kamerka_stack.sh", *args)
                self.assertEqual(result.returncode, 0, result.stderr)
                panes = subprocess.run(
                    [tmux, "-S", socket, "list-panes", "-t", "kamerka:stack",
                     "-F", "#{pane_title}"],
                    capture_output=True, text=True, check=True,
                ).stdout.splitlines()
                self.assertCountEqual(panes, [
                    "runserver", "celery-worker", "celery-beat", "worker-status",
                ])
                session_env = subprocess.run(
                    [tmux, "-S", socket, "show-environment", "-t", "=kamerka"],
                    capture_output=True, text=True, check=True,
                ).stdout
                self.assertIn("DB_NAME=caller-db", session_env)
                self.assertIn("DB_USER=caller-user", session_env)
                self.assertIn("DB_HOST=caller-host", session_env)
                self.assertIn("DB_PORT=5444", session_env)
                self.assertNotIn("stale-password", session_env)
                self.assertNotIn("stale-timeout", session_env)
        result = self.run_script("tmux_kamerka_stack.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already exists", result.stdout)
        self.env["MIGRATE_EXIT"] = "1"
        result = self.run_script("tmux_kamerka_stack.sh", "--restart")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(subprocess.run(
            [tmux, "-S", socket, "has-session", "-t", "=kamerka"],
            capture_output=True,
        ).returncode, 0)
        self.assertEqual(subprocess.run(
            [tmux, "-S", socket, "has-session", "-t", "=kamerka-dev"],
            capture_output=True,
        ).returncode, 0)

    def test_postgres_setup_creates_only_missing_role_and_database(self):
        self.write_executable(
            "bin/psql",
            '#!/bin/sh\n'
            'case "$*" in *"SELECT 1"*) exit 0;; esac\n'
            'query="$(cat)"\n'
            'case "$query" in\n'
            '  *pg_roles*) printf "%s" "$TEST_ROLE_EXISTS";;\n'
            '  *pg_database*) printf "%s" "$TEST_DB_EXISTS";;\n'
            'esac\n',
        )
        for command in ("createuser", "createdb"):
            self.write_executable(
                f"bin/{command}",
                '#!/bin/sh\nprintf "%s %s\\n" "${0##*/}" "$*" >> "$COMMAND_LOG"\n',
            )
        self.env["PATH"] = str(self.root / "bin") + os.pathsep + os.environ["PATH"]
        self.env.update(DB_USER="kamerka", DB_NAME="kamerka")
        for exists in ("", "1"):
            with self.subTest(exists=exists):
                self.log.unlink(missing_ok=True)
                self.env.update(TEST_ROLE_EXISTS=exists, TEST_DB_EXISTS=exists)
                result = self.run_script("setup_postgres.sh")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.commands(), [] if exists else [
                    "createuser --createdb --login --pwprompt -- kamerka",
                    "createdb --owner=kamerka -- kamerka",
                ])


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
