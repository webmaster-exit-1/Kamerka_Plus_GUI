"""
Tests for the Plugin / Toolchain System.

Covers:
  - ToolPlugin dataclass and registry (load, get, all_tools, enabled)
  - Dispatcher (tool discovery, TaskRun creation, disabled tool rejection)
  - Playbook model creation and validation
  - Playbook execution via the API view (one end-to-end test)
"""
import json
import os
from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings

# ---------------------------------------------------------------------------
# Helpers shared across tests
# ---------------------------------------------------------------------------

def _make_search():
    from app_kamerka.models import Search
    return Search.objects.create(
        coordinates="",
        country="Test",
        ics="test",
        coordinates_search="",
    )


def _make_device(search):
    from app_kamerka.models import Device
    return Device.objects.create(
        search=search,
        ip="10.0.0.99",
        product="TestProduct",
        org="TestOrg",
        port="80",
        type="test",
        category="test",
        country_code="US",
    )


# ---------------------------------------------------------------------------
# Registry tests
# ---------------------------------------------------------------------------

class ToolRegistryLoadTest(TestCase):
    """Registry must expose all expected tools after module import."""

    def test_registry_is_non_empty(self):
        from app_kamerka.tool_registry import all_tools
        tools = all_tools()
        self.assertGreater(len(tools), 0, "Registry must contain at least one tool")

    def test_core_tools_registered(self):
        from app_kamerka.tool_registry import get_tool
        for name in ("screenshot", "nuclei", "nmap", "wappalyzer", "exploitdb",
                     "whois", "gfw", "honeypot", "sbom"):
            with self.subTest(tool=name):
                plugin = get_tool(name)
                self.assertIsNotNone(plugin, "Tool {!r} must be registered".format(name))

    def test_plugin_has_required_fields(self):
        from app_kamerka.tool_registry import get_tool
        plugin = get_tool("screenshot")
        self.assertTrue(plugin.name)
        self.assertTrue(plugin.label)
        self.assertTrue(plugin.description)
        self.assertTrue(plugin.celery_task_name)
        self.assertIn(plugin.call_mode, ("args", "kwargs_id", "kwargs_device_id"))

    def test_unknown_tool_returns_none(self):
        from app_kamerka.tool_registry import get_tool
        self.assertIsNone(get_tool("does_not_exist_xyz"))

    def test_all_tools_returns_list(self):
        from app_kamerka.tool_registry import all_tools
        tools = all_tools()
        self.assertIsInstance(tools, list)

    def test_enabled_tools_subset_of_all(self):
        from app_kamerka.tool_registry import all_tools, enabled_tools
        all_names = {p.name for p in all_tools()}
        enabled_names = {p.name for p in enabled_tools()}
        self.assertTrue(enabled_names.issubset(all_names))

    def test_bulk_tools_all_bulk_supported(self):
        from app_kamerka.tool_registry import bulk_tools
        for p in bulk_tools():
            self.assertTrue(p.bulk_supported, "{!r} in bulk_tools but bulk_supported=False".format(p.name))

    def test_to_dict_returns_expected_keys(self):
        from app_kamerka.tool_registry import get_tool
        d = get_tool("screenshot").to_dict()
        for key in ("name", "label", "description", "required_binaries",
                    "required_secrets", "bulk_supported", "enabled"):
            self.assertIn(key, d)

    def test_to_dict_is_json_serialisable(self):
        from app_kamerka.tool_registry import all_tools
        for plugin in all_tools():
            with self.subTest(tool=plugin.name):
                try:
                    json.dumps(plugin.to_dict())
                except (TypeError, ValueError) as exc:
                    self.fail("to_dict() for {!r} is not JSON-serialisable: {}".format(plugin.name, exc))

    def test_register_duplicate_name_raises(self):
        from app_kamerka.tool_registry import ToolPlugin, get_tool, register

        original = get_tool("screenshot")

        with self.assertRaises(ValueError):
            register(
                ToolPlugin(
                    name="screenshot",
                    label="Duplicate Screenshot",
                    description="Duplicate entry for test",
                    celery_task_name="kamerka.tasks.capture_screenshot",
                    call_mode="args",
                )
            )
        self.assertIs(get_tool("screenshot"), original)


class ToolPluginEnabledTest(TestCase):
    """Plugin.enabled must respect the KAMERKA_TOOL_<NAME>_ENABLED env var."""

    def test_tool_disabled_by_env(self):
        from app_kamerka.tool_registry import get_tool
        plugin = get_tool("screenshot")
        with patch.dict(os.environ, {"KAMERKA_TOOL_SCREENSHOT_ENABLED": "false"}):
            self.assertFalse(plugin.enabled)

    def test_tool_enabled_by_default(self):
        from app_kamerka.tool_registry import get_tool
        plugin = get_tool("screenshot")
        # Ensure env var is NOT set
        env = {k: v for k, v in os.environ.items() if k != "KAMERKA_TOOL_SCREENSHOT_ENABLED"}
        with patch.dict(os.environ, env, clear=True):
            self.assertTrue(plugin.enabled)

    def test_disabled_tool_excluded_from_enabled_tools(self):
        from app_kamerka.tool_registry import enabled_tools
        with patch.dict(os.environ, {"KAMERKA_TOOL_SCREENSHOT_ENABLED": "false"}):
            names = [p.name for p in enabled_tools()]
            self.assertNotIn("screenshot", names)

    def test_disabled_tool_excluded_from_bulk_tools(self):
        from app_kamerka.tool_registry import bulk_tools
        with patch.dict(os.environ, {"KAMERKA_TOOL_SCREENSHOT_ENABLED": "false"}):
            names = [p.name for p in bulk_tools()]
            self.assertNotIn("screenshot", names)


# ---------------------------------------------------------------------------
# Dispatcher tests
# ---------------------------------------------------------------------------

class DispatcherTest(TestCase):
    """dispatch_tool must create a TaskRun and return (AsyncResult, TaskRun)."""

    def setUp(self):
        self.search = _make_search()
        self.device = _make_device(self.search)

    def test_dispatch_creates_task_run(self):
        from app_kamerka.dispatcher import dispatch_tool
        from app_kamerka.models import TaskRun
        from django.test import RequestFactory
        from django.contrib.auth.models import AnonymousUser

        rf = RequestFactory()
        request = rf.get("/")
        request.user = AnonymousUser()

        with patch("kamerka.tasks.capture_screenshot") as mock_task:
            mock_task.delay.return_value = MagicMock(id="test-task-id-123")
            mock_task.name = "kamerka.tasks.capture_screenshot"
            async_result, task_run = dispatch_tool(request, "screenshot", device_id=self.device.id)

        self.assertIsNotNone(task_run)
        self.assertEqual(task_run.tool, "screenshot")
        self.assertEqual(task_run.device_id, self.device.id)
        db_run = TaskRun.objects.get(pk=task_run.pk)
        self.assertEqual(db_run.tool, "screenshot")

    def test_dispatch_unknown_tool_raises(self):
        from app_kamerka.dispatcher import dispatch_tool, ToolNotFoundError
        from django.test import RequestFactory
        from django.contrib.auth.models import AnonymousUser

        rf = RequestFactory()
        request = rf.get("/")
        request.user = AnonymousUser()

        with self.assertRaises(ToolNotFoundError):
            dispatch_tool(request, "nonexistent_tool_xyz", device_id=self.device.id)

    def test_dispatch_disabled_tool_raises(self):
        from app_kamerka.dispatcher import dispatch_tool, ToolDisabledError
        from django.test import RequestFactory
        from django.contrib.auth.models import AnonymousUser

        rf = RequestFactory()
        request = rf.get("/")
        request.user = AnonymousUser()

        with patch.dict(os.environ, {"KAMERKA_TOOL_SCREENSHOT_ENABLED": "false"}):
            with self.assertRaises(ToolDisabledError):
                dispatch_tool(request, "screenshot", device_id=self.device.id)

    def test_dispatch_requires_device_id(self):
        from app_kamerka.dispatcher import dispatch_tool
        from django.test import RequestFactory
        from django.contrib.auth.models import AnonymousUser

        rf = RequestFactory()
        request = rf.get("/")
        request.user = AnonymousUser()

        with self.assertRaises(ValueError):
            dispatch_tool(request, "screenshot", device_id=None)

    def test_dispatch_rejects_unsupported_call_mode(self):
        from app_kamerka.dispatcher import dispatch_tool
        from app_kamerka.tool_registry import ToolPlugin
        from django.test import RequestFactory
        from django.contrib.auth.models import AnonymousUser

        rf = RequestFactory()
        request = rf.get("/")
        request.user = AnonymousUser()

        bad_plugin = ToolPlugin(
            name="bad-tool",
            label="Bad Tool",
            description="bad call mode",
            celery_task_name="kamerka.tasks.capture_screenshot",
            call_mode="invalid_mode",
        )
        with patch("app_kamerka.dispatcher.get_tool", return_value=bad_plugin):
            with patch("kamerka.tasks.capture_screenshot") as mock_task:
                mock_task.delay.return_value = MagicMock(id="bad-mode-task")
                mock_task.name = "kamerka.tasks.capture_screenshot"
                with self.assertRaises(ValueError):
                    dispatch_tool(request, "bad-tool", device_id=self.device.id)


# ---------------------------------------------------------------------------
# API: Tool Discovery endpoint
# ---------------------------------------------------------------------------

class ToolDiscoveryAPITest(TestCase):
    """GET /api/tools/ must return JSON list of all registered tools."""

    def test_returns_200(self):
        response = self.client.get("/api/tools/")
        self.assertEqual(response.status_code, 200)

    def test_returns_json_list(self):
        response = self.client.get("/api/tools/")
        data = json.loads(response.content)
        self.assertIsInstance(data, list)

    def test_all_tools_present(self):
        from app_kamerka.tool_registry import all_tools
        response = self.client.get("/api/tools/")
        data = json.loads(response.content)
        returned_names = {t["name"] for t in data}
        expected_names = {p.name for p in all_tools()}
        self.assertEqual(returned_names, expected_names)

    def test_tool_dict_has_required_keys(self):
        response = self.client.get("/api/tools/")
        data = json.loads(response.content)
        for tool in data:
            for key in ("name", "label", "description", "bulk_supported", "enabled"):
                self.assertIn(key, tool, "Key {!r} missing from tool {!r}".format(key, tool.get("name")))

    def test_applicable_endpoint_returns_device_tools(self):
        search = _make_search()
        device = _make_device(search)
        response = self.client.get("/api/tools/applicable/{}/".format(device.id))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("device_id", data)
        self.assertIn("tools", data)
        self.assertEqual(data["device_id"], device.id)
        self.assertIsInstance(data["tools"], list)

    def test_applicable_endpoint_404_for_invalid_device(self):
        response = self.client.get("/api/tools/applicable/999999/")
        self.assertEqual(response.status_code, 404)


# ---------------------------------------------------------------------------
# Bulk run — registry-driven
# ---------------------------------------------------------------------------

class BulkRunRegistryTest(TestCase):
    """bulk_run must use the registry to validate tool names."""

    def setUp(self):
        self.search = _make_search()
        self.device = _make_device(self.search)

    def _csrf_client(self):
        from django.test import Client
        c = Client(enforce_csrf_checks=False)
        return c

    def test_invalid_tool_returns_400(self):
        c = self._csrf_client()
        response = c.post(
            "/bulk/run",
            data=json.dumps({"tool": "nonexistent_xyz", "device_ids": [self.device.id]}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn("error", data)

    def test_non_bulk_tool_returns_400(self):
        # 'whois' has bulk_supported=False
        c = self._csrf_client()
        response = c.post(
            "/bulk/run",
            data=json.dumps({"tool": "whois", "device_ids": [self.device.id]}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn("error", data)

    def test_disabled_tool_returns_400(self):
        c = self._csrf_client()
        with patch.dict(os.environ, {"KAMERKA_TOOL_SCREENSHOT_ENABLED": "false"}):
            response = c.post(
                "/bulk/run",
                data=json.dumps({"tool": "screenshot", "device_ids": [self.device.id]}),
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn("error", data)

    def test_valid_bulk_tool_dispatches(self):
        c = self._csrf_client()
        with patch("kamerka.tasks.capture_screenshot") as mock_task:
            mock_task.delay.return_value = MagicMock(id="bulk-task-1")
            mock_task.name = "kamerka.tasks.capture_screenshot"
            response = c.post(
                "/bulk/run",
                data=json.dumps({"tool": "screenshot", "device_ids": [self.device.id]}),
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("runs", data)
        self.assertEqual(len(data["runs"]), 1)


# ---------------------------------------------------------------------------
# Playbook model tests
# ---------------------------------------------------------------------------

class PlaybookModelTest(TestCase):
    """Playbook and PlaybookRun models must save and retrieve correctly."""

    def test_create_playbook(self):
        from app_kamerka.models import Playbook
        pb = Playbook.objects.create(
            name="Test Playbook",
            description="A test playbook",
            steps=[
                {"tool": "screenshot", "order": 1, "exec_type": "chain"},
                {"tool": "nuclei", "order": 2, "exec_type": "chain"},
            ],
        )
        self.assertIsNotNone(pb.pk)
        self.assertEqual(pb.name, "Test Playbook")
        self.assertEqual(len(pb.steps), 2)
        self.assertEqual(pb.steps[0]["tool"], "screenshot")

    def test_playbook_str(self):
        from app_kamerka.models import Playbook
        pb = Playbook.objects.create(name="My Playbook", steps=[])
        self.assertIn("My Playbook", str(pb))

    def test_create_playbook_run(self):
        from app_kamerka.models import Playbook, PlaybookRun
        pb = Playbook.objects.create(name="Run Test PB", steps=[])
        run = PlaybookRun.objects.create(
            playbook=pb,
            device_ids=[1, 2, 3],
            status=PlaybookRun.STATUS_RUNNING,
        )
        self.assertIsNotNone(run.pk)
        self.assertEqual(run.status, "running")
        self.assertEqual(run.device_ids, [1, 2, 3])

    def test_playbook_run_str(self):
        from app_kamerka.models import Playbook, PlaybookRun
        pb = Playbook.objects.create(name="Str Test PB", steps=[])
        run = PlaybookRun.objects.create(playbook=pb, device_ids=[], status="pending")
        self.assertIn("Str Test PB", str(run))
        self.assertIn("pending", str(run))


# ---------------------------------------------------------------------------
# Playbook API tests
# ---------------------------------------------------------------------------

class PlaybookCreateAPITest(TestCase):
    """POST /api/playbooks/create/ must create a Playbook record."""

    def setUp(self):
        from django.contrib.auth.models import User
        self.user = User.objects.create_user("pbtest", password="pbtest")
        self.client.login(username="pbtest", password="pbtest")

    def _post(self, data):
        return self.client.post(
            "/api/playbooks/create/",
            data=json.dumps(data),
            content_type="application/json",
        )

    def test_create_valid_playbook(self):
        response = self._post({
            "name": "API Test Playbook",
            "description": "Test",
            "steps": [
                {"tool": "screenshot", "order": 1, "exec_type": "chain"},
            ],
        })
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.content)
        self.assertIn("id", data)
        self.assertEqual(data["name"], "API Test Playbook")

    def test_missing_name_returns_400(self):
        response = self._post({"steps": [{"tool": "screenshot", "order": 1}]})
        self.assertEqual(response.status_code, 400)

    def test_unknown_tool_in_steps_returns_400(self):
        response = self._post({
            "name": "Bad Steps PB",
            "steps": [{"tool": "unknown_xyz", "order": 1}],
        })
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn("error", data)

    def test_non_object_step_returns_400(self):
        response = self._post({
            "name": "Malformed Steps PB",
            "steps": ["not-a-dict"],
        })
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertEqual(data["error"], "Each step must be an object")

    def test_step_missing_tool_returns_400(self):
        response = self._post({
            "name": "Missing Tool Field PB",
            "steps": [{"order": 1, "exec_type": "chain"}],
        })
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertIn("Unknown tool in steps", data["error"])

    def test_duplicate_name_returns_400(self):
        from app_kamerka.models import Playbook
        Playbook.objects.create(name="Duplicate PB", steps=[])
        response = self._post({"name": "Duplicate PB", "steps": []})
        self.assertEqual(response.status_code, 400)


class PlaybookRunAPITest(TestCase):
    """POST /api/playbooks/<pk>/run/ must dispatch tasks and create a PlaybookRun."""

    def setUp(self):
        from django.contrib.auth.models import User
        from app_kamerka.models import Playbook
        self.user = User.objects.create_user("pbruntest", password="pbruntest")
        self.client.login(username="pbruntest", password="pbruntest")
        self.search = _make_search()
        self.device = _make_device(self.search)
        self.playbook = Playbook.objects.create(
            name="Run Test Playbook",
            steps=[
                {"tool": "screenshot", "order": 1, "exec_type": "chain"},
            ],
        )

    def test_run_dispatches_tasks_and_returns_run_id(self):
        from app_kamerka.models import PlaybookRun
        with patch("kamerka.tasks.capture_screenshot") as mock_task:
            mock_task.delay.return_value = MagicMock(id="pb-run-task-1")
            mock_task.name = "kamerka.tasks.capture_screenshot"
            response = self.client.post(
                "/api/playbooks/{}/run/".format(self.playbook.pk),
                data=json.dumps({"device_ids": [self.device.id]}),
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("playbook_run_id", data)
        self.assertIn("runs", data)
        self.assertEqual(len(data["runs"]), 1)
        self.assertEqual(data["runs"][0]["tool"], "screenshot")
        self.assertEqual(data["runs"][0]["device_id"], self.device.id)
        # Verify PlaybookRun was persisted
        pb_run = PlaybookRun.objects.get(pk=data["playbook_run_id"])
        self.assertEqual(pb_run.playbook_id, self.playbook.pk)
        self.assertEqual(len(pb_run.task_runs), 1)

    def test_run_no_devices_returns_400(self):
        response = self.client.post(
            "/api/playbooks/{}/run/".format(self.playbook.pk),
            data=json.dumps({"device_ids": []}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_run_nonexistent_playbook_returns_404(self):
        response = self.client.post(
            "/api/playbooks/999999/run/",
            data=json.dumps({"device_ids": [self.device.id]}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 404)

    def test_playbook_with_multiple_devices_and_steps(self):
        """Playbook execution over multiple devices dispatches one task per device per step."""
        from app_kamerka.models import Playbook, PlaybookRun
        search2 = _make_search()
        device2 = _make_device(search2)
        playbook2 = Playbook.objects.create(
            name="Multi-device Multi-step PB",
            steps=[
                {"tool": "screenshot", "order": 1, "exec_type": "chain"},
                {"tool": "port_scan",  "order": 2, "exec_type": "chain"},
            ],
        )
        with patch("kamerka.tasks.capture_screenshot") as m_ss, \
             patch("kamerka.tasks.port_scan_task") as m_ps:
            m_ss.delay.side_effect = [MagicMock(id="ss1"), MagicMock(id="ss2")]
            m_ss.name = "kamerka.tasks.capture_screenshot"
            m_ps.delay.side_effect = [MagicMock(id="ps1"), MagicMock(id="ps2")]
            m_ps.name = "kamerka.tasks.port_scan_task"
            response = self.client.post(
                "/api/playbooks/{}/run/".format(playbook2.pk),
                data=json.dumps({"device_ids": [self.device.id, device2.id]}),
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        # 2 devices × 2 steps = 4 task dispatches
        self.assertEqual(len(data["runs"]), 4)
        pb_run = PlaybookRun.objects.get(pk=data["playbook_run_id"])
        self.assertEqual(len(pb_run.task_runs), 4)

    def test_run_rejects_malformed_steps(self):
        from app_kamerka.models import Playbook

        bad_steps_playbook = Playbook.objects.create(
            name="Bad Steps Run",
            steps=["not-a-dict"],
        )
        response = self.client.post(
            "/api/playbooks/{}/run/".format(bad_steps_playbook.pk),
            data=json.dumps({"device_ids": [self.device.id]}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertEqual(data["runs"], [])
        self.assertIn("Skipped invalid step at position 1: expected dict, got str", data["errors"])
