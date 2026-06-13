from unittest.mock import patch

import requests
from django.test import Client, RequestFactory, SimpleTestCase, TestCase

from app_kamerka.test_compat import apply_py314_django_test_patches

apply_py314_django_test_patches()

from app_kamerka.hexstrike_views import hexsploit_view

from app_kamerka.hexstrike_client import (
    ALLOWED_ACTIONS,
    HexStrikeClient,
    validate_target,
)
from app_kamerka.models import Device, Search


class HexStrikeClientTest(SimpleTestCase):
    def test_validate_target_accepts_ipv4(self):
        self.assertEqual(validate_target("192.168.1.10"), "192.168.1.10")

    def test_validate_target_rejects_injection(self):
        self.assertIsNone(validate_target("1.2.3.4; rm -rf /"))

    def test_unknown_action_rejected(self):
        result = HexStrikeClient().run_action("run_shell", {"command": "id"})
        self.assertIn("Unknown action", result["error"])

    @patch("app_kamerka.hexstrike_client.requests.Session")
    def test_health_offline(self, session_cls):
        session = session_cls.return_value
        session.get.side_effect = requests.exceptions.ConnectionError("refused")
        result = HexStrikeClient().health()
        self.assertTrue(result.get("offline"))


class HexSploitViewsTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.factory = RequestFactory()
        self.search = Search.objects.create(
            coordinates="0,0",
            country="US",
            ics="[]",
            coordinates_search="[]",
        )
        self.device = Device.objects.create(
            search=self.search,
            ip="10.0.0.50",
            product="Modbus PLC",
            port="502",
            type="modbus",
            lat="40.0",
            lon="-74.0",
            country_code="US",
        )

    def test_hexsploit_page_renders(self):
        request = self.factory.get(
            "/hexsploit/", {"device_id": str(self.device.id)}
        )
        response = hexsploit_view(request)
        self.assertEqual(response.status_code, 200)
        body = response.content.decode("utf-8", errors="replace")
        self.assertIn("HexSploit", body)
        self.assertIn("10.0.0.50", body)

    def test_action_api_requires_ajax(self):
        response = self.client.post(
            "/api/hexstrike/action/",
            data='{"action":"health"}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    @patch.object(HexStrikeClient, "run_action")
    def test_action_api_whitelist(self, run_action):
        run_action.return_value = {"status": "healthy"}
        response = self.client.post(
            "/api/hexstrike/action/",
            data='{"action":"health","payload":{}}',
            content_type="application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 200)
        run_action.assert_called_once_with("health", {})

    def test_allowed_actions_cover_c2_surface(self):
        expected = {
            "health",
            "analyze_target",
            "smart_scan",
            "select_tools",
            "attack_chain",
            "execute_chain",
            "process_dashboard",
            "nuclei",
            "metasploit",
            "autorecon",
            "rustscan",
            "nmap_advanced",
            "enum4linux_ng",
            "responder",
        }
        self.assertEqual(set(ALLOWED_ACTIONS.keys()), expected)