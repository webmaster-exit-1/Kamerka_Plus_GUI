"""Deployment endpoint regression tests; no real backend requests."""

import os
from pathlib import Path
import runpy
import shutil
import tempfile
from unittest.mock import patch

from django.conf import settings
from django.test import RequestFactory, SimpleTestCase, override_settings

from app_kamerka.hexstrike_client import HexStrikeClient, server_url
from app_kamerka.hexstrike_views import hexsploit_view
from app_kamerka.ollama_payload_generator import ollama_url, query_ollama


class DeploymentSettingsTests(SimpleTestCase):
    def load_settings(self, env):
        with patch.dict(os.environ, env, clear=True), patch("dotenv.load_dotenv"):
            return runpy.run_path(str(Path(settings.BASE_DIR) / "kamerka/settings.py"))

    def test_native_defaults_and_blank_values_use_loopback(self):
        for env in ({}, {"HEXSTRIKE_SERVER_URL": " ", "HEXSPLOIT_OLLAMA_SERVER_URL": ""}):
            with self.subTest(env=env):
                config = self.load_settings(env)
                self.assertEqual(config["HEXSTRIKE_SERVER_URL"], "http://127.0.0.1:8888")
                self.assertEqual(config["HEXSPLOIT_OLLAMA_SERVER_URL"], "http://127.0.0.1:11434")

    def test_environment_endpoints_are_normalized(self):
        config = self.load_settings({
            "HEXSTRIKE_SERVER_URL": " https://hexstrike.example/prefix/ ",
            "HEXSPLOIT_OLLAMA_SERVER_URL": " https://ollama.example/llm/ ",
        })
        self.assertEqual(config["HEXSTRIKE_SERVER_URL"], "https://hexstrike.example/prefix")
        self.assertEqual(config["HEXSPLOIT_OLLAMA_SERVER_URL"], "https://ollama.example/llm")

    def test_project_dotenv_loads_independent_of_working_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "kamerka").mkdir()
            target = root / "kamerka/settings.py"
            shutil.copy(Path(settings.BASE_DIR) / "kamerka/settings.py", target)
            (root / ".env").write_text(
                "HEXSTRIKE_SERVER_URL=https://dotenv.example/tools/\n"
                "HEXSPLOIT_OLLAMA_SERVER_URL=https://dotenv.example/ollama/\n"
            )
            with patch.dict(os.environ, {
                "HEXSPLOIT_OLLAMA_SERVER_URL": "https://exported.example/",
            }, clear=True):
                config = runpy.run_path(str(target))
            self.assertEqual(config["HEXSTRIKE_SERVER_URL"], "https://dotenv.example/tools")
            self.assertEqual(config["HEXSPLOIT_OLLAMA_SERVER_URL"], "https://exported.example")

    def test_compose_does_not_override_dotenv_endpoints_or_model(self):
        import yaml

        compose = yaml.safe_load((Path(settings.BASE_DIR) / "docker-compose.yml").read_text())
        for service in ("web", "celery", "celery-beat"):
            config = compose["services"][service]
            self.assertIn(".env", config["env_file"])
            for key in ("HEXSTRIKE_SERVER_URL", "HEXSPLOIT_OLLAMA_SERVER_URL", "HEXSPLOIT_OLLAMA_MODEL"):
                self.assertNotIn(key, config["environment"])


class HexSploitEndpointTests(SimpleTestCase):
    @override_settings(HEXSTRIKE_SERVER_URL="", HEXSPLOIT_OLLAMA_SERVER_URL="")
    def test_client_fallbacks_are_loopback(self):
        self.assertEqual(server_url(), "http://127.0.0.1:8888")
        self.assertEqual(ollama_url(), "http://127.0.0.1:11434")

    @override_settings(HEXSTRIKE_SERVER_URL="https://tools.example/prefix/")
    @patch("app_kamerka.hexstrike_views.render")
    @patch("app_kamerka.hexstrike_client.requests.Session")
    def test_health_actions_and_display_share_configured_endpoint(self, session, render):
        session.return_value.get.return_value.json.return_value = {"status": "healthy"}
        request = RequestFactory().get(
            "/hexsploit/?server_url=http://untrusted.example",
            HTTP_HOST="untrusted.example",
        )
        hexsploit_view(request)
        self.assertEqual(render.call_args.args[2]["hexstrike_url"], "https://tools.example/prefix")
        self.assertTrue(render.call_args.args[2]["hexstrike_online"])
        session.return_value.get.assert_called_once_with(
            "https://tools.example/prefix/health", params={}, timeout=30,
        )
        HexStrikeClient().run_action("analyze_target", {"target": "example.com"})
        session.return_value.post.assert_called_once_with(
            "https://tools.example/prefix/api/intelligence/analyze-target",
            json={"target": "example.com"}, timeout=settings.HEXSTRIKE_TIMEOUT,
        )

    @override_settings(
        HEXSPLOIT_OLLAMA_SERVER_URL="https://llm.example/prefix/",
        HEXSPLOIT_OLLAMA_MODEL="deployment-model",
    )
    @patch("app_kamerka.ollama_payload_generator.requests.post")
    def test_ollama_honors_endpoint_and_model(self, post):
        post.return_value.json.return_value = {"response": " recommendation "}
        self.assertEqual(query_ollama("test prompt"), "recommendation")
        post.assert_called_once_with(
            "https://llm.example/prefix/api/generate",
            json={"model": "deployment-model", "prompt": "test prompt", "stream": False},
            timeout=30,
        )
