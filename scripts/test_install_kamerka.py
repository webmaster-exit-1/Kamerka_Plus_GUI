"""Unit tests for scripts/install_kamerka.py helpers (no full install run)."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "install_kamerka",
    ROOT / "scripts" / "install_kamerka.py",
)
install = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(install)


class InstallKamerkaHelpersTest(unittest.TestCase):
    def test_password_strength_rejects_weak(self):
        issues = install.password_strength_issues("admin")
        self.assertTrue(any("12" in i for i in issues))

    def test_password_strength_accepts_generated(self):
        pwd = install.generate_password(20)
        self.assertEqual(len(pwd), 20)
        self.assertEqual(install.password_strength_issues(pwd), [])

    def test_env_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("# comment\nLEGACY=keep\nSHODAN_API_KEY=old\n", encoding="utf-8")
            install.write_env_file(path, {"SHODAN_API_KEY": "new-key", "DEBUG": "False"})
            text = path.read_text(encoding="utf-8")
            self.assertIn("SHODAN_API_KEY=new-key", text)
            self.assertIn("DEBUG=False", text)
            self.assertIn("LEGACY=keep", text)
            self.assertIn("# comment", text)
            data = install.read_env_file(path)
            self.assertEqual(data["SHODAN_API_KEY"], "new-key")


if __name__ == "__main__":
    unittest.main()