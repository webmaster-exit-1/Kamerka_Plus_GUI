"""Tests for gui/main_window.py and gui/launch.py.

PyQt6 is not installed in this environment (it lives in requirements-3d.txt).
These tests verify:
  - Both files are valid Python (py_compile).
  - Module-level availability flags are set correctly when PyQt6 is absent.
  - MainWindow.__init__ raises RuntimeError immediately when PyQt6 is absent.
  - DetailsPanel.__init__ raises RuntimeError immediately when PyQt6 is absent.
  - _bootstrap_django sets DJANGO_SETTINGS_MODULE and adds the project root to
    sys.path (django.setup() is mocked so Django need not be configured).
  - launch.main() returns 1 when PyQt6 is absent (mocking _bootstrap_django).
"""

import os
import py_compile
import sys
import importlib
from unittest.mock import patch, MagicMock
import pytest

# Absolute path to the project root
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestMainWindowSyntax:
    def test_compiles_without_error(self):
        path = os.path.join(_PROJECT_ROOT, "gui", "main_window.py")
        # raises py_compile.PyCompileError on syntax error
        py_compile.compile(path, doraise=True)

    def test_pyqt6_unavailable_flag(self):
        import gui.main_window as mw
        # PyQt6 is not installed → flag must be False
        assert mw._PYQT6_AVAILABLE is False

    def test_globe_available_flag_exists(self):
        import gui.main_window as mw
        assert hasattr(mw, "_GLOBE_AVAILABLE")

    def test_main_window_class_exists(self):
        import gui.main_window as mw
        assert hasattr(mw, "MainWindow")

    def test_device_loader_class_exists(self):
        import gui.main_window as mw
        assert hasattr(mw, "_DeviceLoader")

    def test_main_window_raises_without_pyqt6(self):
        import gui.main_window as mw
        assert mw._PYQT6_AVAILABLE is False
        with pytest.raises(RuntimeError, match="PyQt6"):
            mw.MainWindow()


class TestDetailsPanelSyntax:
    def test_compiles_without_error(self):
        path = os.path.join(_PROJECT_ROOT, "gui", "details_panel.py")
        py_compile.compile(path, doraise=True)

    def test_pyqt6_unavailable_flag(self):
        import gui.details_panel as dp
        assert dp._PYQT6_AVAILABLE is False

    def test_details_panel_class_exists(self):
        import gui.details_panel as dp
        assert hasattr(dp, "DetailsPanel")

    def test_details_panel_raises_without_pyqt6(self):
        import gui.details_panel as dp
        assert dp._PYQT6_AVAILABLE is False
        with pytest.raises(RuntimeError, match="PyQt6"):
            dp.DetailsPanel()


class TestLaunchSyntax:
    def test_compiles_without_error(self):
        path = os.path.join(_PROJECT_ROOT, "gui", "launch.py")
        py_compile.compile(path, doraise=True)

    def test_main_function_exists(self):
        import gui.launch as launch
        assert callable(launch.main)

    def test_bootstrap_django_function_exists(self):
        import gui.launch as launch
        assert callable(launch._bootstrap_django)


class TestBootstrapDjango:
    def test_sets_django_settings_module_when_unset(self):
        import gui.launch as launch
        env_backup = os.environ.pop("DJANGO_SETTINGS_MODULE", None)
        try:
            with patch("django.setup"):
                launch._bootstrap_django()
            assert os.environ["DJANGO_SETTINGS_MODULE"] == "kamerka.settings"
        finally:
            if env_backup is not None:
                os.environ["DJANGO_SETTINGS_MODULE"] = env_backup
            else:
                os.environ.pop("DJANGO_SETTINGS_MODULE", None)

    def test_respects_existing_django_settings_module(self):
        import gui.launch as launch
        os.environ["DJANGO_SETTINGS_MODULE"] = "custom.settings"
        try:
            with patch("django.setup"):
                launch._bootstrap_django()
            assert os.environ["DJANGO_SETTINGS_MODULE"] == "custom.settings"
        finally:
            os.environ.pop("DJANGO_SETTINGS_MODULE", None)

    def test_adds_project_root_to_sys_path(self):
        import gui.launch as launch
        saved = sys.path.copy()
        sys.path = [p for p in sys.path if p != _PROJECT_ROOT]
        try:
            with patch("django.setup"):
                launch._bootstrap_django()
            assert _PROJECT_ROOT in sys.path
        finally:
            sys.path = saved

    def test_calls_django_setup(self):
        import gui.launch as launch
        with patch("django.setup") as mock_setup:
            launch._bootstrap_django()
        mock_setup.assert_called_once()


class TestLaunchMain:
    def test_returns_1_when_pyqt6_missing(self):
        """main() must return 1 when PyQt6 is not installed."""
        import gui.launch as launch
        with patch.object(launch, "_bootstrap_django"):
            result = launch.main()
        assert result == 1
