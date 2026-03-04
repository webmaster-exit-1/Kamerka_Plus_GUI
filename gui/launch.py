"""
launch.py – Application entry-point for the Kamerka-Plus-GUI 3D viewer.

Usage
-----
    python -m gui.launch
    # or
    python gui/launch.py

This script:
  1. Bootstraps Django so the ORM is available for the device loader.
  2. Creates the QApplication and MainWindow.
  3. Enters the Qt event loop.

Django settings used:
    ``settings.NAABU_BIN``, ``settings.NUCLEI_BIN`` — loaded from
    ``kamerka/tool_settings.py``.  Override via ``KAMERKA_NAABU_BIN`` /
    ``KAMERKA_NUCLEI_BIN`` environment variables before launching.
"""

from __future__ import annotations

import os
import sys


def _bootstrap_django() -> None:
    """Configure Django settings for standalone (non-server) use."""
    # Allow the caller to override the settings module via environment variable.
    settings_module = os.environ.get(
        "DJANGO_SETTINGS_MODULE", "kamerka.settings"
    )
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", settings_module)

    # Add the project root to sys.path so Django can find the app packages.
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    import django
    django.setup()


def main() -> int:
    """Bootstrap Django and launch the PyQt6 application.

    Returns
    -------
    int
        Exit code (0 = success).
    """
    _bootstrap_django()

    try:
        from PyQt6.QtWidgets import QApplication
    except ImportError:
        print(
            "PyQt6 is not installed.\n"
            "Install: pip install PyQt6 pyvista pyvistaqt pyproj",
            file=sys.stderr,
        )
        return 1

    from gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("Kamerka Plus")
    app.setApplicationVersion("3.0")

    window = MainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
