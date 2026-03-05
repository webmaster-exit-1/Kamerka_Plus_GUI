"""
main_window.py – PyQt6 application main window for Kamerka-Plus-GUI.

Layout
------
┌─────────────────────────────────────────────────────────────┐
│  [Toolbar: Load Devices | Refresh | Clear]                  │
├──────────────────┬──────────────────────────────────────────┤
│                  │                                          │
│  DetailsPanel    │         GlobeWidget (PyVista)            │
│  (left, ~300 px) │         (right, fills remaining space)   │
│                  │                                          │
│                  │                                          │
└──────────────────┴──────────────────────────────────────────┘

Signal flow
-----------
GlobeWidget.spike_selected  →  DetailsPanel.populate_from_spike

All I/O (fetching devices from DB) runs in a QThread so the Qt event loop
is never blocked.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

try:
    from PyQt6.QtCore import QThread, Qt, pyqtSignal, QObject
    from PyQt6.QtWidgets import (
        QHBoxLayout,
        QLabel,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QSplitter,
        QStatusBar,
        QToolBar,
        QWidget,
    )
    _PYQT6_AVAILABLE = True
except ImportError:
    _PYQT6_AVAILABLE = False

try:
    from globe_3d.globe_widget import GlobeWidget
    from gui.details_panel import DetailsPanel
    _GLOBE_AVAILABLE = True
except Exception:
    _GLOBE_AVAILABLE = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Background worker: loads device records from the Django ORM without
# blocking the Qt event loop.
# ---------------------------------------------------------------------------

class _DeviceLoader(QObject if _PYQT6_AVAILABLE else object):
    """QObject worker that fetches device records in a background QThread."""

    if _PYQT6_AVAILABLE:
        finished = pyqtSignal(list)   # emits List[Dict[str, Any]]
        error = pyqtSignal(str)

    def run(self) -> None:
        """Fetch all Device records and emit them as a list of dicts."""
        try:
            from app_kamerka.models import Device, NucleiResult
            devices = []
            for d in Device.objects.select_related("search").prefetch_related(
                "nucleiresult_set"
            ).all():
                nuclei = [
                    {
                        "template_id": n.template_id,
                        "name": n.name,
                        "severity": n.severity,
                        "matched_at": n.matched_at,
                        "description": n.description,
                    }
                    for n in d.nucleiresult_set.all()
                ]
                # Determine dominant severity from NucleiResult findings
                severity = "unknown"
                if nuclei:
                    from globe_3d.spike_renderer import dominant_severity
                    severity = dominant_severity([r["severity"] for r in nuclei])

                devices.append(
                    {
                        "ip": d.ip,
                        "lat": d.lat,
                        "lon": d.lon,
                        "org": d.org or "",
                        "city": d.city or "",
                        "country_code": d.country_code,
                        "data": d.data,
                        "vulns": d.vulns,
                        "notes": d.notes,
                        "product": d.product,
                        "port": d.port,
                        "type": d.type,
                        "severity": severity,
                        "nuclei_results": nuclei,
                    }
                )
            self.finished.emit(devices)
        except Exception as exc:
            self.error.emit(str(exc))


# ---------------------------------------------------------------------------
# Main Window
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow if _PYQT6_AVAILABLE else object):
    """Top-level window hosting the 3-D globe and the Details panel."""

    def __init__(self, parent=None) -> None:
        if not _PYQT6_AVAILABLE:
            raise RuntimeError(
                "PyQt6 is not installed.  Install it with: pip install PyQt6"
            )
        super().__init__(parent)
        self.setWindowTitle("ꓘamerka Plus – 3D Intelligence Globe")
        self.resize(1400, 860)

        self._device_records: List[Dict[str, Any]] = []
        self._loader_thread: Any = None

        self._build_toolbar()
        self._build_central_widget()
        self._build_status_bar()

    # ------------------------------------------------------------------
    # Qt layout builders
    # ------------------------------------------------------------------

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        load_btn = QPushButton("Load Devices")
        load_btn.clicked.connect(self._on_load_devices)
        toolbar.addWidget(load_btn)

        refresh_btn = QPushButton("Refresh Globe")
        refresh_btn.clicked.connect(self._on_refresh)
        toolbar.addWidget(refresh_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._on_clear)
        toolbar.addWidget(clear_btn)

    def _build_central_widget(self) -> None:
        splitter = QSplitter(Qt.Orientation.Horizontal)

        if _GLOBE_AVAILABLE:
            self._details = DetailsPanel(self)
            self._globe = GlobeWidget(self)
            self._globe.spike_selected.connect(self._on_spike_selected)
            splitter.addWidget(self._details)
            splitter.addWidget(self._globe)
            splitter.setSizes([320, 1080])
        else:
            # Graceful degradation when PyVista/PyQt6 are not installed
            placeholder = QLabel(
                "3D globe requires pyvista and pyvistaqt.\n"
                "Install: pip install pyvista pyvistaqt"
            )
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            splitter.addWidget(placeholder)

        self.setCentralWidget(splitter)

    def _build_status_bar(self) -> None:
        self._status_bar = QStatusBar()
        self.setStatusBar(self._status_bar)
        self._status_bar.showMessage("Ready.")

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_spike_selected(self, spike_data: Dict[str, Any]) -> None:
        """Relay a spike click to the Details panel."""
        if _GLOBE_AVAILABLE:
            self._details.populate_from_spike(spike_data)
        count = spike_data.get("count", 1)
        lat = spike_data.get("lat", 0)
        lon = spike_data.get("lon", 0)
        self._status_bar.showMessage(
            "Selected: {} device(s) near ({:.3f}, {:.3f})".format(count, lat, lon)
        )

    def _on_load_devices(self) -> None:
        """Fetch devices from Django DB in a background thread."""
        self._status_bar.showMessage("Loading devices…")

        self._loader_thread = QThread()
        self._loader = _DeviceLoader()
        self._loader.moveToThread(self._loader_thread)
        self._loader_thread.started.connect(self._loader.run)
        self._loader.finished.connect(self._on_devices_loaded)
        self._loader.finished.connect(self._loader_thread.quit)
        self._loader.error.connect(self._on_load_error)
        self._loader.error.connect(self._loader_thread.quit)
        self._loader_thread.start()

    def _on_devices_loaded(self, devices: List[Dict[str, Any]]) -> None:
        self._device_records = devices
        if _GLOBE_AVAILABLE:
            self._globe.load_devices(devices)
        self._status_bar.showMessage(
            "Loaded {} device(s).".format(len(devices))
        )

    def _on_load_error(self, message: str) -> None:
        self._status_bar.showMessage("Error loading devices.")
        QMessageBox.critical(self, "Load Error", message)

    def _on_refresh(self) -> None:
        if _GLOBE_AVAILABLE and self._device_records:
            self._globe.refresh_lod(self._device_records)
            self._status_bar.showMessage("Globe refreshed.")

    def _on_clear(self) -> None:
        if _GLOBE_AVAILABLE:
            self._globe.load_devices([])
            self._details.clear()
        self._device_records = []
        self._status_bar.showMessage("Cleared.")
