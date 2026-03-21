"""
details_panel.py – PyQt6 sidebar widget for device intelligence display.

The DetailsPanel is shown on the left side of the MainWindow.  It is
populated whenever the analyst clicks a 3-D spike on the globe by the
``spike_selected`` signal from ``GlobeWidget``.

Displayed information
---------------------
* IP address and organisation
* Open ports banner (from ``Device.data``)
* NucleiResult vulnerability findings (template, severity, description)
* Raw scan notes
"""

from __future__ import annotations

from typing import Any, Dict, List

try:
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import (
        QFrame,
        QLabel,
        QScrollArea,
        QSizePolicy,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
    _PYQT6_AVAILABLE = True
except ImportError:
    _PYQT6_AVAILABLE = False


class DetailsPanel(QWidget if _PYQT6_AVAILABLE else object):
    """Scrollable sidebar that shows intelligence for the selected spike."""

    def __init__(self, parent=None) -> None:
        if not _PYQT6_AVAILABLE:
            raise RuntimeError(
                "PyQt6 is not installed.  Install it with: pip install PyQt6"
            )
        super().__init__(parent)
        self.setMinimumWidth(300)
        self.setSizePolicy(
            QSizePolicy.Policy.Preferred,
            QSizePolicy.Policy.Expanding,
        )
        self._build_ui()

    # ------------------------------------------------------------------
    # Qt layout
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(6)

        # Title
        title = QLabel("Device Intelligence")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        outer.addWidget(title)

        self._separator = QFrame()
        self._separator.setFrameShape(QFrame.Shape.HLine)
        outer.addWidget(self._separator)

        # Scrollable body
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(scroll)

        body = QWidget()
        scroll.setWidget(body)
        self._body_layout = QVBoxLayout(body)
        self._body_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._body_layout.setSpacing(6)

        # IP / org header
        self._ip_label = QLabel("No device selected")
        self._ip_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        self._ip_label.setWordWrap(True)
        self._body_layout.addWidget(self._ip_label)

        # Banner / data
        self._banner_label = QLabel("Banner")
        self._banner_label.setStyleSheet("color: grey; font-size: 11px;")
        self._body_layout.addWidget(self._banner_label)

        self._banner_text = QTextEdit()
        self._banner_text.setReadOnly(True)
        self._banner_text.setMaximumHeight(150)
        self._banner_text.setPlaceholderText("No banner data available.")
        self._body_layout.addWidget(self._banner_text)

        # Hardware & Protocol section
        self._hw_label = QLabel("Hardware & Protocol")
        self._hw_label.setStyleSheet("color: grey; font-size: 11px;")
        self._body_layout.addWidget(self._hw_label)

        self._hw_text = QTextEdit()
        self._hw_text.setReadOnly(True)
        self._hw_text.setMaximumHeight(120)
        self._hw_text.setPlaceholderText("No protocol fingerprint data.")
        self._body_layout.addWidget(self._hw_text)

        # Risk & Vulnerability section
        self._risk_label = QLabel("Risk Intelligence")
        self._risk_label.setStyleSheet("color: grey; font-size: 11px;")
        self._body_layout.addWidget(self._risk_label)

        self._risk_text = QTextEdit()
        self._risk_text.setReadOnly(True)
        self._risk_text.setMaximumHeight(100)
        self._risk_text.setPlaceholderText("No EPSS/KEV data available.")
        self._body_layout.addWidget(self._risk_text)

        # Vulnerability findings
        self._vulns_label = QLabel("Vulnerability Findings")
        self._vulns_label.setStyleSheet("color: grey; font-size: 11px;")
        self._body_layout.addWidget(self._vulns_label)

        self._vulns_text = QTextEdit()
        self._vulns_text.setReadOnly(True)
        self._vulns_text.setPlaceholderText("No Nuclei findings available.")
        self._body_layout.addWidget(self._vulns_text)

        # Notes
        self._notes_label = QLabel("Notes")
        self._notes_label.setStyleSheet("color: grey; font-size: 11px;")
        self._body_layout.addWidget(self._notes_label)

        self._notes_text = QTextEdit()
        self._notes_text.setReadOnly(True)
        self._notes_text.setMaximumHeight(80)
        self._notes_text.setPlaceholderText("No notes.")
        self._body_layout.addWidget(self._notes_text)

        self.setLayout(outer)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def clear(self) -> None:
        """Reset all fields to their empty/placeholder state."""
        self._ip_label.setText("No device selected")
        self._banner_text.clear()
        self._hw_text.clear()
        self._risk_text.clear()
        self._vulns_text.clear()
        self._notes_text.clear()

    def populate_from_spike(self, spike_data: Dict[str, Any]) -> None:
        """Fill the panel with intelligence from a clicked spike.

        Parameters
        ----------
        spike_data : dict
            The spike-data dict emitted by ``GlobeWidget.spike_selected``.
            Must contain a ``"devices"`` list of device record dicts.
        """
        devices: List[Dict[str, Any]] = spike_data.get("devices", [])
        if not devices:
            self.clear()
            return

        # For multi-device clusters show a summary; for single show full detail.
        if len(devices) == 1:
            self._populate_single(devices[0])
        else:
            self._populate_cluster(devices, spike_data)

    def populate_from_device(self, device_dict: Dict[str, Any]) -> None:
        """Fill the panel directly from a device record dict.

        Parameters
        ----------
        device_dict : dict
            Device record with keys matching ``app_kamerka.models.Device``
            fields (``ip``, ``org``, ``data``, ``vulns``, ``notes``).
        """
        self._populate_single(device_dict)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _populate_single(self, device: Dict[str, Any]) -> None:
        ip = device.get("ip", "Unknown")
        org = device.get("org", "")
        city = device.get("city", "")
        country = device.get("country_code", "")

        header_parts = [ip]
        if org:
            header_parts.append(org)
        if city:
            header_parts.append("{} {}".format(city, country).strip())
        self._ip_label.setText("  |  ".join(header_parts))

        banner = device.get("data", "")
        self._banner_text.setPlainText(banner or "No banner data available.")

        # Hardware & Protocol
        hw_lines = []
        product = device.get("product", "")
        if product:
            hw_lines.append("Product: {}".format(product))
        cpe = device.get("cpe", "")
        if cpe:
            hw_lines.append("CPE: {}".format(cpe))
        isp = device.get("isp", "")
        if isp:
            hw_lines.append("ISP: {}".format(isp))
        fingerprints = device.get("fingerprints", [])
        for fp in fingerprints:
            proto = fp.get("protocol", "?")
            hw_lines.append("[{}]".format(proto.upper()))
            for k in ("vendor_id", "module_name", "hardware_version",
                       "firmware_version", "serial_number"):
                val = fp.get(k, "")
                if val:
                    hw_lines.append("  {}: {}".format(
                        k.replace("_", " ").title(), val
                    ))
        self._hw_text.setPlainText(
            "\n".join(hw_lines) if hw_lines else "No hardware data."
        )

        # Risk Intelligence
        risk_lines = []
        vuln_intel = device.get("vuln_intel", [])
        for vi in vuln_intel:
            cve = vi.get("cve_id", "?")
            epss = vi.get("epss_score", 0.0)
            kev = vi.get("kev_listed", False)
            line = "{} EPSS:{:.4f}".format(cve, epss)
            if kev:
                line += " [KEV]"
            risk_lines.append(line)
        self._risk_text.setPlainText(
            "\n".join(risk_lines) if risk_lines else "No EPSS/KEV data."
        )

        self._render_vulns(device)

        notes = device.get("notes", "")
        self._notes_text.setPlainText(notes or "")

    def _populate_cluster(
        self, devices: List[Dict[str, Any]], spike_data: Dict[str, Any]
    ) -> None:
        count = spike_data.get("count", len(devices))
        severity = spike_data.get("severity", "unknown")
        lat = spike_data.get("lat", "?")
        lon = spike_data.get("lon", "?")

        self._ip_label.setText(
            "{} devices  |  {:.4f}, {:.4f}  |  severity: {}".format(
                count, float(lat), float(lon), severity
            )
        )
        # Show a summary of IPs
        ip_list = "\n".join(d.get("ip", "?") for d in devices[:20])
        if len(devices) > 20:
            ip_list += "\n… and {} more".format(len(devices) - 20)
        self._banner_text.setPlainText(ip_list)

        # Aggregate all vuln findings
        all_vulns = []
        for d in devices:
            all_vulns.extend(self._extract_vulns(d))
        self._vulns_text.setPlainText(
            "\n\n".join(all_vulns) if all_vulns else "No findings."
        )
        self._notes_text.clear()

    def _render_vulns(self, device: Dict[str, Any]) -> None:
        lines = self._extract_vulns(device)
        self._vulns_text.setPlainText(
            "\n\n".join(lines) if lines else "No Nuclei findings available."
        )

    @staticmethod
    def _extract_vulns(device: Dict[str, Any]) -> List[str]:
        """Extract Nuclei findings from a device dict.

        Tries the ``"nuclei_results"`` key (pre-fetched ORM objects serialised
        as dicts) first, then falls back to the raw ``"vulns"`` string field.
        """
        lines: List[str] = []

        nuclei_results = device.get("nuclei_results", [])
        for result in nuclei_results:
            sev = result.get("severity", "?").upper()
            name = result.get("name", result.get("template_id", "?"))
            desc = result.get("description", "")
            matched = result.get("matched_at", "")
            lines.append(
                "[{}] {}\n  Matched: {}\n  {}".format(sev, name, matched, desc).strip()
            )

        if not lines:
            raw_vulns = device.get("vulns", "")
            if raw_vulns and raw_vulns not in ("", "[]", "{}"):
                lines.append(str(raw_vulns))

        return lines
