"""
globe_widget.py – PyVista + PyQt6 interactive 3-D globe widget.

Architecture
------------
GlobeWidget wraps a ``pyvistaqt.QtInteractor`` inside a plain ``QWidget``
so it can be inserted into any existing PyQt6 layout.

Offline-first texture
---------------------
The Earth texture is loaded from ``<project_root>/assets/earth_surface.jpg``
when it exists.  If the file is not present the widget falls back to
``pyvista.examples.planets.download_earth_surface()``, which downloads the
texture once and caches it locally.

Themes
------
Five built-in visual themes are available (see ``globe_3d.themes``):
cyberpunk, matrix, thermal, satellite, ghost.  Switch at runtime with::

    globe_widget.set_theme("matrix")

File loading — 2-D/3-D heat map pipeline
-----------------------------------------
Shodan CSV and KML exports produced by ``kamerka.tasks.shodan_csv_export``
/ ``shodan_kml_export`` can be loaded directly::

    globe_widget.load_file("/path/to/export.csv")   # or .kml
    globe_widget.load_file("/path/to/export.kml")

The resulting spike visualisation is a *3-D heat map*: spike height encodes
device-cluster size, spike colour encodes Nuclei/CVE severity.

Picker events
-------------
Clicking a spike mesh emits the ``spike_selected`` Qt signal with the
spike-data dict as payload.

Usage
-----
    from globe_3d.globe_widget import GlobeWidget

    widget = GlobeWidget(parent=self)
    widget.load_devices(device_records)   # list[dict] with lat/lon/severity
    layout.addWidget(widget)
"""

from __future__ import annotations

import os
import shutil
from typing import Any, Dict, List, Optional

try:
    from PyQt6.QtCore import pyqtSignal
    from PyQt6.QtWidgets import QVBoxLayout, QWidget
    _PYQT6_AVAILABLE = True
except ImportError:
    _PYQT6_AVAILABLE = False

try:
    import pyvista as pv
    import pyvistaqt
    _PYVISTA_AVAILABLE = True
except ImportError:
    _PYVISTA_AVAILABLE = False

from globe_3d.coordinate_mapper import EARTH_RADIUS, latlon_to_xyz, spike_base_xyz
from globe_3d.lod_manager import get_render_data
from globe_3d.spike_renderer import SPIKE_RADIUS, build_spike_data
from globe_3d.themes import DEFAULT_THEME, THEMES, GlobeTheme

# Path where the cached texture is stored for offline use.
_ASSETS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets")
_TEXTURE_PATH = os.path.join(_ASSETS_DIR, "earth_surface.jpg")


def _load_earth_texture() -> Optional[Any]:  # -> pv.Texture | None
    """Load the Earth surface texture, using the local cache when available."""
    if not _PYVISTA_AVAILABLE:
        return None
    if os.path.exists(_TEXTURE_PATH):
        return pv.read_texture(_TEXTURE_PATH)
    try:
        from pyvista.examples.planets import download_earth_surface
        texture_path = download_earth_surface()
        os.makedirs(_ASSETS_DIR, exist_ok=True)
        shutil.copy2(texture_path, _TEXTURE_PATH)
        return pv.read_texture(_TEXTURE_PATH)
    except Exception:
        return None


class GlobeWidget(QWidget if _PYQT6_AVAILABLE else object):
    """Interactive 3-D Earth globe embedded in a PyQt6 widget.

    Signals
    -------
    spike_selected : dict
        Emitted when the analyst clicks a device spike.  The payload is the
        spike-data dict (keys: lat, lon, count, severity, devices).
    """

    if _PYQT6_AVAILABLE:
        spike_selected = pyqtSignal(dict)

    def __init__(self, parent=None) -> None:
        if not _PYQT6_AVAILABLE:
            raise RuntimeError("PyQt6 is not installed.  pip install PyQt6")
        if not _PYVISTA_AVAILABLE:
            raise RuntimeError("pyvista/pyvistaqt not installed.  pip install pyvista pyvistaqt")
        super().__init__(parent)

        self._spike_data: List[Dict[str, Any]] = []
        self._spike_actors: List[Any] = []
        self._earth_actor: Optional[Any] = None
        self._grid_actor: Optional[Any] = None
        self._current_zoom: float = 0.0
        self._device_records: List[Dict[str, Any]] = []
        self._theme: GlobeTheme = THEMES[DEFAULT_THEME]

        self._build_ui()
        self._init_globe()

    # ------------------------------------------------------------------
    # Qt layout
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._plotter = pyvistaqt.QtInteractor(self)
        layout.addWidget(self._plotter.interactor)
        self.setLayout(layout)

    # ------------------------------------------------------------------
    # Globe initialisation
    # ------------------------------------------------------------------

    def _init_globe(self) -> None:
        """Build the Earth sphere and graticule using the current theme."""
        t = self._theme
        self._plotter.set_background(t.background)

        earth_mesh = pv.Sphere(
            radius=EARTH_RADIUS,
            theta_resolution=64,
            phi_resolution=64,
        )

        texture = _load_earth_texture() if t.use_texture else None
        if texture is not None:
            self._earth_actor = self._plotter.add_mesh(
                earth_mesh, texture=texture,
                smooth_shading=True, opacity=t.earth_opacity,
                ambient=t.ambient,
            )
        else:
            self._earth_actor = self._plotter.add_mesh(
                earth_mesh,
                color=t.earth_colour,
                smooth_shading=True,
                opacity=t.earth_opacity,
                ambient=t.ambient,
            )

        # Lat/lon graticule wireframe
        graticule = pv.Sphere(
            radius=EARTH_RADIUS * 1.001,
            theta_resolution=36,
            phi_resolution=18,
        )
        self._grid_actor = self._plotter.add_mesh(
            graticule,
            style="wireframe",
            color=t.grid_colour,
            opacity=t.grid_opacity,
            line_width=t.grid_line_width,
        )

        self._plotter.camera.position = (0, 0, 3.5)
        self._plotter.camera.focal_point = (0, 0, 0)
        self._plotter.enable_trackball_style()
        self._plotter.iren.add_observer("InteractionEvent", self._on_camera_moved)

    # ------------------------------------------------------------------
    # Public API — theme
    # ------------------------------------------------------------------

    def set_theme(self, theme_key: str) -> None:
        """Switch to a different visual theme and re-render everything.

        Parameters
        ----------
        theme_key : str
            One of ``"cyberpunk"``, ``"matrix"``, ``"thermal"``,
            ``"satellite"``, ``"ghost"``.
        """
        theme = THEMES.get(theme_key)
        if theme is None:
            return
        self._theme = theme

        # Remove old earth + grid actors
        if self._earth_actor is not None:
            self._plotter.remove_actor(self._earth_actor)
        if self._grid_actor is not None:
            self._plotter.remove_actor(self._grid_actor)

        self._init_globe()

        # Re-render spikes with theme-aware colours
        if self._spike_data:
            self._clear_spikes()
            self._render_spikes()

    # ------------------------------------------------------------------
    # Public API — device loading
    # ------------------------------------------------------------------

    def load_devices(
        self,
        device_records: List[Dict[str, Any]],
        zoom_level: Optional[float] = None,
    ) -> None:
        """Render a 3-D heat map of *device_records* on the globe.

        Spike height  →  cluster size (number of co-located devices).
        Spike colour  →  dominant Nuclei / CVE severity for the cluster.

        This is the *3-D heat map*: the spatial distribution of threats
        rises off the globe surface proportional to concentration and
        severity — equivalent to a choropleth but in three dimensions.

        Parameters
        ----------
        device_records : list[dict]
            Dicts with at minimum ``lat``, ``lon``, ``severity``.
            Also accepts dicts produced by ``kml_loader`` and ``csv_loader``.
        zoom_level : float, optional
            LOD zoom override (0.0 = global, 1.0 = street level).
        """
        self._device_records = list(device_records)
        self._clear_spikes()

        effective_zoom = zoom_level if zoom_level is not None else self._estimate_zoom()
        self._current_zoom = effective_zoom

        lod_clusters = get_render_data(self._device_records, effective_zoom)
        self._spike_data = build_spike_data(lod_clusters)
        self._render_spikes()

    def load_file(self, path: str) -> List[Dict[str, Any]]:
        """Load a Kamerka CSV or KML export and render it as a 3-D heat map.

        Detects the file format from the extension (``.csv`` / ``.kml``).
        The loaded device list is stored internally so ``refresh_lod()``
        can re-cluster without re-reading the file.

        Parameters
        ----------
        path : str
            Absolute path to a ``.csv`` or ``.kml`` file produced by the
            Shodan export views (``/export/csv/<id>`` or ``/export/kml/<id>``).

        Returns
        -------
        list[dict]
            The parsed device dicts (empty list on parse failure).
        """
        ext = os.path.splitext(path)[1].lower()
        if ext == ".kml":
            from globe_3d.kml_loader import load_kml
            devices = load_kml(path)
        elif ext == ".csv":
            from globe_3d.csv_loader import load_csv
            devices = load_csv(path)
        else:
            import logging
            logging.getLogger(__name__).warning(
                "load_file: unsupported extension %r (expected .csv or .kml)", ext
            )
            return []

        self.load_devices(devices)
        return devices

    def refresh_lod(self, device_records: Optional[List[Dict[str, Any]]] = None) -> None:
        """Re-render spikes at the current camera zoom level.

        Uses the last-loaded device list when *device_records* is omitted.
        """
        records = device_records if device_records is not None else self._device_records
        self.load_devices(records)

    # ------------------------------------------------------------------
    # Internal rendering helpers
    # ------------------------------------------------------------------

    def _clear_spikes(self) -> None:
        for actor in self._spike_actors:
            self._plotter.remove_actor(actor)
        self._spike_actors.clear()

    def _render_spikes(self) -> None:
        for i, spike in enumerate(self._spike_data):
            lat = spike["lat"]
            lon = spike["lon"]
            height = spike["height"]
            # Use theme-aware colour so spikes remain readable on all backgrounds
            colour = self._theme.spike_colour(spike["severity"])

            bx, by, bz = spike_base_xyz(lat, lon)
            nx, ny, nz = latlon_to_xyz(lat, lon)
            cx = bx + nx * height / 2
            cy = by + ny * height / 2
            cz = bz + nz * height / 2

            cylinder = pv.Cylinder(
                center=(cx, cy, cz),
                direction=(nx, ny, nz),
                radius=SPIKE_RADIUS,
                height=height,
                resolution=12,
            )
            actor = self._plotter.add_mesh(
                cylinder,
                color=colour,
                smooth_shading=False,
                name="spike_{}".format(i),
            )
            self._spike_actors.append(actor)

            # Glowing tip sphere
            tip = (bx + nx * height, by + ny * height, bz + nz * height)
            dot = pv.Sphere(radius=SPIKE_RADIUS * 2.5, center=tip)
            self._spike_actors.append(
                self._plotter.add_mesh(dot, color=colour, smooth_shading=True)
            )

        self._plotter.enable_mesh_picking(callback=self._on_mesh_picked, show=False)

    def _on_mesh_picked(self, mesh: Any) -> None:
        actor_name = getattr(mesh, "name", None)
        if actor_name and actor_name.startswith("spike_"):
            try:
                idx = int(actor_name.split("_")[1])
                if 0 <= idx < len(self._spike_data):
                    self.spike_selected.emit(self._spike_data[idx])
            except (IndexError, ValueError):
                pass

    def _on_camera_moved(self, obj: Any, event: Any) -> None:
        self._current_zoom = self._estimate_zoom()

    def _estimate_zoom(self) -> float:
        try:
            dist = self._plotter.camera.GetDistance()
        except Exception:
            return 0.0
        min_dist, max_dist = 1.0, 5.0
        return 1.0 - min(max((dist - min_dist) / (max_dist - min_dist), 0.0), 1.0)
