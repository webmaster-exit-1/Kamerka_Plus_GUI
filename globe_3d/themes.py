"""
globe_3d/themes.py – Visual theme definitions for the 3-D globe viewer.

Each theme is a :class:`GlobeTheme` dataclass that fully describes the
colour palette applied to:

* The page/background colour.
* The Earth sphere (solid colour *or* a texture path override).
* The lat/lon graticule wireframe.
* The device spikes (severity → colour remapping so spikes stay readable
  against each background).

Usage
-----
    from globe_3d.themes import THEMES, GlobeTheme

    theme: GlobeTheme = THEMES["matrix"]
    plotter.set_background(theme.background)

Available themes
----------------
cyberpunk   Dark navy earth, electric-blue grid, neon severity spikes.
matrix      Black-green earth, phosphor-green grid, green spike palette.
thermal     Deep-purple earth, amber grid, heat-map spike palette.
satellite   Texture earth (if cached), subtle white grid, natural spikes.
ghost       Translucent silver earth, cyan grid, monochrome spikes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

RGB = Tuple[float, float, float]

# ---------------------------------------------------------------------------
# Theme dataclass
# ---------------------------------------------------------------------------

@dataclass
class GlobeTheme:
    """Complete visual specification for one globe theme.

    Parameters
    ----------
    name : str
        Human-readable display name shown in the toolbar combo box.
    background : str
        PyVista/matplotlib colour string for the render window background.
    earth_colour : str
        Fallback solid colour for the Earth sphere (used when no texture
        is available or the theme intentionally bypasses the texture).
    use_texture : bool
        When ``True`` the widget attempts to load the cached Earth texture
        before falling back to *earth_colour*.
    earth_opacity : float
        Opacity of the Earth mesh (1.0 = fully opaque).
    grid_colour : str
        Colour of the lat/lon graticule wireframe.
    grid_opacity : float
        Opacity of the graticule wireframe.
    grid_line_width : float
        Line width of the graticule in screen pixels.
    severity_colours : dict[str, RGB]
        Overrides the default severity → colour mapping from
        ``spike_renderer.SEVERITY_COLOURS``.  Keys that are absent fall
        back to the default palette.
    ambient : float
        Ambient lighting coefficient (0–1).  Higher values flatten the shading
        which suits translucent / monochrome themes.
    label : str
        Short label shown in the toolbar combo box (falls back to *name*).
    """

    name: str
    background: str
    earth_colour: str
    use_texture: bool
    earth_opacity: float
    grid_colour: str
    grid_opacity: float
    grid_line_width: float
    severity_colours: Dict[str, RGB]
    ambient: float = 0.3
    label: str = ""

    def __post_init__(self) -> None:
        if not self.label:
            self.label = self.name.capitalize()

    def spike_colour(self, severity: str) -> RGB:
        """Return the spike colour for *severity*, consulting theme overrides first."""
        from globe_3d.spike_renderer import SEVERITY_COLOURS
        key = severity.strip().lower() if severity else "unknown"
        return self.severity_colours.get(key, SEVERITY_COLOURS.get(key, (0.5, 0.5, 0.5)))


# ---------------------------------------------------------------------------
# Theme definitions
# ---------------------------------------------------------------------------

#: Default severity palette (imported lazily to avoid circular import).
_DEFAULT_SEV: Dict[str, RGB] = {}


def _default() -> Dict[str, RGB]:
    global _DEFAULT_SEV
    if not _DEFAULT_SEV:
        from globe_3d.spike_renderer import SEVERITY_COLOURS
        _DEFAULT_SEV = dict(SEVERITY_COLOURS)
    return _DEFAULT_SEV


CYBERPUNK = GlobeTheme(
    name="cyberpunk",
    label="🌐 Cyberpunk",
    background="black",
    earth_colour="#0a1428",
    use_texture=True,
    earth_opacity=1.0,
    grid_colour="#0064d7",
    grid_opacity=0.25,
    grid_line_width=0.6,
    severity_colours={},          # use default severity palette
    ambient=0.3,
)

MATRIX = GlobeTheme(
    name="matrix",
    label="💚 Matrix",
    background="#000800",
    earth_colour="#001a00",
    use_texture=False,
    earth_opacity=1.0,
    grid_colour="#00ff44",
    grid_opacity=0.30,
    grid_line_width=0.7,
    severity_colours={
        "critical": (0.0, 1.0, 0.2),
        "high":     (0.0, 0.9, 0.1),
        "medium":   (0.0, 0.75, 0.0),
        "low":      (0.0, 0.6, 0.0),
        "info":     (0.0, 0.4, 0.0),
        "unknown":  (0.0, 0.3, 0.0),
    },
    ambient=0.4,
)

THERMAL = GlobeTheme(
    name="thermal",
    label="🔥 Thermal",
    background="#05000a",
    earth_colour="#1a0025",
    use_texture=False,
    earth_opacity=1.0,
    grid_colour="#ff6600",
    grid_opacity=0.25,
    grid_line_width=0.6,
    severity_colours={
        "critical": (1.0, 0.05, 0.0),
        "high":     (1.0, 0.35, 0.0),
        "medium":   (1.0, 0.75, 0.0),
        "low":      (0.6, 0.0,  0.8),
        "info":     (0.2, 0.0,  0.6),
        "unknown":  (0.15, 0.0, 0.4),
    },
    ambient=0.25,
)

SATELLITE = GlobeTheme(
    name="satellite",
    label="🛰 Satellite",
    background="#000010",
    earth_colour="#1a3a5c",
    use_texture=True,              # use real Earth photo when cached
    earth_opacity=1.0,
    grid_colour="#ffffff",
    grid_opacity=0.12,
    grid_line_width=0.4,
    severity_colours={},           # keep default severity palette
    ambient=0.35,
)

GHOST = GlobeTheme(
    name="ghost",
    label="👻 Ghost",
    background="#080808",
    earth_colour="#b0c8d0",
    use_texture=False,
    earth_opacity=0.18,            # translucent — shows globe interior
    grid_colour="#00e1ff",
    grid_opacity=0.50,
    grid_line_width=0.8,
    severity_colours={
        "critical": (1.0, 1.0, 1.0),
        "high":     (0.85, 0.85, 0.85),
        "medium":   (0.65, 0.65, 0.65),
        "low":      (0.45, 0.45, 0.45),
        "info":     (0.3,  0.3,  0.3),
        "unknown":  (0.2,  0.2,  0.2),
    },
    ambient=0.6,
)

#: Ordered mapping of theme key → GlobeTheme used by the toolbar combo box.
THEMES: Dict[str, GlobeTheme] = {
    t.name: t for t in [CYBERPUNK, MATRIX, THERMAL, SATELLITE, GHOST]
}

#: Default theme applied on startup.
DEFAULT_THEME: str = "cyberpunk"
