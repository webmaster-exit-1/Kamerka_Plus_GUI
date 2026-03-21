"""
spike_renderer.py – 3-D cylinder ("spike") rendering for Kamerka-Plus-GUI.

Each device cluster is represented as a cylinder (spike) rising from the Earth
surface.  Visual encoding:

  Colour  →  Nuclei severity
              Red    = critical / high
              Yellow = medium
              Green  = low / info / unknown

  Height  →  Proportional to the number of devices in the geolocation cluster
              (clamped between MIN_SPIKE_HEIGHT and MAX_SPIKE_HEIGHT so tiny
              clusters are still visible and large ones don't dominate the view).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Severity → colour mapping (RGB, 0–1 floats)
# ---------------------------------------------------------------------------

#: Colour palette keyed by normalised severity label.
SEVERITY_COLOURS: Dict[str, Tuple[float, float, float]] = {
    "critical": (1.0, 0.0, 0.0),   # red
    "high":     (1.0, 0.0, 0.0),   # red
    "medium":   (1.0, 1.0, 0.0),   # yellow
    "low":      (0.0, 0.8, 0.0),   # green
    "info":     (0.0, 0.6, 1.0),   # blue
    "unknown":  (0.5, 0.5, 0.5),   # grey
    "kev":      (0.6, 0.0, 1.0),   # purple — CISA KEV listed
}

#: Spike geometry constants (units match the Earth sphere radius = 1.0).
MIN_SPIKE_HEIGHT: float = 0.02
MAX_SPIKE_HEIGHT: float = 0.25
SPIKE_RADIUS: float = 0.008


def _normalise_severity(severity: str) -> str:
    """Map a raw Nuclei severity string to a canonical key."""
    return severity.strip().lower() if severity else "unknown"


def severity_to_colour(severity: str) -> Tuple[float, float, float]:
    """Return the RGB colour tuple for a given Nuclei severity label.

    Parameters
    ----------
    severity : str
        Raw severity string from a ``NucleiResult`` record
        (e.g. ``"Critical"``, ``"HIGH"``, ``"medium"``).

    Returns
    -------
    tuple[float, float, float]
        *(r, g, b)* in the range 0–1.
    """
    key = _normalise_severity(severity)
    return SEVERITY_COLOURS.get(key, SEVERITY_COLOURS["unknown"])


def scale_spike_height(device_count: int, max_count: int) -> float:
    """Compute the cylinder height for a cluster of *device_count* devices.

    The height is linearly interpolated between ``MIN_SPIKE_HEIGHT`` and
    ``MAX_SPIKE_HEIGHT`` relative to the maximum cluster size in the current
    data set (``max_count``).  A floor of ``MIN_SPIKE_HEIGHT`` guarantees that
    single-device locations are always rendered.

    Parameters
    ----------
    device_count : int
        Number of devices in this geographic cluster.
    max_count : int
        Largest cluster size in the full data set (used for normalisation).

    Returns
    -------
    float
        Cylinder height in sphere-radius units.
    """
    if max_count <= 0 or device_count <= 0:
        return MIN_SPIKE_HEIGHT
    ratio = min(device_count / max_count, 1.0)
    return MIN_SPIKE_HEIGHT + ratio * (MAX_SPIKE_HEIGHT - MIN_SPIKE_HEIGHT)


def build_spike_data(
    clusters: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Translate a sequence of device-cluster dicts into spike-geometry dicts.

    Each cluster dict must contain at minimum:

    ``lat`` : float         Latitude of the cluster centroid.
    ``lon`` : float         Longitude of the cluster centroid.
    ``count`` : int         Number of devices in the cluster.
    ``severity`` : str      Dominant Nuclei severity label.

    Optional keys
    -------------
    ``devices`` : list      Raw device records (forwarded verbatim).

    Returns
    -------
    list[dict]
        Each element has keys:
        ``lat``, ``lon``, ``height``, ``colour``, ``count``, ``severity``,
        ``devices`` (list, may be empty).
    """
    if not clusters:
        return []

    max_count = max(c.get("count", 1) for c in clusters)

    spikes = []
    for cluster in clusters:
        lat = float(cluster["lat"])
        lon = float(cluster["lon"])
        count = int(cluster.get("count", 1))
        severity = str(cluster.get("severity", "unknown"))
        spikes.append(
            {
                "lat": lat,
                "lon": lon,
                "height": scale_spike_height(count, max_count),
                "colour": severity_to_colour(severity),
                "count": count,
                "severity": severity,
                "devices": cluster.get("devices", []),
            }
        )
    return spikes


def dominant_severity(severities: Sequence[str]) -> str:
    """Return the most severe label from a collection of severity strings.

    Priority order: critical > high > medium > low > info > unknown.

    Parameters
    ----------
    severities : sequence of str
        Collection of raw severity strings.

    Returns
    -------
    str
        The highest-priority severity found, or ``"unknown"`` if the input is
        empty.
    """
    priority = ["kev", "critical", "high", "medium", "low", "info", "unknown"]
    normalised = [_normalise_severity(s) for s in severities]
    for level in priority:
        if level in normalised:
            return level
    return "unknown"
