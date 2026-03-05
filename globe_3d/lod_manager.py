"""
lod_manager.py – Level-of-Detail cluster/dissolve logic for the globe view.

Two rendering modes
-------------------
Global view  (camera far from Earth):
    Devices are aggregated into geographic clusters represented as a single
    tall spike.  Cluster radius is controlled by ``CLUSTER_RADIUS_DEG``.

Zoomed view  (camera close to a region):
    The aggregate spike is dissolved back into individual device points so
    that the analyst can see per-IP detail.

The switchover is driven by the *zoom level* – a float in the range
[0.0, 1.0] where 0.0 means "looking at the whole globe" and 1.0 means
"zoomed in as far as possible".  ``LOD_ZOOM_THRESHOLD`` is the crossover
point.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Dict, List, Sequence

from globe_3d.spike_renderer import dominant_severity

#: Geographic bucket size (degrees) used in the global / clustered view.
CLUSTER_RADIUS_DEG: float = 2.0

#: Camera zoom fraction above which individual points are shown instead of
#: aggregate bars.  Range [0.0, 1.0].
LOD_ZOOM_THRESHOLD: float = 0.6


def _bucket_key(lat: float, lon: float, radius_deg: float) -> tuple:
    """Snap (lat, lon) to a grid with cell size *radius_deg*."""
    lat_bucket = math.floor(lat / radius_deg) * radius_deg
    lon_bucket = math.floor(lon / radius_deg) * radius_deg
    return (lat_bucket, lon_bucket)


def cluster_devices(
    devices: Sequence[Dict[str, Any]],
    radius_deg: float = CLUSTER_RADIUS_DEG,
) -> List[Dict[str, Any]]:
    """Aggregate *devices* into geographic clusters for the global view.

    Each device dict must contain at minimum:
        ``lat``      : float  Latitude in degrees.
        ``lon``      : float  Longitude in degrees.
        ``severity`` : str    Dominant Nuclei severity label (may be empty).

    Parameters
    ----------
    devices : sequence of dict
        Raw device records (e.g. from the Django ``Device`` queryset).
    radius_deg : float, optional
        Grid-cell size in degrees used for bucketing (default 2°).

    Returns
    -------
    list[dict]
        Cluster dicts suitable for :func:`globe_3d.spike_renderer.build_spike_data`.
        Keys: ``lat``, ``lon``, ``count``, ``severity``, ``devices``.
    """
    buckets: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)

    for device in devices:
        try:
            lat = float(device["lat"])
            lon = float(device["lon"])
        except (KeyError, TypeError, ValueError):
            continue
        key = _bucket_key(lat, lon, radius_deg)
        buckets[key].append(device)

    clusters = []
    for (lat_bucket, lon_bucket), members in buckets.items():
        # Centroid = average of member coordinates
        centroid_lat = sum(float(d["lat"]) for d in members) / len(members)
        centroid_lon = sum(float(d["lon"]) for d in members) / len(members)
        severities = [str(d.get("severity", "")) for d in members]
        clusters.append(
            {
                "lat": centroid_lat,
                "lon": centroid_lon,
                "count": len(members),
                "severity": dominant_severity(severities),
                "devices": members,
            }
        )
    return clusters


def dissolve_cluster(cluster: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Dissolve a single aggregate cluster back into individual device points.

    Parameters
    ----------
    cluster : dict
        A cluster dict returned by :func:`cluster_devices`, containing a
        ``devices`` list of individual device records.

    Returns
    -------
    list[dict]
        One spike-data dict per device.  Each has ``count=1``.
    """
    result = []
    for device in cluster.get("devices", []):
        try:
            lat = float(device["lat"])
            lon = float(device["lon"])
        except (KeyError, TypeError, ValueError):
            continue
        result.append(
            {
                "lat": lat,
                "lon": lon,
                "count": 1,
                "severity": str(device.get("severity", "unknown")),
                "devices": [device],
            }
        )
    return result


def get_render_data(
    devices: Sequence[Dict[str, Any]],
    zoom_level: float,
    radius_deg: float = CLUSTER_RADIUS_DEG,
    lod_threshold: float = LOD_ZOOM_THRESHOLD,
) -> List[Dict[str, Any]]:
    """Return the spike-data list appropriate for the current *zoom_level*.

    Parameters
    ----------
    devices : sequence of dict
        Full set of active device records.
    zoom_level : float
        Current camera zoom fraction in [0.0, 1.0].
    radius_deg : float, optional
        Clustering grid cell size in degrees (default ``CLUSTER_RADIUS_DEG``).
    lod_threshold : float, optional
        Zoom fraction above which individual points are shown (default
        ``LOD_ZOOM_THRESHOLD``).

    Returns
    -------
    list[dict]
        Cluster dicts (``count ≥ 1``) ready for
        :func:`globe_3d.spike_renderer.build_spike_data`.
    """
    clusters = cluster_devices(devices, radius_deg=radius_deg)

    if zoom_level < lod_threshold:
        # Global view – return aggregate clusters as-is
        return clusters

    # Zoomed view – dissolve every cluster into individual points
    individual: List[Dict[str, Any]] = []
    for cluster in clusters:
        individual.extend(dissolve_cluster(cluster))
    return individual
