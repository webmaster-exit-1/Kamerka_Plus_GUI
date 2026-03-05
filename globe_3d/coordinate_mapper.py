"""
coordinate_mapper.py – WGS-84 ↔ Cartesian conversion for the PyVista globe.

The Earth mesh produced by PyVista uses a unit sphere (radius = 1.0).  All
spike placements must use the same radius so that the base of every cylinder
sits exactly on the surface.

Formula (from the architectural directive)
------------------------------------------
  lat, lon  →  radians first, then:
      x = R · cos(lat) · cos(lon)
      y = R · cos(lat) · sin(lon)
      z = R · sin(lat)
"""

from __future__ import annotations

import math
from typing import Tuple

# PyVista's planet sphere uses radius 1 by default.
# Spikes are rendered slightly above the surface by adding SPIKE_OFFSET.
EARTH_RADIUS: float = 1.0
SPIKE_OFFSET: float = 0.001  # small gap so the spike base is visible


def latlon_to_xyz(
    lat_deg: float,
    lon_deg: float,
    radius: float = EARTH_RADIUS,
) -> Tuple[float, float, float]:
    """Convert WGS-84 geographic coordinates to Cartesian (X, Y, Z).

    Parameters
    ----------
    lat_deg : float
        Geodetic latitude in degrees (−90 … +90).
    lon_deg : float
        Geodetic longitude in degrees (−180 … +180).
    radius : float, optional
        Sphere radius.  Must match the radius used when constructing the
        ``pyvista.Sphere`` Earth mesh (default ``EARTH_RADIUS = 1.0``).

    Returns
    -------
    tuple[float, float, float]
        *(x, y, z)* Cartesian coordinates on the unit sphere surface.
    """
    lat = math.radians(lat_deg)
    lon = math.radians(lon_deg)
    x = radius * math.cos(lat) * math.cos(lon)
    y = radius * math.cos(lat) * math.sin(lon)
    z = radius * math.sin(lat)
    return x, y, z


def xyz_to_latlon(
    x: float,
    y: float,
    z: float,
    radius: float = EARTH_RADIUS,
) -> Tuple[float, float]:
    """Inverse conversion: Cartesian (X, Y, Z) → WGS-84 (lat_deg, lon_deg).

    Parameters
    ----------
    x, y, z : float
        Cartesian coordinates on the sphere.
    radius : float, optional
        Sphere radius used in the original mapping (default ``EARTH_RADIUS``).

    Returns
    -------
    tuple[float, float]
        *(lat_deg, lon_deg)* in degrees.
    """
    r = math.sqrt(x * x + y * y + z * z)
    if r == 0:
        return 0.0, 0.0
    lat_deg = math.degrees(math.asin(z / r))
    lon_deg = math.degrees(math.atan2(y, x))
    return lat_deg, lon_deg


def spike_base_xyz(
    lat_deg: float,
    lon_deg: float,
    radius: float = EARTH_RADIUS,
) -> Tuple[float, float, float]:
    """Return the Cartesian position for the *base* of a spike.

    The base is placed at ``radius + SPIKE_OFFSET`` so it sits just above the
    Earth surface and is fully visible even at the globe equator.

    Parameters
    ----------
    lat_deg : float
        Geodetic latitude in degrees.
    lon_deg : float
        Geodetic longitude in degrees.
    radius : float, optional
        Earth mesh radius (default ``EARTH_RADIUS``).

    Returns
    -------
    tuple[float, float, float]
        Cartesian coordinates for the spike base.
    """
    return latlon_to_xyz(lat_deg, lon_deg, radius=radius + SPIKE_OFFSET)
