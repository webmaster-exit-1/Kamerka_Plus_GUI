"""
app_layers/views.py — REST endpoints for the data layer system.

Endpoints
---------
GET  /api/layers/                          — list all enabled layers (JSON)
GET  /api/layers/<slug>/features.json      — GeoJSON FeatureCollection for a layer
POST /api/layers/import/                   — import a GeoJSON FeatureCollection
GET  /api/layers/<slug>/refresh/           — manually trigger a layer refresh
"""
from __future__ import annotations

import json
import math

from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_http_methods

from app_layers.models import DataLayer, LayerFeature


def _require_staff(request):
    """Return a 403 JSON response unless the requester is an authenticated staff user."""
    if request.user.is_authenticated and request.user.is_staff:
        return None
    return JsonResponse({"error": "Permission denied. Staff access required."}, status=403)


def _iter_lon_lat_pairs(node):
    """Yield ``(lon, lat)`` float pairs from GeoJSON-style coordinates data.

    ``node`` should be a GeoJSON ``coordinates`` value, i.e. a nested list/tuple
    structure that eventually contains numeric ``[lon, lat]`` pairs.
    """
    if not isinstance(node, (list, tuple)):
        return
    if len(node) >= 2 and all(isinstance(v, (int, float)) for v in node[:2]):
        yield float(node[0]), float(node[1])
        return
    for item in node:
        yield from _iter_lon_lat_pairs(item)


def _bbox_overlaps(a, b):
    """Return True when two ``(min_lon, min_lat, max_lon, max_lat)`` boxes overlap."""
    a_min_lon, a_min_lat, a_max_lon, a_max_lat = a
    b_min_lon, b_min_lat, b_max_lon, b_max_lat = b
    return not (
        a_max_lon < b_min_lon
        or a_min_lon > b_max_lon
        or a_max_lat < b_min_lat
        or a_min_lat > b_max_lat
    )


def _geometry_bounds(geometry):
    """Return the bounds of a GeoJSON geometry as ``(min_lon, min_lat, max_lon, max_lat)``."""
    if not isinstance(geometry, dict):
        return None

    coords = list(_iter_lon_lat_pairs(geometry.get("coordinates")))
    if not coords:
        return None

    lons = [lon for lon, _lat in coords]
    lats = [lat for _lon, lat in coords]
    return min(lons), min(lats), max(lons), max(lats)


def _geometry_intersects_bbox(geometry, bbox):
    """Return True if the geometry bounds overlap ``bbox``.

    ``geometry`` is expected to be a GeoJSON geometry dict with a
    ``coordinates`` key. ``bbox`` must be ``(min_lon, min_lat, max_lon, max_lat)``.
    """
    geometry_bbox = _geometry_bounds(geometry)
    if geometry_bbox is None:
        return False
    return _bbox_overlaps(geometry_bbox, bbox)


def _parse_bbox(raw_bbox: str):
    """Parse ``min_lon,min_lat,max_lon,max_lat`` into a 4-float tuple.

    Returns ``(min_lon, min_lat, max_lon, max_lat)`` on success, else ``None``.
    """
    try:
        parts = [float(p.strip()) for p in (raw_bbox or "").split(",")]
    except ValueError:
        return None
    if len(parts) != 4:
        return None
    if not all(math.isfinite(value) for value in parts):
        return None
    min_lon, min_lat, max_lon, max_lat = parts
    if min_lon >= max_lon or min_lat >= max_lat:
        return None
    return min_lon, min_lat, max_lon, max_lat


def _parse_limit(raw_limit: str, *, max_limit: int = 5000):
    """Parse a positive integer limit query value.

    Returns a clamped integer on success, ``None`` when not provided, or
    ``False`` when provided but invalid. Values greater than ``max_limit`` are
    clamped to ``max_limit``.
    """
    if raw_limit in (None, ""):
        return None
    try:
        value = int(str(raw_limit).strip())
    except (TypeError, ValueError):
        return False
    if value <= 0:
        return False
    return min(value, max_limit)


def _layer_supported_views(layer: DataLayer):
    """Return supported frontend views for a layer as ``["map", "globe"]`` subset."""
    cfg = layer.renderer_config or {}
    cfg_views = cfg.get("views")
    if isinstance(cfg_views, list):
        views = [v for v in cfg_views if v in ("map", "globe")]
        if views:
            return views

    supports_globe = layer.layer_type in {"point", "linestring"}
    return ["map", "globe"] if supports_globe else ["map"]


def _serialize_layer(layer: DataLayer):
    """Serialize DataLayer metadata for 2D + 3D consumers."""
    supported_views = _layer_supported_views(layer)
    features_path = f"/api/layers/{layer.slug}/features.json"
    return {
        "slug": layer.slug,
        "name": layer.name,
        "layer_type": layer.layer_type,
        "color": layer.color,
        "icon": layer.icon,
        "renderer_config": layer.renderer_config or {},
        "supported_views": supported_views,
        "last_refreshed": layer.last_refreshed.isoformat() if layer.last_refreshed else None,
        "endpoints": {
            "features": features_path,
        },
    }


@require_GET
def layer_list(request):
    """Return metadata for all enabled layers as JSON."""
    layers = DataLayer.objects.filter(enabled=True)
    view_filter = (request.GET.get("view", "") or "").strip().lower()
    data = []
    for layer in layers:
        payload = _serialize_layer(layer)
        if view_filter and view_filter not in payload["supported_views"]:
            continue
        data.append(payload)
    return JsonResponse(data, safe=False)


@require_GET
def layer_features(request, slug: str):
    """Return a GeoJSON FeatureCollection for the named layer."""
    try:
        layer = DataLayer.objects.get(slug=slug, enabled=True)
    except DataLayer.DoesNotExist:
        return JsonResponse({"error": "not found"}, status=404)

    bbox = None
    raw_bbox = request.GET.get("bbox", "")
    if raw_bbox:
        bbox = _parse_bbox(raw_bbox)
        if bbox is None:
            return JsonResponse(
                {"error": "invalid bbox; expected min_lon,min_lat,max_lon,max_lat"},
                status=400,
            )

    limit = _parse_limit(request.GET.get("limit"))
    if limit is False:
        return JsonResponse(
            {"error": "invalid limit; expected a positive integer"},
            status=400,
        )

    features = []
    for feat in layer.features.all():
        if bbox and not _geometry_intersects_bbox(feat.geometry, bbox):
            continue
        features.append({
            "type": "Feature",
            "geometry": feat.geometry,
            "properties": {
                **feat.properties,
                "_layer": slug,
                "_id": feat.pk,
            },
        })
        if limit and len(features) >= limit:
            break

    return JsonResponse(
        {
            "type": "FeatureCollection",
            "features": features,
            "layer": {
                "slug": layer.slug,
                "name": layer.name,
                "layer_type": layer.layer_type,
                "color": layer.color,
                "icon": layer.icon,
                "renderer_config": layer.renderer_config or {},
            },
        }
    )


@require_http_methods(["POST"])
def layer_import(request):
    """Import a GeoJSON FeatureCollection as a new DataLayer (or update existing).

    Expected JSON body::

        {
            "slug": "my_layer",
            "name": "My custom layer",
            "color": "#00ff00",
            "features": { ...GeoJSON FeatureCollection... }
        }
    """
    permission_error = _require_staff(request)
    if permission_error:
        return permission_error

    try:
        payload = json.loads(request.body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse({"error": "invalid JSON"}, status=400)

    slug = payload.get("slug", "")
    name = payload.get("name", slug)
    color = payload.get("color", "#ffffff")

    if not slug:
        return JsonResponse({"error": "slug is required"}, status=400)

    fc = payload.get("features") or {}
    if not isinstance(fc, dict):
        return JsonResponse(
            {"error": "features must contain a GeoJSON FeatureCollection object"},
            status=400,
        )
    if fc.get("type") != "FeatureCollection":
        return JsonResponse(
            {"error": "features.type must be 'FeatureCollection'"},
            status=400,
        )

    feature_rows = []
    imported = 0
    feature_list = fc.get("features", [])
    if not isinstance(feature_list, list):
        return JsonResponse({"error": "features.features must be a list"}, status=400)

    for index, feat in enumerate(feature_list, start=1):
        geom = feat.get("geometry") or {}
        props = feat.get("properties") or {}
        coords = geom.get("coordinates", [])
        lat = lon = None
        if geom.get("type") == "Point":
            if len(coords) < 2:
                return JsonResponse(
                    {"error": f"feature {index} has invalid Point coordinates"},
                    status=400,
                )
            try:
                lon, lat = float(coords[0]), float(coords[1])
            except (TypeError, ValueError):
                return JsonResponse(
                    {"error": f"feature {index} has non-numeric Point coordinates"},
                    status=400,
                )
        ext_id = str(props.get("id", ""))
        defaults = {
            "lat": lat,
            "lon": lon,
            "geometry": geom,
            "properties": props,
        }
        feature_rows.append((ext_id, defaults))

    layer, created = DataLayer.objects.get_or_create(
        slug=slug,
        defaults={"name": name, "color": color},
    )
    if not created:
        updated_fields = []
        if layer.name != name:
            layer.name = name
            updated_fields.append("name")
        if layer.color != color:
            layer.color = color
            updated_fields.append("color")
        if updated_fields:
            layer.save(update_fields=updated_fields)

    for ext_id, defaults in feature_rows:
        if ext_id:
            LayerFeature.objects.update_or_create(
                layer=layer, external_id=ext_id, defaults=defaults
            )
        else:
            LayerFeature.objects.create(layer=layer, **defaults)
        imported += 1

    return JsonResponse({"imported": imported, "layer": slug})


@require_GET
def layer_refresh(request, slug: str):
    """Manually trigger a Celery refresh task for the named layer."""
    from app_layers.tasks import refresh_layer

    try:
        DataLayer.objects.get(slug=slug, enabled=True)
    except DataLayer.DoesNotExist:
        return JsonResponse({"error": "not found"}, status=404)

    task = refresh_layer.delay(slug)
    return JsonResponse({"task_id": task.id, "slug": slug})
