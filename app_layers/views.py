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

from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_http_methods

from app_layers.models import DataLayer, LayerFeature


def _require_staff(request):
    """Return a 403 JSON response unless the requester is an authenticated staff user."""
    if request.user.is_authenticated and request.user.is_staff:
        return None
    return JsonResponse({"error": "Permission denied. Staff access required."}, status=403)


def _iter_lon_lat_pairs(node):
    """Yield ``(lon, lat)`` pairs from a GeoJSON coordinates tree."""
    if not isinstance(node, (list, tuple)):
        return
    if len(node) >= 2 and all(isinstance(v, (int, float)) for v in node[:2]):
        yield float(node[0]), float(node[1])
        return
    for item in node:
        yield from _iter_lon_lat_pairs(item)


def _geometry_intersects_bbox(geometry, bbox):
    """Return True if any coordinate in *geometry* falls within *bbox*."""
    if not isinstance(geometry, dict):
        return False
    min_lon, min_lat, max_lon, max_lat = bbox
    for lon, lat in _iter_lon_lat_pairs(geometry.get("coordinates")):
        if min_lon <= lon <= max_lon and min_lat <= lat <= max_lat:
            return True
    return False


def _parse_bbox(raw_bbox: str):
    """Parse ``min_lon,min_lat,max_lon,max_lat`` query parameter."""
    try:
        parts = [float(p.strip()) for p in (raw_bbox or "").split(",")]
    except ValueError:
        return None
    if len(parts) != 4:
        return None
    min_lon, min_lat, max_lon, max_lat = parts
    if min_lon >= max_lon or min_lat >= max_lat:
        return None
    return min_lon, min_lat, max_lon, max_lat


@require_GET
def layer_list(request):
    """Return metadata for all enabled layers as JSON."""
    layers = DataLayer.objects.filter(enabled=True)
    data = [
        {
            "slug": l.slug,
            "name": l.name,
            "layer_type": l.layer_type,
            "color": l.color,
            "icon": l.icon,
            "last_refreshed": l.last_refreshed.isoformat() if l.last_refreshed else None,
        }
        for l in layers
    ]
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

    return JsonResponse(
        {
            "type": "FeatureCollection",
            "features": features,
            "layer": {
                "slug": layer.slug,
                "name": layer.name,
                "color": layer.color,
                "icon": layer.icon,
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
