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
import logging

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_http_methods

from app_layers.models import DataLayer, LayerFeature

logger = logging.getLogger(__name__)


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
        layer = DataLayer.objects.get(slug=slug)
    except DataLayer.DoesNotExist:
        return JsonResponse({"error": "not found"}, status=404)

    features = []
    for feat in layer.features.all():
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


@csrf_exempt
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
    try:
        payload = json.loads(request.body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse({"error": "invalid JSON"}, status=400)

    slug = payload.get("slug", "")
    name = payload.get("name", slug)
    color = payload.get("color", "#ffffff")

    if not slug:
        return JsonResponse({"error": "slug is required"}, status=400)

    layer, _ = DataLayer.objects.get_or_create(
        slug=slug,
        defaults={"name": name, "color": color},
    )

    fc = payload.get("features") or {}
    imported = 0
    for feat in fc.get("features", []):
        geom = feat.get("geometry") or {}
        props = feat.get("properties") or {}
        coords = geom.get("coordinates", [])
        lat = lon = None
        if geom.get("type") == "Point" and len(coords) >= 2:
            lon, lat = float(coords[0]), float(coords[1])
        ext_id = str(props.get("id", ""))
        defaults = {
            "lat": lat,
            "lon": lon,
            "geometry": geom,
            "properties": props,
        }
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
        return JsonResponse({"error": "not found or disabled"}, status=404)

    task = refresh_layer.delay(slug)
    return JsonResponse({"task_id": task.id, "slug": slug})
