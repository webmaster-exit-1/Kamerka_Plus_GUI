"""
app_layers/tasks.py — Celery tasks for refreshing data layers.

Each layer is refreshed on its own schedule as defined in layers.json.
Fetched data is upserted into LayerFeature records.  All outbound HTTP is
cached in Redis to avoid hammering public APIs on every beat tick.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List

import requests
from celery import shared_task
from django.core.cache import cache
from django.utils import timezone

from app_layers.models import DataLayer, LayerFeature

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config", "layers.json")


def _load_config() -> List[Dict[str, Any]]:
    with open(_CONFIG_PATH) as fh:
        return json.load(fh)["layers"]


# ---------------------------------------------------------------------------
# HTTP helper with Redis cache
# ---------------------------------------------------------------------------

_HTTP_TIMEOUT = 20  # seconds


def _cached_get(url: str, ttl_seconds: int = 3600) -> Any:
    """Fetch *url* with a Redis-backed cache keyed on the URL.

    Returns the parsed JSON body or None on error.
    """
    cache_key = f"layer_fetch:{url}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached
    try:
        resp = requests.get(url, timeout=_HTTP_TIMEOUT, headers={"User-Agent": "KamerkaPlusGUI/1.0"})
        resp.raise_for_status()
        data = resp.json()
        cache.set(cache_key, data, ttl_seconds)
        return data
    except Exception as exc:
        logger.warning("layer fetch failed for %s: %s", url, exc)
        return None


# ---------------------------------------------------------------------------
# Feature parsers per layer type
# ---------------------------------------------------------------------------

def _parse_usgs_earthquakes(data: Any) -> List[Dict]:
    """Parse USGS GeoJSON FeatureCollection into flat feature dicts."""
    features = []
    if not isinstance(data, dict) or "features" not in data:
        return features
    for feat in data["features"]:
        props = feat.get("properties", {})
        geom = feat.get("geometry") or {}
        coords = geom.get("coordinates", [])
        if len(coords) < 2:
            continue
        lon, lat = float(coords[0]), float(coords[1])
        features.append({
            "external_id": feat.get("id", ""),
            "lat": lat,
            "lon": lon,
            "geometry": {"type": "Point", "coordinates": [lon, lat]},
            "properties": {
                "mag": props.get("mag"),
                "place": props.get("place", ""),
                "time": props.get("time"),
                "url": props.get("url", ""),
            },
        })
    return features


def _parse_submarine_cables(data: Any) -> List[Dict]:
    """Parse TeleGeography cable GeoJSON into flat feature dicts.

    The TeleGeography cable file wraps individual cables under a top-level
    ``cables`` key; each cable has a ``cable_name`` and ``coordinates``
    list of [lon, lat] pairs.  We store a single LineString feature per cable.
    """
    features = []
    if not isinstance(data, dict):
        return features

    # Format A: top-level "cables" list (TeleGeography cable-geo.json)
    cables = data.get("cables", [])
    if cables:
        for cable in cables:
            cid = cable.get("cable_id") or cable.get("id") or cable.get("cable_name", "")
            coords = cable.get("coordinates", [])
            if not coords:
                continue
            # coordinates may be a list of [lon, lat] pairs or a list of
            # line-segment lists; flatten to a simple list of [lon, lat].
            if coords and isinstance(coords[0], list) and isinstance(coords[0][0], list):
                # list of segments — use first segment
                flat = coords[0]
            elif coords and isinstance(coords[0], (int, float)):
                flat = [coords]
            else:
                flat = coords
            features.append({
                "external_id": str(cid),
                "lat": None,
                "lon": None,
                "geometry": {"type": "LineString", "coordinates": flat},
                "properties": {
                    "name": cable.get("cable_name", ""),
                    "rfs": cable.get("rfs", ""),
                    "owners": cable.get("owners", []),
                },
            })
        return features

    # Format B: standard GeoJSON FeatureCollection
    if data.get("type") == "FeatureCollection":
        for feat in data.get("features", []):
            props = feat.get("properties", {})
            geom = feat.get("geometry") or {}
            cid = props.get("id") or props.get("cable_id") or feat.get("id", "")
            features.append({
                "external_id": str(cid),
                "lat": None,
                "lon": None,
                "geometry": geom,
                "properties": {
                    "name": props.get("name") or props.get("cable_name", ""),
                    "rfs": props.get("rfs", ""),
                    "owners": props.get("owners", []),
                },
            })

    return features


def _parse_ioda_outages(data: Any) -> List[Dict]:
    """Parse IODA API response into point features (country centroids).

    IODA returns a dict like:
      {"data": [{"entity": {...}, "scores": [...]}]}
    We use a small lookup table of country → lat/lon for the centroid.
    """
    # Simple country-centroid table (ISO2 → lat, lon)
    _CENTROIDS = {
        "US": (38.0, -97.0), "GB": (54.0, -2.0), "DE": (51.0, 10.0),
        "FR": (46.0, 2.0), "JP": (36.0, 138.0), "CN": (35.0, 105.0),
        "RU": (60.0, 100.0), "BR": (-14.0, -51.0), "IN": (20.0, 77.0),
        "AU": (-25.0, 133.0), "CA": (56.0, -96.0), "NG": (10.0, 8.0),
        "ZA": (-29.0, 25.0), "MX": (23.0, -102.0), "SG": (1.3, 103.8),
        "UA": (49.0, 32.0), "IR": (32.0, 53.0), "PK": (30.0, 70.0),
        "TR": (39.0, 35.0), "EG": (26.0, 30.0),
    }
    features = []
    if not isinstance(data, dict):
        return features
    items = data.get("data", [])
    if not isinstance(items, list):
        return features
    for item in items:
        entity = item.get("entity") or {}
        code = (entity.get("code") or "").upper()
        centroid = _CENTROIDS.get(code)
        if not centroid:
            continue
        lat, lon = centroid
        score = 0.0
        scores_list = item.get("scores", [])
        if scores_list:
            try:
                score = float(scores_list[-1].get("score", 0) or 0)
            except (TypeError, ValueError):
                score = 0.0
        features.append({
            "external_id": f"ioda:{code}",
            "lat": lat,
            "lon": lon,
            "geometry": {"type": "Point", "coordinates": [lon, lat]},
            "properties": {
                "entity": entity.get("name", code),
                "score": score,
                "code": code,
            },
        })
    return features


def _parse_overpass(data: Any, popup_fields: List[str]) -> List[Dict]:
    """Parse OpenStreetMap Overpass API JSON into point features."""
    features = []
    if not isinstance(data, dict):
        return features
    for elem in data.get("elements", []):
        lat = elem.get("lat")
        lon = elem.get("lon")
        if lat is None or lon is None:
            continue
        tags = elem.get("tags", {})
        props = {k: tags.get(k, "") for k in popup_fields}
        features.append({
            "external_id": f"osm:{elem.get('id', '')}",
            "lat": float(lat),
            "lon": float(lon),
            "geometry": {"type": "Point", "coordinates": [float(lon), float(lat)]},
            "properties": props,
        })
    return features


# ---------------------------------------------------------------------------
# Upsert helper
# ---------------------------------------------------------------------------

def _upsert_features(layer: DataLayer, features: List[Dict]) -> int:
    """Insert or update LayerFeature rows for *layer*.

    Returns the number of features created or updated.
    """
    count = 0
    for feat in features:
        ext_id = feat.get("external_id", "")
        defaults = {
            "lat": feat.get("lat"),
            "lon": feat.get("lon"),
            "geometry": feat.get("geometry", {}),
            "properties": feat.get("properties", {}),
        }
        if ext_id:
            _, created = LayerFeature.objects.update_or_create(
                layer=layer,
                external_id=ext_id,
                defaults=defaults,
            )
        else:
            LayerFeature.objects.create(layer=layer, **defaults)
            created = True
        if created:
            count += 1
    return count


# ---------------------------------------------------------------------------
# Main refresh task
# ---------------------------------------------------------------------------

@shared_task(name="app_layers.tasks.refresh_layer", bind=True, max_retries=3)
def refresh_layer(self, slug: str) -> str:
    """Refresh all features for the DataLayer identified by *slug*.

    Called by the Celery beat schedule defined in settings.CELERY_BEAT_SCHEDULE.
    """
    try:
        layer = DataLayer.objects.get(slug=slug, enabled=True)
    except DataLayer.DoesNotExist:
        return f"layer {slug!r} not found or disabled"

    cfg_list = [c for c in _load_config() if c["slug"] == slug]
    cfg = cfg_list[0] if cfg_list else {}

    source_url = layer.source_url or cfg.get("source_url", "")
    ttl = (layer.refresh_minutes or 60) * 60

    features: List[Dict] = []

    if slug == "earthquakes":
        data = _cached_get(source_url, ttl)
        features = _parse_usgs_earthquakes(data) if data else []

    elif slug == "submarine_cables":
        data = _cached_get(source_url, ttl)
        features = _parse_submarine_cables(data) if data else []

    elif slug == "internet_outages":
        data = _cached_get(source_url, ttl)
        features = _parse_ioda_outages(data) if data else []

    elif slug in ("power_infrastructure", "critical_facilities"):
        overpass_query = (layer.renderer_config or {}).get("overpass_query") or \
                         cfg.get("renderer_config", {}).get("overpass_query", "")
        if overpass_query and source_url:
            try:
                resp = requests.post(
                    source_url,
                    data={"data": overpass_query},
                    timeout=30,
                    headers={"User-Agent": "KamerkaPlusGUI/1.0"},
                )
                resp.raise_for_status()
                popup_fields = (layer.renderer_config or {}).get("popup_fields", [])
                features = _parse_overpass(resp.json(), popup_fields)
            except Exception as exc:
                logger.warning("overpass fetch failed for %s: %s", slug, exc)

    elif slug == "ics_clusters":
        # Derived from existing Shodan Device records — no HTTP fetch needed
        from app_kamerka.models import Device

        filter_types = cfg.get("renderer_config", {}).get("filter_types", [])
        qs = Device.objects.filter(lat__isnull=False, lon__isnull=False)
        if filter_types:
            from django.db.models import Q
            q = Q()
            for t in filter_types:
                q |= Q(type__icontains=t)
            qs = qs.filter(q)

        for dev in qs:
            try:
                lat, lon = float(dev.lat), float(dev.lon)
            except (TypeError, ValueError):
                continue
            features.append({
                "external_id": f"shodan:{dev.ip}:{dev.port}",
                "lat": lat,
                "lon": lon,
                "geometry": {"type": "Point", "coordinates": [lon, lat]},
                "properties": {
                    "ip": dev.ip,
                    "type": dev.type,
                    "org": dev.org or "",
                    "city": dev.city or "",
                    "vulns": dev.vulns or "",
                },
            })

    count = _upsert_features(layer, features)
    layer.mark_refreshed()

    # Notify SSE subscribers
    try:
        from django.core.cache import cache as _cache
        import redis as _redis_lib
        _r = _redis_lib.from_url(
            __import__("django.conf", fromlist=["settings"]).settings.CELERY_BROKER_URL
        )
        _r.publish("layer_updated", json.dumps({"slug": slug, "count": count}))
    except Exception:
        pass

    return f"refreshed {slug}: {count} new features, {len(features)} total"


@shared_task(name="app_layers.tasks.refresh_all_layers")
def refresh_all_layers() -> str:
    """Trigger refresh for every enabled DataLayer."""
    layers = DataLayer.objects.filter(enabled=True)
    results = []
    for layer in layers:
        result = refresh_layer(layer.slug)
        results.append(result)
    return "; ".join(results)
