# WorldMonitor Integration — Gap Analysis & Architecture

## Overview

This document describes the integration of WorldMonitor-inspired features into
Kamerka Plus GUI.  WorldMonitor (https://github.com/koala73/worldmonitor) is an
open-source AGPL-3 geopolitical intelligence dashboard with ~45 toggleable data
layers, real-time news/finance feeds, and AI-synthesised briefs.

**Important:** No WorldMonitor source code is copied or derived here.  Only the
concept of declarative data-layer configuration and multi-panel UX patterns are
reused.  All implementation is original.  If you distribute a build that
incorporates any WorldMonitor code directly, AGPL-3 obligations apply.

---

## Overlap

| Feature | Kamerka | WorldMonitor |
|---------|---------|--------------|
| 3D globe | PyVista/PyQt6 + Three.js (web) | Three.js |
| 2D map | Leaflet | Leaflet / MapboxGL |
| Geolocation enrichment | MaxMind + WHOIS | MaxMind |
| Device markers | Shodan result spikes | Custom icons |
| Export | KML, CSV, GeoJSON | GeoJSON |

---

## Gaps filled by this integration

| Feature | Source inspiration | Implementation |
|---------|-------------------|----------------|
| Earthquakes layer | WorldMonitor | USGS GeoJSON feed (public, free) |
| Internet outages layer | WorldMonitor | IODA/CAIDA API (public, free) |
| Submarine cables layer | WorldMonitor | TeleGeography open dataset |
| Critical infrastructure | WorldMonitor | OpenStreetMap Overpass API |
| Power grids | WorldMonitor | Open Infrastructure Map |
| ICS clusters | Kamerka-specific | Derived from Shodan results |
| RSS/news feed ingestion | WorldMonitor (500+ feeds) | feedparser — 50 curated OSINT feeds |
| AI-synthesised briefs | WorldMonitor (local LLM) | Ollama HTTP API; extractive fallback |
| Real-time updates | WorldMonitor WebSocket | Server-Sent Events (SSE) |
| Risk scoring | WorldMonitor Country Index | Weighted scoring in `enrichment.py` |
| i18n | WorldMonitor (21 languages) | Django i18n — 6 priority languages |
| Resizable panels | WorldMonitor UI | Collapsible sidebar in Django templates |

---

## Architecture

### New Django apps

```
app_layers/   — Data layer system (models, Celery tasks, REST endpoints)
app_feeds/    — RSS/news feed ingestion, AI briefs, SSE streaming
```

### Data flow

```
Celery Beat → app_layers.tasks.refresh_layer()
                    → fetch public API (USGS / OSM / TeleGeography …)
                    → upsert LayerFeature records in SQLite
                    → redis.publish("layer_updated", layer_slug)

Celery Beat → app_feeds.tasks.refresh_feeds()
                    → feedparser fetches each FeedSource URL
                    → upsert FeedEntry records
                    → pycountry extracts mentioned countries
                    → redis.publish("feed_updated", entry_pk)

Browser     → GET /api/feeds/entries/sse/
                    → long-lived HTTP response (text/event-stream)
                    → Django view subscribes to Redis channels
                    → streams events to browser JS

Browser     → GET /api/layers/<slug>/features.json?bbox=min_lon,min_lat,max_lon,max_lat
                    → returns LayerFeature GeoJSON FeatureCollection
                    → Leaflet layer control adds/removes layer (viewport-filtered)

Browser     → POST /api/layers/import/
                    → accepts GeoJSON FeatureCollection
                    → creates DataLayer + LayerFeature records

Browser     → GET /api/export/geojson/<search_id>
                    → Kamerka Device records as GeoJSON FeatureCollection
                    → compatible with Kepler.gl, QGIS, WorldMonitor seeds
```

### Risk scoring formula (`app_kamerka/enrichment.py`)

```
base_score  = min(vuln_count * 8, 40)              # 0-40 from vulns
infra_bonus = 15 if nearby_critical_infra else 0   # proximity bonus
feed_bonus  = 15 if country_in_recent_alerts else 0 # threat intel bonus
hp_penalty  = -20 if likely_honeypot else 0        # honeypot deduction
risk_score  = clamp(base_score + infra_bonus + feed_bonus + hp_penalty, 0, 100)
```

---

## Layer configuration format (`app_layers/config/layers.json`)

Each layer entry:

```json
{
  "slug": "earthquakes",
  "name": "Earthquakes (USGS)",
  "layer_type": "point",
  "source_url": "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/significant_week.geojson",
  "refresh_minutes": 60,
  "color": "#ff6600",
  "icon": "⚡",
  "enabled": true,
  "renderer_config": {
    "min_magnitude": 4.0,
    "popup_fields": ["mag", "place", "time", "url"]
  }
}
```

---

## Installation & Usage

See `docs/INSTALL.md` for full setup instructions including the new
Celery beat schedule configuration.

### Quick start for new features

```bash
# Install new Python dependencies
pip install -r requirements.txt

# Apply new migrations
python manage.py migrate

# Seed default data layers and feed sources
python manage.py seed_layers
python manage.py seed_feeds

# Start Celery with beat scheduler (required for periodic refresh)
celery --app kamerka worker --beat --loglevel=info

# Set optional Ollama host for AI briefs
export OLLAMA_HOST=http://localhost:11434
```

---

## Licence note

All code in this repository is licensed under the project's existing licence.
WorldMonitor data-layer concepts and UX patterns are re-implemented from
scratch.  No AGPL-3 code is present.
