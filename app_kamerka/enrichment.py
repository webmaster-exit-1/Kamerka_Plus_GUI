"""
app_kamerka/enrichment.py — Device risk scoring and layer context enrichment.

Risk score formula (0–100)
--------------------------
base_score  = min(vuln_count * 8, 40)           # up to 40 from CVE count
infra_bonus = 15 if nearby critical-infra layer  # proximity to power/facility
feed_bonus  = 15 if country in recent alerts     # threat intel match
kev_bonus   = 15 if any CVE is CISA KEV listed   # known exploited
hp_penalty  = -20 if likely honeypot             # deduct for honeypots
risk_score  = clamp(sum, 0, 100)

Public API
----------
compute_risk_score(device_id: int) -> int
enrich_device_context(device_id: int) -> dict
"""
from __future__ import annotations

import json
import logging
import math
from typing import Any, Dict

logger = logging.getLogger(__name__)

# Maximum distance (degrees) to consider a layer feature "nearby"
_PROXIMITY_DEG = 1.0  # ~111 km per degree


def _parse_vuln_count(vulns_field: str) -> int:
    """Return the number of CVEs stored in Device.vulns."""
    if not vulns_field:
        return 0
    try:
        lst = json.loads(vulns_field.replace("'", '"'))
        return len(lst) if isinstance(lst, list) else 0
    except (json.JSONDecodeError, ValueError):
        # Fallback: count CVE- occurrences
        return vulns_field.count("CVE-")


def _nearby_critical_infra(lat: float, lon: float) -> bool:
    """Return True when a critical-infrastructure LayerFeature exists within
    _PROXIMITY_DEG degrees of (lat, lon)."""
    try:
        from app_layers.models import LayerFeature

        return LayerFeature.objects.filter(
            layer__slug__in=["critical_facilities", "power_infrastructure", "ics_clusters"],
            lat__range=(lat - _PROXIMITY_DEG, lat + _PROXIMITY_DEG),
            lon__range=(lon - _PROXIMITY_DEG, lon + _PROXIMITY_DEG),
        ).exists()
    except Exception:
        return False


def _country_in_recent_alerts(country_code: str) -> bool:
    """Return True if *country_code* appears in a recent FeedEntry."""
    if not country_code:
        return False
    try:
        from app_feeds.models import FeedEntry
        from django.utils.timezone import now, timedelta

        cutoff = now() - timedelta(days=7)
        return FeedEntry.objects.filter(
            published__gte=cutoff,
            geo_countries__icontains=country_code,
        ).exists()
    except Exception:
        return False


def _has_kev_vuln(device_id: int) -> bool:
    """Return True if the device has at least one CISA KEV-listed CVE."""
    try:
        from app_kamerka.models import VulnIntelligence

        return VulnIntelligence.objects.filter(
            device_id=device_id, kev_listed=True
        ).exists()
    except Exception:
        return False


def _is_likely_honeypot(device_id: int) -> bool:
    """Return True if the device has a high honeypot probability."""
    try:
        from app_kamerka.models import HoneypotAnalysis

        hp = HoneypotAnalysis.objects.filter(device_id=device_id).first()
        return hp is not None and hp.probability >= 0.7
    except Exception:
        return False


def compute_risk_score(device_id: int) -> int:
    """Compute and return the risk score (0–100) for device *device_id*."""
    from app_kamerka.models import Device

    try:
        dev = Device.objects.get(pk=device_id)
    except Device.DoesNotExist:
        return 0

    vuln_count = _parse_vuln_count(dev.vulns)
    base_score = min(vuln_count * 8, 40)

    lat = lon = None
    try:
        lat = float(dev.lat)
        lon = float(dev.lon)
    except (TypeError, ValueError):
        pass

    infra_bonus = 15 if (lat is not None and lon is not None and _nearby_critical_infra(lat, lon)) else 0
    feed_bonus = 15 if _country_in_recent_alerts(dev.country_code) else 0
    kev_bonus = 15 if _has_kev_vuln(device_id) else 0
    hp_penalty = -20 if _is_likely_honeypot(device_id) else 0

    score = base_score + infra_bonus + feed_bonus + kev_bonus + hp_penalty
    return max(0, min(100, score))


def build_layer_context(device_id: int) -> Dict[str, Any]:
    """Build a JSON-serialisable context dict for *device_id*.

    Contains:
    - nearby_infra: list of slugs of nearby critical infrastructure layers
    - recent_alerts: bool — country has recent threat-intel feed entries
    - kev_listed: bool — at least one KEV vuln on the device
    - likely_honeypot: bool
    """
    from app_kamerka.models import Device

    try:
        dev = Device.objects.get(pk=device_id)
    except Device.DoesNotExist:
        return {}

    lat = lon = None
    try:
        lat = float(dev.lat)
        lon = float(dev.lon)
    except (TypeError, ValueError):
        pass

    nearby_infra: list = []
    if lat is not None and lon is not None:
        try:
            from app_layers.models import LayerFeature

            slugs = (
                LayerFeature.objects.filter(
                    layer__slug__in=[
                        "critical_facilities",
                        "power_infrastructure",
                        "ics_clusters",
                    ],
                    lat__range=(lat - _PROXIMITY_DEG, lat + _PROXIMITY_DEG),
                    lon__range=(lon - _PROXIMITY_DEG, lon + _PROXIMITY_DEG),
                )
                .values_list("layer__slug", flat=True)
                .distinct()
            )
            nearby_infra = list(slugs)
        except Exception:
            pass

    return {
        "nearby_infra": nearby_infra,
        "recent_alerts": _country_in_recent_alerts(dev.country_code),
        "kev_listed": _has_kev_vuln(device_id),
        "likely_honeypot": _is_likely_honeypot(device_id),
    }
