"""
app_feeds/tasks.py — Celery tasks for feed ingestion and AI brief generation.

Tasks
-----
refresh_feeds        — fetch all active FeedSource URLs via feedparser (hourly)
geo_tag_entries      — extract ISO-2 country codes from recent entry text
generate_brief       — produce an extractive or Ollama brief for a region
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
from collections import OrderedDict, defaultdict
from typing import Dict, List, Optional, Tuple

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)

# Country centroid lookup (ISO-2 → lat, lon)
_CENTROIDS = {
    "US": (38.0, -97.0), "GB": (54.0, -2.0), "DE": (51.0, 10.0),
    "FR": (46.0, 2.0), "JP": (36.0, 138.0), "CN": (35.0, 105.0),
    "RU": (60.0, 100.0), "BR": (-14.0, -51.0), "IN": (20.0, 77.0),
    "AU": (-25.0, 133.0), "CA": (56.0, -96.0), "NG": (10.0, 8.0),
    "ZA": (-29.0, 25.0), "MX": (23.0, -102.0), "SG": (1.3, 103.8),
    "UA": (49.0, 32.0), "IR": (32.0, 53.0), "PK": (30.0, 70.0),
    "TR": (39.0, 35.0), "EG": (26.0, 30.0), "SA": (24.0, 45.0),
    "IL": (31.5, 34.75), "KR": (37.0, 127.5), "ID": (-5.0, 120.0),
    "PH": (13.0, 122.0), "VN": (16.0, 108.0),
}

_MAX_ENTRIES = None  # resolved lazily from settings to respect runtime config
_NOMINATIM_GEOCODER = None
_GEOCODE_CACHE: "OrderedDict[str, Optional[Tuple[float, float]]]" = OrderedDict()
_TRANSLATION_CACHE: "OrderedDict[str, str]" = OrderedDict()
_MAX_GEOCODE_CACHE_SIZE = 2000
_MAX_TRANSLATION_CACHE_SIZE = 4000
GLOBAL_BRIEF_ALIASES = {"GLOBAL", "ALL", "WORLD", "*"}
_CACHE_LOCK = threading.Lock()

_COORDINATE_PATTERN = re.compile(
    r"(?P<lat>[+-]?(?:90(?:\.0+)?|[1-8]?\d(?:\.\d+)?))\s*[,/]\s*"
    r"(?P<lon>[+-]?(?:180(?:\.0+)?|1[0-7]\d(?:\.\d+)?|[1-9]?\d(?:\.\d+)?))"
)
_ADDRESS_PATTERN = re.compile(
    r"\b\d{1,5}\s+[A-Za-z0-9][A-Za-z0-9\s.\-]{3,80}\s"
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Place|Pl|Court|Ct)\b"
    r"(?:,\s*[A-Za-z][A-Za-z\s.\-]{1,40}){0,3}",
    flags=re.IGNORECASE,
)
_NON_LATIN_PATTERN = re.compile(r"[^\x00-\x7F]")


def _get_max_entries() -> int:
    """Return the configured FEED_MAX_ENTRIES value from Django settings."""
    from django.conf import settings
    return getattr(settings, "FEED_MAX_ENTRIES", 500)


def _get_max_translation_calls() -> int:
    from django.conf import settings

    return int(getattr(settings, "FEED_TRANSLATION_MAX_CALLS", 60))


def _get_translation_endpoint() -> str:
    from django.conf import settings

    return str(
        getattr(
            settings,
            "FEED_TRANSLATE_URL",
            "https://translate.argosopentech.com/translate",
        )
    ).strip()


def _extract_country_codes(text: str) -> List[str]:
    """Extract ISO-2 country codes mentioned in *text* using pycountry."""
    try:
        import pycountry
    except ImportError:
        return []

    found = []
    text_lower = text.lower()
    for country in pycountry.countries:
        # Match official name or common name (case-insensitive, word boundary)
        names = [country.name.lower()]
        if hasattr(country, "common_name"):
            names.append(country.common_name.lower())
        for name in names:
            if re.search(r"\b" + re.escape(name) + r"\b", text_lower):
                found.append(country.alpha_2)
                break
    return list(dict.fromkeys(found))  # deduplicate, preserve order


def _is_probably_english(text: str, language_hint: str = "") -> bool:
    hint = (language_hint or "").strip().lower()
    if hint.startswith("en"):
        return True
    if not text:
        return True
    non_latin = len(_NON_LATIN_PATTERN.findall(text))
    if non_latin > 0:
        return False
    tokens = re.findall(r"[a-z]+", text.lower())
    if not tokens:
        return True
    common_en = {
        "the", "and", "for", "with", "from", "this", "that", "security",
        "attack", "vulnerability", "threat", "update", "report", "cyber",
    }
    hits = sum(1 for token in tokens if token in common_en)
    return hits >= 2 or (hits >= 1 and len(tokens) < 12)


def _bounded_cache_set(cache_obj: OrderedDict, key: str, value, max_size: int) -> None:
    with _CACHE_LOCK:
        cache_obj[key] = value
        cache_obj.move_to_end(key)
        while len(cache_obj) > max_size:
            cache_obj.popitem(last=False)


def _translate_to_english(
    text: str, language_hint: str = "", budget: Optional[Dict[str, int]] = None
) -> str:
    text = (text or "").strip()
    if not text:
        return text
    if _is_probably_english(text, language_hint):
        return text
    cache_key = f"{language_hint}|{text[:1000]}"
    with _CACHE_LOCK:
        cached = _TRANSLATION_CACHE.get(cache_key)
        if cached is not None:
            _TRANSLATION_CACHE.move_to_end(cache_key)
    if cached is not None:
        return cached
    if budget is not None and budget.get("remaining", 0) <= 0:
        return text

    try:
        import requests

        endpoint = _get_translation_endpoint()
        if not endpoint:
            return text
        response = requests.post(
            endpoint,
            json={
                "q": text[:4500],
                "source": "auto",
                "target": "en",
                "format": "text",
            },
            timeout=6,
        )
        response.raise_for_status()
        payload = response.json()
        translated = str(payload.get("translatedText") or "").strip()
        if translated:
            _bounded_cache_set(_TRANSLATION_CACHE, cache_key, translated, _MAX_TRANSLATION_CACHE_SIZE)
            if budget is not None:
                budget["remaining"] = max(0, budget.get("remaining", 0) - 1)
            return translated
    except Exception:
        logger.debug("Feed translation failed", exc_info=True)

    if budget is not None:
        budget["remaining"] = max(0, budget.get("remaining", 0) - 1)
    _bounded_cache_set(_TRANSLATION_CACHE, cache_key, text, _MAX_TRANSLATION_CACHE_SIZE)
    return text


@shared_task(name="app_feeds.tasks.refresh_feeds", bind=True, max_retries=2)
def refresh_feeds(self) -> str:
    """Fetch all active FeedSource URLs and upsert new FeedEntry records."""
    try:
        import feedparser
    except ImportError:
        return "feedparser not installed — pip install feedparser"

    from app_feeds.models import FeedSource, FeedEntry

    sources = FeedSource.objects.filter(active=True)
    total_new = 0
    translation_budget = {"remaining": _get_max_translation_calls()}

    for src in sources:
        try:
            feed = feedparser.parse(src.url)
        except Exception as exc:
            logger.warning("feedparser error for %s: %s", src.url, exc)
            src.error_count += 1
            src.save(update_fields=["error_count"])
            continue

        new_in_source = 0
        feed_language_hint = ""
        try:
            feed_language_hint = (
                feed.get("feed", {}).get("language")
                or feed.get("headers", {}).get("content-language")
                or ""
            )
        except Exception:
            feed_language_hint = ""
        for entry in (feed.entries or [])[:100]:
            entry_id = entry.get("id") or entry.get("link") or ""
            from app_feeds.text_utils import html_to_plain

            title = html_to_plain(entry.get("title", ""), max_len=500)
            summary = html_to_plain(entry.get("summary", ""), max_len=5000)
            entry_language_hint = entry.get("language") or feed_language_hint
            title = _translate_to_english(title, entry_language_hint, budget=translation_budget)[:500]
            summary = _translate_to_english(summary, entry_language_hint, budget=translation_budget)[:5000]
            url = entry.get("link", "")[:500]

            # Parse published date
            published = None
            if entry.get("published_parsed"):
                import time
                import datetime
                t = entry.published_parsed
                try:
                    published = timezone.make_aware(
                        datetime.datetime(*t[:6]),
                        timezone.utc,
                    )
                except Exception:
                    pass

            defaults = {
                "title": title,
                "summary": summary,
                "url": url,
                "published": published,
            }

            if entry_id:
                fe, created = FeedEntry.objects.get_or_create(
                    source=src,
                    entry_id=entry_id[:500],
                    defaults=defaults,
                )
            else:
                # No stable id — deduplicate by title+source
                fe, created = FeedEntry.objects.get_or_create(
                    source=src,
                    title=title,
                    defaults=defaults,
                )

            if created:
                new_in_source += 1

        src.error_count = 0
        src.last_fetched = timezone.now()
        src.save(update_fields=["error_count", "last_fetched"])
        total_new += new_in_source

    # Publish to Redis for SSE subscribers
    _publish_redis("feed_updated", {"total_new": total_new})

    # Cap total entries
    _prune_old_entries()

    return f"refresh_feeds: {total_new} new entries across {sources.count()} sources"

@shared_task(name="app_feeds.tasks.geo_tag_entries")
def geo_tag_entries(hours: int = 24) -> str:
    """Extract country codes and coordinates from recently fetched feed entries."""
    from app_feeds.models import FeedEntry
    from app_feeds.text_utils import html_to_plain
    from django.db.models import Q
    from django.utils.timezone import now, timedelta

    cutoff = now() - timedelta(hours=hours)
    qs = FeedEntry.objects.filter(fetched_at__gte=cutoff).filter(
        Q(geo_countries="") | Q(geo_lat__isnull=True) | Q(geo_lon__isnull=True)
    )
    tagged = 0
    mapped = 0
    for entry in qs:
        text = html_to_plain(f"{entry.title} {entry.summary}", max_len=8000)
        updated_fields = []

        if not entry.geo_countries:
            codes = _extract_country_codes(text)
            if codes:
                entry.geo_countries = ",".join(codes[:10])
                updated_fields.append("geo_countries")
                tagged += 1

        if entry.geo_lat is None or entry.geo_lon is None:
            coords = _extract_coordinate_pair(text)
            if not coords:
                address = _extract_address_candidate(text)
                if address:
                    coords = _geocode_address(address)
            if not coords and entry.geo_countries:
                first_code = entry.geo_countries.split(",")[0].strip().upper()
                coords = _CENTROIDS.get(first_code)
            if coords:
                entry.geo_lat, entry.geo_lon = coords
                updated_fields.extend(["geo_lat", "geo_lon"])
                mapped += 1

        if updated_fields:
            entry.save(update_fields=sorted(set(updated_fields)))

    return f"geo_tag_entries: {tagged} entries tagged, {mapped} entries mapped"


@shared_task(name="app_feeds.tasks.generate_brief")
def generate_brief(region: str, max_entries: int = 10) -> str:
    """Generate (or refresh) an intelligence brief for *region*.

    Uses Ollama when OLLAMA_HOST is set, otherwise falls back to
    extractive summarisation. Always persists a Brief so the UI can
    leave the pending state (even when no feed rows match).
    """
    from app_feeds.models import FeedEntry, Brief
    from app_feeds.ai_briefs import generate as _gen

    region = (region or "").strip().upper()
    is_global = _is_global_region(region)
    brief_scope = "GLOBAL" if is_global else region
    try:
        if is_global:
            entries = _entries_for_global(max_entries=max(max_entries, 40))
        else:
            entries = _entries_for_region(region, max_entries=max_entries)
        if not entries:
            content = _empty_brief_message(brief_scope)
            Brief.objects.create(region=brief_scope, content=content, method="empty")
            return f"generate_brief: empty brief for {brief_scope!r}"

        from app_feeds.text_utils import html_to_plain

        texts = [
            f"{html_to_plain(e.title)}: {html_to_plain(e.summary, max_len=300)}"
            for e in entries
        ]
        content, method = _gen(brief_scope, texts)
        Brief.objects.create(region=brief_scope, content=content, method=method)
        return f"generate_brief: {method} brief created for {brief_scope!r}"
    finally:
        _clear_brief_pending(brief_scope)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _brief_pending_key(region: str) -> str:
    return f"brief_pending:{(region or '').strip().upper()}"


def mark_brief_pending(region: str, ttl: int = 300) -> None:
    """Mark a region brief as in-flight (avoids duplicate Celery jobs on poll)."""
    from django.core.cache import cache

    cache.set(_brief_pending_key(region), True, timeout=ttl)


def _clear_brief_pending(region: str) -> None:
    from django.core.cache import cache

    cache.delete(_brief_pending_key(region))


def is_brief_pending(region: str) -> bool:
    from django.core.cache import cache

    return bool(cache.get(_brief_pending_key(region)))


def _region_search_terms(region: str) -> List[str]:
    region = (region or "").strip().upper()
    terms = [region]
    try:
        import pycountry

        country = pycountry.countries.get(alpha_2=region)
        if country:
            terms.append(country.name)
            common = getattr(country, "common_name", None)
            if common:
                terms.append(common)
    except Exception:
        pass
    return [t for t in terms if t]


def _is_global_region(region: str) -> bool:
    normalized = (region or "").strip().upper()
    return normalized in GLOBAL_BRIEF_ALIASES


def _entries_for_region(region: str, max_entries: int = 10) -> list:
    """Feed rows for a region: geo tag first, then title/summary keyword match."""
    from django.db.models import Q

    from app_feeds.models import FeedEntry

    region = (region or "").strip().upper()
    tagged = FeedEntry.objects.filter(geo_countries__icontains=region).order_by(
        "-published"
    )
    if tagged.exists():
        return list(tagged[:max_entries])

    q = Q()
    for term in _region_search_terms(region):
        q |= Q(title__icontains=term) | Q(summary__icontains=term)
    if not q:
        return []
    return list(FeedEntry.objects.filter(q).order_by("-published")[:max_entries])


def _entries_for_global(max_entries: int = 40) -> list:
    """Prioritize up to 2 cyber entries per country, then fill with latest entries."""
    from app_feeds.models import FeedEntry

    max_entries = max(10, max_entries)
    selected = []
    selected_ids = set()
    fallback = []
    per_country_cyber = defaultdict(int)
    recent_entries = (
        FeedEntry.objects.select_related("source")
        .exclude(title="")
        .order_by("-published", "-id")[:500]
    )

    for entry in recent_entries:
        if not entry.source:
            fallback.append(entry)
            continue
        countries = [
            code.strip().upper()
            for code in (entry.geo_countries or "").split(",")
            if len(code.strip()) == 2 and code.strip().isalpha()
        ] or ["GLOBAL"]

        if entry.source.category == "cyber":
            needed_country = next((c for c in countries if per_country_cyber[c] < 2), None)
            if needed_country and entry.pk not in selected_ids:
                selected.append(entry)
                selected_ids.add(entry.pk)
                per_country_cyber[needed_country] += 1
                if len(selected) >= max_entries:
                    break
                continue
        fallback.append(entry)

    for entry in fallback:
        if entry.pk in selected_ids:
            continue
        selected.append(entry)
        selected_ids.add(entry.pk)
        if len(selected) >= max_entries:
            break

    return selected[:max_entries]


def _empty_brief_message(region: str) -> str:
    from app_feeds.models import FeedEntry

    region = (region or "").strip().upper()
    total = FeedEntry.objects.count()
    if total == 0:
        try:
            import feedparser  # noqa: F401
        except ImportError:
            return (
                f"No intelligence brief available for {region}.\n\n"
                "RSS ingestion is disabled: install feedparser "
                "(pip install feedparser) and restart the Celery worker, "
                "then run refresh_feeds or wait for the hourly feed task."
            )
        return (
            f"No intelligence brief available for {region}.\n\n"
            "The feed database is empty. Run refresh_feeds or wait for the "
            "hourly Celery task to pull RSS sources."
        )
    if _is_global_region(region):
        return (
            "No feed articles are available for the global briefing.\n\n"
            "Run refresh_feeds or wait for the hourly Celery task, then "
            "allow geo_tag_entries to map countries and coordinates."
        )
    return (
        f"No feed articles matched region {region}.\n\n"
        "Entries may lack geo tags — geo_tag_entries runs hourly. "
        "Try another region from the dropdown or refresh feeds."
    )


def _extract_coordinate_pair(text: str) -> Optional[Tuple[float, float]]:
    for match in _COORDINATE_PATTERN.finditer(text or ""):
        try:
            lat = float(match.group("lat"))
            lon = float(match.group("lon"))
        except (TypeError, ValueError):
            continue
        if -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0:
            return lat, lon
    return None


def _extract_address_candidate(text: str) -> Optional[str]:
    match = _ADDRESS_PATTERN.search(text or "")
    if not match:
        return None
    return match.group(0).strip()


def _geocode_address(address: str) -> Optional[Tuple[float, float]]:
    if not address:
        return None
    with _CACHE_LOCK:
        if address in _GEOCODE_CACHE:
            _GEOCODE_CACHE.move_to_end(address)
            return _GEOCODE_CACHE[address]

    global _NOMINATIM_GEOCODER
    try:
        if _NOMINATIM_GEOCODER is None:
            with _CACHE_LOCK:
                if _NOMINATIM_GEOCODER is None:
                    from geopy.geocoders import Nominatim

                    _NOMINATIM_GEOCODER = Nominatim(user_agent="kamerka_feeds_geo")
        location = _NOMINATIM_GEOCODER.geocode(address, timeout=5)
        if location:
            coords = (float(location.latitude), float(location.longitude))
            _bounded_cache_set(_GEOCODE_CACHE, address, coords, _MAX_GEOCODE_CACHE_SIZE)
            return coords
    except Exception:
        logger.debug("Failed to geocode address: %s", address)

    _bounded_cache_set(_GEOCODE_CACHE, address, None, _MAX_GEOCODE_CACHE_SIZE)
    return None


def _publish_redis(channel: str, payload: dict) -> None:
    """Publish a JSON message to a Redis channel (best-effort)."""
    try:
        import redis as _redis_lib
        from django.conf import settings

        r = _redis_lib.from_url(settings.REDIS_URL)
        r.publish(channel, json.dumps(payload))
    except Exception:
        pass


def _prune_old_entries() -> None:
    """Keep only the most recent FEED_MAX_ENTRIES FeedEntry rows."""
    from app_feeds.models import FeedEntry

    max_entries = _get_max_entries()
    total = FeedEntry.objects.count()
    if total > max_entries:
        cutoff_id = (
            FeedEntry.objects.order_by("-fetched_at")
            .values_list("id", flat=True)[max_entries - 1 : max_entries]
        )
        if cutoff_id:
            FeedEntry.objects.filter(id__lt=cutoff_id[0]).delete()
