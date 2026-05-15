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
from typing import List, Optional

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


def _get_max_entries() -> int:
    """Return the configured FEED_MAX_ENTRIES value from Django settings."""
    from django.conf import settings
    return getattr(settings, "FEED_MAX_ENTRIES", 500)


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

    for src in sources:
        try:
            feed = feedparser.parse(src.url)
        except Exception as exc:
            logger.warning("feedparser error for %s: %s", src.url, exc)
            src.error_count += 1
            src.save(update_fields=["error_count"])
            continue

        new_in_source = 0
        for entry in (feed.entries or [])[:100]:
            entry_id = entry.get("id") or entry.get("link") or ""
            title = entry.get("title", "")[:500]
            summary = entry.get("summary", "")[:5000]
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
    """Extract country codes from recently fetched entries that lack geo tags."""
    from app_feeds.models import FeedEntry
    from django.utils.timezone import now, timedelta

    cutoff = now() - timedelta(hours=hours)
    qs = FeedEntry.objects.filter(
        fetched_at__gte=cutoff, geo_countries=""
    )
    tagged = 0
    for entry in qs:
        text = f"{entry.title} {entry.summary}"
        codes = _extract_country_codes(text)
        if codes:
            entry.geo_countries = ",".join(codes[:10])
            # Use centroid of first resolved country
            centroid = _CENTROIDS.get(codes[0])
            if centroid:
                entry.geo_lat, entry.geo_lon = centroid
            entry.save(update_fields=["geo_countries", "geo_lat", "geo_lon"])
            tagged += 1

    return f"geo_tag_entries: {tagged} entries tagged"


@shared_task(name="app_feeds.tasks.generate_brief")
def generate_brief(region: str, max_entries: int = 10) -> str:
    """Generate (or refresh) an intelligence brief for *region*.

    Uses Ollama when OLLAMA_HOST is set, otherwise falls back to
    extractive summarisation.
    """
    from app_feeds.models import FeedEntry, Brief
    from app_feeds.ai_briefs import generate as _gen

    # Gather recent entries mentioning the region
    entries = FeedEntry.objects.filter(
        geo_countries__icontains=region
    ).order_by("-published")[:max_entries]

    if not entries:
        return f"generate_brief: no entries for {region!r}"

    texts = [f"{e.title}: {e.summary[:300]}" for e in entries]
    content, method = _gen(region, texts)

    Brief.objects.create(region=region, content=content, method=method)
    return f"generate_brief: {method} brief created for {region!r}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _publish_redis(channel: str, payload: dict) -> None:
    """Publish a JSON message to a Redis channel (best-effort)."""
    try:
        import redis as _redis_lib
        from django.conf import settings

        r = _redis_lib.from_url(settings.CELERY_BROKER_URL)
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
