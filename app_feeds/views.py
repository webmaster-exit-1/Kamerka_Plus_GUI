"""
app_feeds/views.py — Feed panel, SSE endpoint, brief API.

Endpoints
---------
GET  /api/feeds/entries/           — recent feed entries (JSON), optionally filtered by country
GET  /api/feeds/entries/sse/       — Server-Sent Events stream for live updates
GET  /api/feeds/brief/<region>/    — latest brief for a region (triggers generation if absent)
POST /api/feeds/brief/<region>/generate/  — force-regenerate brief
"""
from __future__ import annotations

import json
import logging
import time

from django.conf import settings
from django.http import HttpResponse, JsonResponse, StreamingHttpResponse
from django.utils.timezone import now, timedelta
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from app_feeds.models import Brief, FeedEntry, FeedSource

logger = logging.getLogger(__name__)


@require_GET
def feed_entries(request):
    """Return recent feed entries as JSON.

    Query params
    ------------
    country : ISO-2 code to filter by geo_countries (optional)
    limit   : max results (default 50, max 200)
    """
    country = request.GET.get("country", "").strip().upper()
    try:
        limit = min(int(request.GET.get("limit", 50)), 200)
    except (ValueError, TypeError):
        limit = 50

    qs = FeedEntry.objects.select_related("source").order_by("-published")
    if country:
        qs = qs.filter(geo_countries__icontains=country)

    entries = []
    for e in qs[:limit]:
        entries.append({
            "id": e.pk,
            "title": e.title,
            "summary": e.summary[:300],
            "url": e.url,
            "published": e.published.isoformat() if e.published else None,
            "source": e.source.name,
            "category": e.source.category,
            "geo_countries": e.geo_countries,
            "geo_lat": e.geo_lat,
            "geo_lon": e.geo_lon,
        })

    return JsonResponse({"entries": entries, "count": len(entries)})


def feed_sse(request):
    """Server-Sent Events stream for real-time feed and layer update notifications.

    The browser subscribes once; the view holds the connection open and
    forwards messages from the Redis ``feed_updated`` and ``layer_updated``
    pub/sub channels.

    Falls back to a 30-second heartbeat loop when Redis is unavailable so the
    browser does not retry-spam the server.
    """
    def _event_stream():
        try:
            import redis as _redis_lib

            r = _redis_lib.from_url(settings.CELERY_BROKER_URL)
            pubsub = r.pubsub()
            pubsub.subscribe("feed_updated", "layer_updated")

            # Send a heartbeat every 30 s while waiting for messages
            last_heartbeat = time.time()
            for message in pubsub.listen():
                if message["type"] == "message":
                    channel = message["channel"]
                    if isinstance(channel, bytes):
                        channel = channel.decode()
                    data = message["data"]
                    if isinstance(data, bytes):
                        data = data.decode()
                    yield f"event: {channel}\ndata: {data}\n\n"

                now_ts = time.time()
                if now_ts - last_heartbeat > 30:
                    yield ": heartbeat\n\n"
                    last_heartbeat = now_ts

        except Exception as exc:
            logger.debug("SSE Redis error: %s", exc)
            # Send a single comment so the client knows the stream is alive,
            # then close — the browser's EventSource will reconnect.
            yield ": redis unavailable\n\n"

    response = StreamingHttpResponse(
        _event_stream(), content_type="text/event-stream"
    )
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return response


@require_GET
def brief_view(request, region: str):
    """Return the latest brief for *region*, generating one if none exists."""
    brief = Brief.objects.filter(region=region).order_by("-generated_at").first()
    if not brief:
        # Trigger async generation and return a placeholder
        from app_feeds.tasks import generate_brief
        generate_brief.delay(region)
        return JsonResponse(
            {"region": region, "content": "Generating brief…", "method": "pending"},
            status=202,
        )
    return JsonResponse(
        {
            "region": brief.region,
            "content": brief.content,
            "method": brief.method,
            "generated_at": brief.generated_at.isoformat(),
        }
    )


@csrf_exempt
@require_POST
def brief_generate(request, region: str):
    """Force-regenerate an intelligence brief for *region*."""
    from app_feeds.tasks import generate_brief

    task = generate_brief.delay(region)
    return JsonResponse({"task_id": task.id, "region": region})
