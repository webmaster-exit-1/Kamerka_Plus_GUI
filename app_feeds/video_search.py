"""Match public videos to RSS headlines for the feeds briefing playlist.

Search hosts are a fixed allowlist. Callers cannot pick the URL. Video ids are
restricted to the YouTube id alphabet before anything is embedded.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

import requests
from django.core.cache import cache

_YT_ID = re.compile(r"^[A-Za-z0-9_-]{11}$")
_YT_IN_URL = re.compile(
    r"(?:youtube\.com/(?:watch\?v=|embed/|shorts/)|youtu\.be/)([A-Za-z0-9_-]{11})"
)
_TOKEN = re.compile(r"[a-z0-9]{4,}")
_STOP = {
    "with", "from", "that", "this", "after", "over", "into", "says", "said",
    "have", "been", "will", "their", "about", "news", "video", "watch",
}

# Fixed hosts. Do not append user input to this list.
_ENDPOINTS = (
    ("https://pipedapi.kavin.rocks/search", {"filter": "videos"}),
    ("https://pipedapi.adminforge.de/search", {"filter": "videos"}),
    ("https://inv.nadeko.net/api/v1/search", {"type": "video"}),
)
_ALLOWED_HOSTS = frozenset(urlparse(url).netloc for url, _params in _ENDPOINTS)


def clean_query(title: str) -> str:
    text = re.sub(r"\s+", " ", str(title or "")).strip()
    text = re.sub(r"^[\[\]]+", "", text)
    text = re.sub(r"https?://\S+", "", text)
    text = re.sub(r"[^\w\s.'+-]", " ", text, flags=re.UNICODE)
    return re.sub(r"\s+", " ", text).strip()[:140]


def _tokens(text: str) -> set:
    return {tok for tok in _TOKEN.findall(text.lower()) if tok not in _STOP}


def _pack(video_id: str, title: str = "", channel: str = "", thumbnail: str = "") -> Optional[Dict[str, str]]:
    if not _YT_ID.match(video_id or ""):
        return None
    thumb = thumbnail if str(thumbnail).startswith("https://") else ""
    return {
        "video_id": video_id,
        "title": (title or "")[:300],
        "channel": (channel or "")[:120],
        "thumbnail": thumb[:500],
        "url": f"https://www.youtube.com/watch?v={video_id}",
        "embed_url": f"https://www.youtube-nocookie.com/embed/{video_id}",
    }


def video_from_page_url(page_url: str, title: str = "") -> Optional[Dict[str, str]]:
    match = _YT_IN_URL.search(page_url or "")
    if not match:
        return None
    packed = _pack(match.group(1), title=title)
    return packed


def _normalize_item(item: Dict[str, Any]) -> Optional[Dict[str, str]]:
    video_id = str(item.get("videoId") or "")
    if not video_id:
        raw_url = str(item.get("url") or "")
        match = re.search(r"(?:[?&]v=|youtu\.be/)([A-Za-z0-9_-]{11})", raw_url)
        if match:
            video_id = match.group(1)
    thumb = str(item.get("thumbnail") or "")
    thumbs = item.get("videoThumbnails")
    if isinstance(thumbs, list) and thumbs and isinstance(thumbs[-1], dict):
        thumb = str(thumbs[-1].get("url") or thumb)
    channel = item.get("uploaderName") or item.get("author") or item.get("uploader") or ""
    return _pack(video_id, title=str(item.get("title") or ""), channel=str(channel), thumbnail=thumb)


def _rank(query: str, videos: List[Dict[str, str]], limit: int) -> List[Dict[str, str]]:
    wanted = _tokens(query)
    scored = []
    for video in videos:
        if not wanted:
            score = 0.0
        else:
            score = len(wanted & _tokens(video.get("title") or "")) / len(wanted)
        scored.append((score, video))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    kept = [video for score, video in scored if score >= 0.34]
    if not kept and scored and scored[0][0] >= 0.25:
        kept = [scored[0][1]]
    out = []
    seen = set()
    for video in kept:
        if video["video_id"] in seen:
            continue
        seen.add(video["video_id"])
        out.append(video)
        if len(out) >= limit:
            break
    return out


def _default_fetch(query: str) -> List[Dict[str, str]]:
    headers = {"User-Agent": "Kamerka-Plus/feeds", "Accept": "application/json"}
    for url, extra in _ENDPOINTS:
        host = urlparse(url).netloc
        if host not in _ALLOWED_HOSTS:
            continue
        try:
            resp = requests.get(
                url,
                params={"q": query, **extra},
                timeout=4,
                allow_redirects=False,
                headers=headers,
            )
            if resp.status_code != 200 or not resp.content:
                continue
            data = resp.json()
        except Exception:
            continue
        items = data if isinstance(data, list) else []
        if isinstance(data, dict):
            items = data.get("items") or data.get("results") or []
        videos = []
        for item in items:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("type") or "video").lower()
            if kind not in ("video", "stream"):
                continue
            packed = _normalize_item(item)
            if packed:
                videos.append(packed)
        if videos:
            return videos
    return []


def match_videos(
    title: str,
    page_url: str = "",
    limit: int = 3,
    fetcher: Optional[Callable[[str], List[Dict[str, str]]]] = None,
) -> List[Dict[str, str]]:
    """Return up to `limit` videos that actually match the headline."""
    limit = max(1, min(int(limit), 5))
    query = clean_query(title)
    direct = video_from_page_url(page_url, title=query)
    ranked: List[Dict[str, str]] = []
    if len(query) >= 4:
        key = "feedvid:" + hashlib.sha256(query.lower().encode()).hexdigest()
        cached = None if fetcher is not None else cache.get(key)
        if cached is None:
            found = (fetcher or _default_fetch)(query)
            ranked = _rank(query, list(found or []), limit)
            ranked = [video for video in ranked if _YT_ID.match(str(video.get("video_id") or ""))]
            if fetcher is None:
                cache.set(key, ranked, 21600 if ranked else 600)
        else:
            ranked = list(cached)
    out: List[Dict[str, str]] = []
    seen = set()
    if direct:
        out.append(direct)
        seen.add(direct["video_id"])
    for video in ranked:
        if video["video_id"] in seen:
            continue
        seen.add(video["video_id"])
        out.append(video)
        if len(out) >= limit:
            break
    return out
