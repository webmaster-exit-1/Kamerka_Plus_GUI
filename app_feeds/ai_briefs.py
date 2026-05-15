"""
app_feeds/ai_briefs.py — AI-synthesised intelligence brief generation.

Tries Ollama first (if OLLAMA_HOST env var is set), falls back to a simple
extractive summariser using sentence scoring.

Public API
----------
generate(region, texts) -> (content: str, method: str)
"""
from __future__ import annotations

import os
import re
from typing import List, Tuple

_OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "")
_OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3")
_OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "60"))


def generate(region: str, texts: List[str]) -> Tuple[str, str]:
    """Generate an intelligence brief for *region* from the supplied *texts*.

    Parameters
    ----------
    region : str
        ISO-2 country code or region/topic keyword.
    texts : list[str]
        Recent feed entry snippets (title + summary excerpt).

    Returns
    -------
    (content, method) : tuple[str, str]
        *content* — the brief text.
        *method*  — ``"ollama"`` or ``"extractive"``.
    """
    if _OLLAMA_HOST:
        try:
            return _ollama_brief(region, texts)
        except Exception:
            pass
    return _extractive_brief(region, texts), "extractive"


def _ollama_brief(region: str, texts: List[str]) -> Tuple[str, str]:
    """Generate a brief via the Ollama HTTP API."""
    import requests

    combined = "\n".join(f"- {t}" for t in texts)
    prompt = (
        f"You are a cybersecurity and geopolitical analyst. "
        f"Summarise the following recent intelligence items related to {region!r} "
        f"in 3-5 bullet points. Focus on threats to critical infrastructure and "
        f"ICS/SCADA systems. Be concise and factual.\n\n{combined}"
    )
    resp = requests.post(
        f"{_OLLAMA_HOST.rstrip('/')}/api/generate",
        json={"model": _OLLAMA_MODEL, "prompt": prompt, "stream": False},
        timeout=_OLLAMA_TIMEOUT,
    )
    resp.raise_for_status()
    content = resp.json().get("response", "").strip()
    if not content:
        raise ValueError("empty Ollama response")
    return content, "ollama"


def _extractive_brief(region: str, texts: List[str]) -> str:
    """Simple extractive summariser: score sentences by term frequency.

    Returns the top-N sentences that best represent the collection.
    Does not require any ML libraries.
    """
    # Tokenise all texts into sentences
    sentences = []
    for text in texts:
        for sent in re.split(r"(?<=[.!?])\s+", text):
            sent = sent.strip()
            if sent:
                sentences.append(sent)

    if not sentences:
        return f"No recent intelligence items found for {region}."

    # Build term-frequency table (stop-words excluded)
    _STOPWORDS = {
        "the", "a", "an", "is", "are", "was", "were", "of", "in", "to",
        "and", "or", "for", "with", "that", "this", "it", "on", "at", "by",
        "be", "has", "have", "from", "as", "its", "not", "but", "he", "she",
        "they", "we", "you", "i", "s", "t", "re", "ve", "ll", "d",
    }
    tf: dict = {}
    for sent in sentences:
        for word in re.findall(r"[a-z]+", sent.lower()):
            if word not in _STOPWORDS and len(word) > 2:
                tf[word] = tf.get(word, 0) + 1

    # Score each sentence as sum of its term frequencies
    scored = []
    for sent in sentences:
        score = sum(
            tf.get(w, 0)
            for w in re.findall(r"[a-z]+", sent.lower())
            if w not in _STOPWORDS
        )
        scored.append((score, sent))

    scored.sort(reverse=True)
    top = [s for _, s in scored[:5]]

    header = f"Intelligence Brief — {region}\n" + "=" * 40
    bullets = "\n".join(f"• {s}" for s in top)
    return f"{header}\n\n{bullets}"
