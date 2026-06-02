"""Plain-text helpers for RSS/HTML feed content."""
from __future__ import annotations

import re
from html import unescape
from html.parser import HTMLParser


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []

    def handle_data(self, data: str) -> None:
        if data:
            self._chunks.append(data)

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() in {"br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6"}:
            self._chunks.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6"}:
            self._chunks.append("\n")

    def get_text(self) -> str:
        return "".join(self._chunks)


def html_to_plain(text: str, *, max_len: int | None = None) -> str:
    """Strip HTML tags and normalise whitespace for display and summarisation."""
    if not text:
        return ""
    raw = str(text).strip()
    if not raw:
        return ""
    if "<" not in raw and "&" not in raw:
        plain = raw
    else:
        parser = _HTMLTextExtractor()
        try:
            parser.feed(raw)
            parser.close()
            plain = parser.get_text()
        except Exception:
            plain = re.sub(r"<[^>]+>", " ", raw)
        plain = unescape(plain)
    plain = re.sub(r"[ \t]+\n", "\n", plain)
    plain = re.sub(r"\n{3,}", "\n\n", plain)
    plain = re.sub(r"[ \t]{2,}", " ", plain)
    plain = plain.strip()
    if max_len is not None and len(plain) > max_len:
        plain = plain[: max_len - 1].rstrip() + "…"
    return plain