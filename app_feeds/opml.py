"""Parse Feeder/standard OPML exports into FeedSource seed records."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

# Map top-level OPML folder titles to FeedSource.category values.
FOLDER_TO_CATEGORY: Dict[str, str] = {
    "CVE & Exploits": "cyber",
    "Hacking News": "cyber",
    "Malware": "cyber",
    "Blogs": "cyber",
    "OSINT": "cyber",
    "YT Hacking News": "cyber",
    "Cyber Crime": "cyber",
    "DFIR Bloggers": "other",
    "DFIR YouTube Feeds": "other",
    "Digital Forensics": "other",
    "Crypt": "other",
    "Fox News": "geo",
    "Latest Headlines": "geo",
    "Uncategorized": "other",
}


def folder_to_category(folder: str) -> str:
    return FOLDER_TO_CATEGORY.get(folder, "other")


def parse_opml(path: str | Path) -> List[Dict[str, Any]]:
    """Return feed dicts: name, url, folder, category."""
    tree = ET.parse(path)
    body = tree.getroot().find("body")
    if body is None:
        return []

    feeds: List[Dict[str, Any]] = []

    def walk(node: ET.Element, folder_path: List[str]) -> None:
        title = (node.get("title") or node.get("text") or "").strip()
        xml_url = node.get("xmlUrl")
        if xml_url:
            folder = " / ".join(folder_path) if folder_path else "Uncategorized"
            feeds.append(
                {
                    "name": title or xml_url,
                    "url": xml_url.strip(),
                    "folder": folder,
                    "category": folder_to_category(folder),
                }
            )
            return
        child_folder = folder_path + ([title] if title else [])
        for child in node.findall("outline"):
            walk(child, child_folder)

    for outline in body.findall("outline"):
        if outline.tag.endswith("settings"):
            continue
        walk(outline, [])

    return feeds