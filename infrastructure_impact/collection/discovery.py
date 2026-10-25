"""Bounded RSS, Atom and CSAF text-index discovery."""

from urllib.parse import urljoin
from xml.etree import ElementTree as ET


def discovery(raw, url, kind, limit, order="oldest_first"):
    if kind == "index":
        urls = [
            urljoin(url, x.strip())
            for x in raw.decode().splitlines()
            if x.strip().endswith(".json")
        ]
        # Explicit bounded index sample, not a claim of a complete recent-date window.
        return (urls[:limit] if order == "newest_first" else urls[-limit:]) if limit else []
    doc = ET.fromstring(raw)
    urls = [
        next(
            (
                node.text
                for node in item
                if node.tag.endswith("}link") and node.text and node.text.endswith(".json")
            ),
            None,
        )
        or item.findtext("link")
        for item in doc.findall(".//item")
    ]
    urls = [u for u in urls if u]
    if not urls:
        urls = [
            x.attrib["href"]
            for x in doc.findall(
                ".//{http://www.w3.org/2005/Atom}entry/{http://www.w3.org/2005/Atom}link"
            )
            if x.attrib.get("href")
        ]
    return list(dict.fromkeys(urls))[:limit]
