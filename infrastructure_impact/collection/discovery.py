"""Bounded RSS, Atom and CSAF index discovery with explicit inventory scope."""

from urllib.parse import urljoin
from xml.etree import ElementTree as ET


def inventory(raw, url, kind):
    if kind == "index":
        urls = [
            urljoin(url, line.strip())
            for line in raw.decode().splitlines()
            if line.strip().endswith(".json")
        ]
        if not urls:
            raise ValueError("Index contains no JSON document links")
        return dict(
            urls=list(dict.fromkeys(urls)),
            entry_count=len(urls),
            entries_without_links=0,
            next_pages=[],
        )
    root = ET.fromstring(raw)
    if root.tag.rsplit("}", 1)[-1] not in ("rss", "feed"):
        raise ValueError("Expected RSS or Atom feed")
    items = root.findall(".//item")
    entries = items or root.findall(".//{http://www.w3.org/2005/Atom}entry")
    urls = []
    missing = 0
    for entry in entries:
        links = []
        self_links = []
        for node in entry:
            if node.tag.rsplit("}", 1)[-1] != "link":
                continue
            href = node.attrib.get("href") or (node.text or "").strip()
            if href and node.attrib.get("rel") == "self":
                self_links.append(href)
            if href and node.attrib.get("rel", "alternate") in ("alternate", "enclosure"):
                links.append(href)
        links = links or self_links
        target = next((u for u in links if u.endswith(".json")), None) or next(iter(links), None)
        if target:
            urls.append(urljoin(url, target))
        else:
            missing += 1
    next_pages = sorted(
        {
            urljoin(url, n.attrib["href"])
            for n in root.iter()
            if n.tag.rsplit("}", 1)[-1] == "link"
            and n.attrib.get("rel") == "next"
            and n.attrib.get("href")
        }
    )
    return dict(
        urls=list(dict.fromkeys(urls)),
        entry_count=len(entries),
        entries_without_links=missing,
        next_pages=next_pages,
    )


def discovery(raw, url, kind, limit, order="oldest_first"):
    if not limit:
        return []
    urls = inventory(raw, url, kind)["urls"]
    if kind == "index":
        return (urls[:limit] if order == "newest_first" else urls[-limit:]) if limit else []
    return urls[:limit]
