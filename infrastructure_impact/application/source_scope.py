"""Structural fingerprints of reviewed evidence sections, not parser outputs.

Only named, reviewed HTML layouts can exclude surrounding navigation. Every tag
and nonblank text node within the selected evidence is retained in the digest.
Attributes are retained except randomized Joomla email-cloak span IDs; table
structure, link targets, headings and conditions remain significant.
"""

import hashlib
import json
import re

from ..adapters.common import HTML, Node


def canonical(node):
    if isinstance(node, str):
        return re.sub(r"\s+", " ", node)
    attrs = {
        k: v
        for k, v in node.attrs.items()
        if not (
            node.tag == "span"
            and k == "id"
            and isinstance(v, str)
            and re.fullmatch(r"cloak[0-9a-f]{32}", v)
        )
    }
    return [
        node.tag,
        sorted(attrs.items()),
        [canonical(c) for c in node.children if isinstance(c, Node) or c.strip()],
    ]


def scope_sha256(raw, scheme):
    tree = HTML(raw).root
    if scheme == "arista_advisory_body_v1":
        nodes = [
            n for n in tree.find({"div"}) if "item-page" in (n.attrs.get("class") or "").split()
        ]
        if len(nodes) != 1:
            raise ValueError("Reviewed Arista article boundary changed")
    elif scheme == "fortinet_investigation_v1":
        details = [
            n for n in tree.find({"div"}) if "detail-item" in (n.attrs.get("class") or "").split()
        ]
        metadata = [
            n for n in tree.find({"table"}) if "meta" in (n.attrs.get("class") or "").split()
        ]
        titles = list(tree.find({"h1"}))
        if not details or len(metadata) != 1 or len(titles) != 1:
            raise ValueError("Reviewed Fortinet advisory boundaries changed")
        nodes = titles + details + metadata
    elif scheme == "fortinet_release_article_v1":
        nodes = [
            n
            for n in tree.find({"article"})
            if "reader__page" in (n.attrs.get("class") or "").split()
        ]
        if len(nodes) != 1 or not any(n.text() == "Resolved issues" for n in nodes[0].find({"h1"})):
            raise ValueError("Reviewed Fortinet release article boundary changed")
    elif scheme == "checkpoint_customer_section_v1":
        articles = [
            n
            for n in tree.find({"article"})
            if "post--single" in (n.attrs.get("class") or "").split()
        ]
        titles = [
            n for n in tree.find({"h1"}) if "entry-title" in (n.attrs.get("class") or "").split()
        ]
        times = [
            n for n in tree.find({"time"}) if "published" in (n.attrs.get("class") or "").split()
        ]
        if len(articles) != 1 or len(titles) != 1 or not times:
            raise ValueError("Reviewed customer article boundary changed")
        paragraphs = list(articles[0].find({"p"}))
        starts = [i for i, n in enumerate(paragraphs) if n.text() == "Check Point Customers"]
        ends = [i for i, n in enumerate(paragraphs) if n.text() == "Resources"]
        if len(starts) != 1 or len(ends) != 1 or ends[0] <= starts[0]:
            raise ValueError("Reviewed customer applicability section changed")
        nodes = titles + times[:1] + paragraphs[starts[0] : ends[0] + 1]
    else:
        raise ValueError("Unknown reviewed evidence-section scheme")
    return hashlib.sha256(
        json.dumps(
            [canonical(n) for n in nodes], ensure_ascii=False, separators=(",", ":")
        ).encode()
    ).hexdigest()


def retained_scopes(db, records, review):
    schemes = {
        c["source_url"]: c["reviewed_scope"]["scheme"]
        for c in review["cases"]
        if c.get("reviewed_scope")
    }
    rows = []
    seen = set()
    for record in records:
        scheme = schemes.get(record["source_url"])
        key = record["source_url"], record["sha256"]
        if not scheme or key in seen:
            continue
        seen.add(key)
        evidence = db.execute(
            "SELECT raw FROM evidence WHERE source_url=? AND sha256=?", key
        ).fetchone()
        if not evidence:
            continue
        try:
            digest = scope_sha256(evidence["raw"], scheme)
        except ValueError:
            continue
        rows.append(
            dict(source_url=key[0], source_sha256=key[1], scheme=scheme, scope_sha256=digest)
        )
    return rows
