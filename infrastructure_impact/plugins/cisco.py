"""Cisco source routing and informational-advisory policy."""

import re
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

from ..adapters.cisco_campaign import ADVISORY_ID, CVE, URL, parse_campaign, reviewed_route
from ..adapters.common import cves
from ..adapters.legacy_html import html_advisory
from ..adapters.vendor_cna import registry_route, vendor_cna
from .contracts import FeedBatch, VendorPlugin
from .shared import is_json, resolve_reviewed_advisory, structured


def parse(raw, url, vendor):
    if urlsplit(url).hostname == "cveawg.mitre.org":
        return vendor_cna(raw, url, vendor)
    if is_json(raw):
        return structured(raw, url, vendor)
    campaign = parse_campaign(raw, url, vendor)
    return campaign if campaign is not None else html_advisory(raw, url, vendor)


def resolve(raw, url, fetch):
    selected = resolve_reviewed_advisory(
        raw,
        url,
        fetch,
        vendor="cisco",
        advisory_id=ADVISORY_ID,
        cve_ids=[CVE],
        primary_url=URL,
        html_route=reviewed_route,
        parse_primary=parse_campaign,
        reason="Reviewed single-CVE HTML retains explicit product rows. The advertised structured representation is retained when available; statement counts do not prove equivalent scope or intent.",
    )
    return selected if selected is not None else (url, raw)


def canonicalize(url):
    if "/security/center/content/" in url:
        return "https://sec.cloudapps.cisco.com" + urlsplit(url).path
    if re.fullmatch(r"/\.well-known/csaf/20\d{2}/[^/]+\.json", urlsplit(url).path):
        return url  # Keep the advertised archive filename; lower-case IDs cannot reconstruct mixed-case API routes.
    if "/.well-known/csaf/" in url and url.endswith(".json"):
        name = urlsplit(url).path.rsplit("/", 1)[-1]
        return f"https://sec.cloudapps.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/{name[:-5]}/csaf/{name}"
    return url


def parse_feed(raw, url, limit, cohort):
    items = ET.fromstring(raw).findall(".//item")
    selected = [
        item
        for i, item in enumerate(items)
        if i < limit or set(cves(" ".join(item.itertext()))) & cohort
    ]
    links = list(
        dict.fromkeys(
            canonicalize(item.findtext("link")) for item in selected if item.findtext("link")
        )
    )[:12]
    ids = list(dict.fromkeys(cid for item in selected for cid in cves(" ".join(item.itertext()))))[
        :8
    ]
    if not links and not ids:
        raise ValueError("No Cisco advisory or CVE links in selected RSS window")
    return FeedBatch(
        (),
        frozenset(cid for item in items for cid in cves(" ".join(item.itertext()))),
        f"Current Cisco RSS window ({len(items)} entries); up to twelve selected publisher URLs and eight CVE registry follow-ups require separate document extraction and Cisco CNA verification; no complete archive implied",
        "ok",
        tuple(links + ["https://cveawg.mitre.org/api/cve/" + cid for cid in ids]),
    )


def plugin():
    return VendorPlugin(
        "cisco",
        "Cisco",
        ("cisco.com", "cveawg.mitre.org"),
        parse,
        canonicalize=canonicalize,
        parse_feed=parse_feed,
        resolve=resolve,
        normalizer_dependencies=(parse_campaign, html_advisory, vendor_cna, structured),
        non_cve_notice=lambda d: not d["cves"] and d["title"].startswith("Cisco Informational"),
        url_filter=lambda url: (
            (urlsplit(url).hostname or "") == "cisco.com"
            or (urlsplit(url).hostname or "").endswith(".cisco.com")
            or registry_route(url)
        ),
        capabilities=(
            "verified-vendor-cna",
            "csaf",
            "cve-json",
            "html",
            "reviewed-source-selection",
        ),
    )
