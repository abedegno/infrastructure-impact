"""Palo Alto JSON sources and HTML-only per-CVE tables."""

import json
import re
from urllib.parse import urljoin, urlsplit

from ..adapters.common import HTML, cves
from ..adapters.paloalto import pan_impact_bulletin, pan_oss_bulletin
from .archive_listings import paloalto as archive_listing
from .contracts import VendorPlugin
from .shared import is_json, structured


def parse(raw, url, vendor):
    if is_json(raw):
        record = structured(raw, url, vendor)
        document = json.loads(raw)
        description = " ".join(
            d.get("value", "")
            for d in document.get("containers", {}).get("cna", {}).get("descriptions", [])
        )
        for sentence in re.findall(r"Panorama appliances are not impacted by [^.]+\.", description):
            excluded = set(cves(sentence))
            for claim in record["assessments"]:
                if "Panorama" in claim["product"] and claim["cve_id"] in excluded:
                    claim.update(
                        status="unaffected", scope="cve_specific", versions=[], remediations=[]
                    )
                    claim["evidence_locator"] += " / descriptions: explicit Panorama CVE exception"
                    claim["exposure"].append(
                        {"category": "publisher_applicability_rationale", "details": sentence}
                    )
        return record
    if "Impact of OSS CVEs in PAN-OS" in HTML(raw).root.text():
        return pan_impact_bulletin(raw, url, vendor)
    return pan_oss_bulletin(raw, url, vendor)


def resolve(raw, url, fetch):
    if is_json(raw):
        return url, raw
    if "/PAN-SA-" in url:
        tree = HTML(raw).root
        if any(
            text in tree.text().lower()
            for text in ("oss cves fixed in pan-os", "impact of oss cves in pan-os")
        ):
            return url, raw  # Preserve reviewed per-CVE HTML qualification tables.
        identity = urlsplit(url).path.rsplit("/", 1)[-1]
        links = {
            urljoin(url, a.attrs.get("href", ""))
            for a in tree.find({"a"})
            if a.attrs.get("href") == "/csaf/" + identity
        }
        if len(links) == 1:
            target = next(iter(links))
            return target, fetch(target)
        raise ValueError(
            "PAN-SA bulletin has no reviewed HTML layout or advertised CSAF representation"
        )
    match = re.search(r"/(CVE-\d{4}-\d+)", url)
    if match:
        target = "https://security.paloaltonetworks.com/json/" + match[1]
        return target, fetch(target)
    return url, raw


def plugin():
    return VendorPlugin(
        "paloalto",
        "Palo Alto Networks",
        ("paloaltonetworks.com",),
        parse,
        parse_archive=archive_listing,
        resolve=resolve,
        capabilities=("cve-json", "html"),
    )
