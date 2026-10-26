"""Vendor-authored records on the CVE registry, with publisher and scope guards.

An upstream component's CVE is never attributed to a vendor merely because its
description or references mention that vendor. Only the configured vendor's CNA
container is normalized; ADP enrichment is not product-impact evidence here.
"""

import json
import re
from urllib.parse import urlsplit

from ..plugins.contracts import SourceNotApplicable
from .standards import cna

JUNIPER_CNA = "8cbe9d5a-a066-4c94-8978-4b15efeae968"


def registry_route(url):
    parsed = urlsplit(url)
    return (
        parsed.scheme == "https"
        and not parsed.username
        and not parsed.password
        and parsed.port in (None, 443)
        and parsed.hostname == "cveawg.mitre.org"
        and bool(re.fullmatch(r"/api/cve/CVE-\d{4}-\d{4,}", parsed.path))
        and not parsed.query
        and not parsed.fragment
    )


PROFILES = {
    "juniper": (JUNIPER_CNA, {"Juniper Networks"}, ("juniper.net",)),
    "cisco": ("d1c1063e-7a18-46af-9102-31f8928bc633", {"Cisco"}, ("cisco.com",)),
    "hpe": (
        "eb103674-0d28-4225-80f8-39fb86215de0",
        {"Hewlett Packard Enterprise", "Hewlett Packard Enterprise (HPE)"},
        ("hpe.com",),
    ),
    "checkpoint": (
        "897c38be-0345-43cd-b6cf-fe179e0c4f45",
        {"checkpoint", "Check Point"},
        ("checkpoint.com",),
    ),
}


def vendor_cna(raw, url, vendor):
    if vendor not in PROFILES or not registry_route(url):
        raise ValueError("Expected configured vendor and exact CVE registry record route")
    organization, product_vendors, domains = PROFILES[vendor]
    data = json.loads(raw)
    meta = data["cveMetadata"]
    container = data["containers"]["cna"]
    if (
        meta.get("cveId") == urlsplit(url).path.rsplit("/", 1)[-1]
        and meta.get("state") == "PUBLISHED"
        and bool(meta.get("assignerOrgId"))
        and meta.get("assignerOrgId") == container.get("providerMetadata", {}).get("orgId")
        and meta.get("assignerOrgId") != organization
    ):
        raise SourceNotApplicable(
            "Registry record is authored by another CNA; retained as a source check without attributing product impact to the requested vendor."
        )
    if (
        meta.get("cveId") != urlsplit(url).path.rsplit("/", 1)[-1]
        or meta.get("state") != "PUBLISHED"
        or meta.get("assignerOrgId") != organization
        or container.get("providerMetadata", {}).get("orgId") != organization
        or any(p.get("vendor") not in product_vendors for p in container.get("affected", []))
        or not container.get("affected")
    ):
        raise ValueError("Record is not a published, configured vendor-authored product assessment")
    references = [r.get("url", "") for r in container.get("references", [])]
    official = [
        u
        for u in references
        if urlsplit(u).scheme == "https"
        and any(
            (urlsplit(u).hostname or "") == d or (urlsplit(u).hostname or "").endswith("." + d)
            for d in domains
        )
    ]
    if not official:
        raise ValueError("Vendor CNA lacks an official publisher reference")
    # A background CVE in a title cannot broaden the registry record's identity.
    scoped = json.loads(json.dumps(data))
    scoped["containers"]["cna"]["title"] = meta["cveId"]
    result = cna(json.dumps(scoped), url, vendor)
    result["title"] = container.get("title", meta["cveId"])
    result["cves"] = [meta["cveId"]]
    result["assessments"] = [a for a in result["assessments"] if a["cve_id"] == meta["cveId"]]
    result["source_format"] = "Vendor-authored CVE registry JSON"
    result["updated_at"] = container["providerMetadata"].get("dateUpdated")
    result["advisory_url"] = official[0]
    context = []
    for field in ("descriptions", "configurations", "solutions", "workarounds"):
        for index, item in enumerate(container.get(field, [])):
            if item.get("lang", "").lower() not in ("en", "en-us"):
                continue
            text = item.get("value", "")
            if not isinstance(text, str) or not text.strip() or len(text) > 20_000:
                raise ValueError("Unusable vendor CNA scope/context text")
            context.append(
                dict(
                    category="publisher_" + field,
                    details=text,
                    source_scope="advisory_context_requires_product_configuration_review",
                    source_locator=f"containers.cna.{field}[{index}]",
                )
            )
    if not any(c["category"] == "publisher_descriptions" for c in context):
        raise ValueError("Vendor CNA needs retained English applicability context")
    for claim in result["assessments"]:
        claim["scope"] = "cve_specific"
        claim["exposure"] = context
    result["warnings"] += [
        "Publisher identity verified against the configured vendor CNA organization ID and product-vendor names, with an official publisher reference. The registry delivers the vendor-authored container; generic upstream and ADP content do not supply product-impact claims.",
        "Version expressions, platforms and configuration context remain publisher assertions. Default status is not expanded into blanket unaffectedness. No version arithmetic, inventory equivalence or completeness is inferred.",
        "Unmapped solutions and workarounds remain context; they do not independently establish product-specific fixes, public availability or first disclosure.",
    ]
    return result


def juniper_cna(raw, url, vendor):
    if vendor != "juniper":
        raise ValueError("Expected Juniper vendor")
    return vendor_cna(raw, url, vendor)
