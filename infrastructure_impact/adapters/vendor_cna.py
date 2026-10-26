"""Vendor-authored records on the CVE registry, with publisher and scope guards.

An upstream component's CVE is never attributed to a vendor merely because its
description or references mention that vendor. Only the configured vendor's CNA
container is normalized; ADP enrichment is not product-impact evidence here.
"""

import json
import re
from urllib.parse import urlsplit

from .standards import cna

JUNIPER_CNA = "8cbe9d5a-a066-4c94-8978-4b15efeae968"


def registry_route(url):
    parsed = urlsplit(url)
    return (
        parsed.hostname == "cveawg.mitre.org"
        and bool(re.fullmatch(r"/api/cve/CVE-\d{4}-\d{4,}", parsed.path))
        and not parsed.query
        and not parsed.fragment
    )


def juniper_cna(raw, url, vendor):
    if vendor != "juniper" or not registry_route(url):
        raise ValueError("Expected exact CVE registry record route")
    data = json.loads(raw)
    meta = data["cveMetadata"]
    container = data["containers"]["cna"]
    if (
        meta.get("cveId") != urlsplit(url).path.rsplit("/", 1)[-1]
        or meta.get("state") != "PUBLISHED"
        or meta.get("assignerOrgId") != JUNIPER_CNA
        or container.get("providerMetadata", {}).get("orgId") != JUNIPER_CNA
        or any(p.get("vendor") != "Juniper Networks" for p in container.get("affected", []))
        or not container.get("affected")
    ):
        raise ValueError("Record is not a published, Juniper-authored product assessment")
    # Title/background references must not broaden this registry record's CVE scope.
    scoped = json.loads(json.dumps(data))
    scoped["containers"]["cna"]["title"] = container.get("title", meta["cveId"])
    result = cna(json.dumps(scoped), url, vendor)
    result["cves"] = [meta["cveId"]]
    result["assessments"] = [a for a in result["assessments"] if a["cve_id"] == meta["cveId"]]
    result["source_format"] = "Vendor-authored CVE registry JSON"
    result["updated_at"] = container["providerMetadata"].get("dateUpdated")
    result["advisory_url"] = next(
        (
            r["url"]
            for r in container.get("references", [])
            if "vendor-advisory" in r.get("tags", [])
            and (urlsplit(r.get("url", "")).hostname or "").endswith(".juniper.net")
        ),
        None,
    )
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
    result["warnings"] = [
        "Publisher identity verified against the configured Juniper CNA organization ID. The CVE registry is the delivery source; this is a vendor-authored container, not generic upstream or ADP inference.",
        "Version expressions, platforms and advisory configuration context remain publisher assertions. Default status is not expanded into blanket unaffectedness. No version arithmetic or hardware inventory equivalence is inferred.",
        "Unmapped solutions and workarounds remain advisory context. They do not independently establish a product-specific fix, public release availability or first disclosure.",
    ]
    return result
