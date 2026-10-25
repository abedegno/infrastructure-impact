"""Reviewed hpe source normalization."""

import re
from datetime import datetime

from .common import HTML, assessment, availability, base, cves


def hpe_bulletin(raw, url, vendor):
    tree = HTML(raw).root
    text = tree.text()
    title = next((n.text() for n in tree.find({"h1", "title"}) if "HPESB" in n.text()), None)
    if not title or "SUPPORTED SOFTWARE VERSIONS*" not in text or "RESOLUTION" not in text:
        raise ValueError("Unsupported HPE bulletin layout")
    identity = re.search(r"HPESB[A-Z]+\d+", title)[0]

    def field(label):
        m = re.search(label + r":\s*(\d{4}-\d{2}-\d{2})", text)
        return m[1] if m else None

    out = base(vendor, url, identity, title, field("Release Date"), field("Last Updated"))
    out.update(source_format="HPE bulletin HTML", document_status="published")
    before, section = text.split("SUPPORTED SOFTWARE VERSIONS*", 1)
    out["cves"] = cves(before)
    affected = section.split("BACKGROUND", 1)[0]
    affected = re.sub(r"^:\s*ONLY impacted versions are listed\.\s*", "", affected).strip()
    resolution = text.split("RESOLUTION", 1)[1].split("HISTORY", 1)[0].strip()
    # The supported-version block uses paragraph or table rows depending on bulletin.
    candidates = []
    for n in tree.find({"p", "li", "tr"}):
        t = n.text()
        if t and t in affected and ("Prior to" in t or "prior to" in t):
            candidates.append(t)
    candidates = list(dict.fromkeys(candidates))
    candidates = [t for t in candidates if not any(t != s and s in t for s in candidates)]
    if not candidates:
        raise ValueError("No scoped HPE affected-version statements")
    for expression in candidates:
        product = re.split(r"\s+-\s+|\s+Prior to\s+", expression, maxsplit=1)[0].strip()
        for cid in out["cves"]:
            out["assessments"].append(
                assessment(
                    cid,
                    product,
                    "affected",
                    "SUPPORTED SOFTWARE VERSIONS",
                    [{"expression": expression}],
                    [
                        {
                            "category": "vendor_fix",
                            "details": resolution,
                            "availability": availability(resolution, "vendor_fix"),
                            "source_scope": "bulletin",
                        }
                    ],
                    "bulletin_shared" if len(out["cves"]) > 1 else "cve_specific",
                )
            )
    out["notes"] = [
        {"category": "bulletin_context", "text": before.split("VULNERABILITY SUMMARY", 1)[-1]}
    ]
    out["warnings"].append(
        "Curated HPE bulletin; coverage is restricted to the listed products. Supported-version and resolution blocks preserve vendor expressions; no range comparison performed."
    )
    # Store a candidate date as a source assertion, never a verified release observation.
    date_match = re.search(r"\((\d{1,2}/\d{1,2}/\d{4})\)", resolution)
    if date_match:
        out["reported_fix_date"] = datetime.strptime(date_match[1], "%m/%d/%Y").date().isoformat()
        out["warnings"].append(
            "Firmware date is reported in the bulletin, not independently verified public availability."
        )
    return out
