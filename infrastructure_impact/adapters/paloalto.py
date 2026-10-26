"""Reviewed paloalto source normalization."""

import re

from .common import HTML, assessment, base, cves


def pan_oss_bulletin(raw, url, vendor):
    tree = HTML(raw).root
    text = tree.text()
    if "oss cves fixed in pan-os" not in text.lower():
        raise ValueError("Unknown PAN-SA HTML layout")
    identity = re.search(r"PAN-SA-\d{4}-\d+", url)[0]
    out = base(vendor, url, identity, "Informational Bulletin: OSS CVEs Fixed in PAN-OS")
    out.update(source_format="Vendor HTML CVE-specific fix table", document_status="published")
    for label, key in [("Published", "published_at"), ("Updated", "updated_at")]:
        m = re.search(label + r"\s+(\d{4}-\d{2}-\d{2})", text)
        if m:
            out[key] = m[1]
    for row in tree.find({"tr"}):
        cells = [c.text() for c in row.find({"td"})]
        if len(cells) != 2 or "fixed in PAN-OS" not in cells[1]:
            continue
        ids = cves(cells[0])
        if len(ids) != 1:
            continue
        cid = ids[0]
        out["cves"].append(cid)
        out["assessments"].append(
            assessment(
                cid,
                "PAN-OS",
                "fixed",
                "Description CVE table / " + cid,
                [{"expression": cells[1]}],
                [
                    {
                        "category": "vendor_fix",
                        "details": cells[1],
                        "availability": "vendor_reports_fixed",
                    }
                ],
            )
        )
    out["cves"] = sorted(set(out["cves"]))
    out["warnings"] = [
        "Publisher says these OSS CVEs had no significant determined impact and were fixed out of caution. Fixed-version rows do not prove earlier versions were exploitable. The JSON export omits this per-CVE table; HTML is the source for these claims."
    ]
    return out


def pan_impact_bulletin(raw, url, vendor):
    tree = HTML(raw).root
    text = tree.text()
    if (
        "PAN-OS does not offer any scenarios required for an attacker to successfully exploit these vulnerabilities and is not impacted."
        not in text
    ):
        raise ValueError("Expected PAN-OS impact statement missing; review changed publisher scope")
    out = base(
        vendor,
        url,
        re.search(r"PAN-SA-\d{4}-\d+", url)[0],
        "Informational Bulletin: Impact of OSS CVEs in PAN-OS",
    )
    out.update(source_format="Vendor HTML scoped impact rationale", document_status="published")
    from ..application.cohort import COHORT

    for label, key in [("Published", "published_at"), ("Updated", "updated_at")]:
        m = re.search(label + r"\s+(\d{4}-\d{2}-\d{2})", text)
        if m:
            out[key] = m[1]
    for row in tree.find({"tr"}):
        cells = [n.text() for n in row.find({"td"})]
        if len(cells) != 2:
            continue
        ids = set(cves(cells[0])) & set(COHORT)
        for cid in sorted(ids):
            a = assessment(
                cid,
                "PAN-OS",
                "unaffected",
                "Description / CVE rationale table / " + cid,
                [
                    {
                        "expression": "Vendor assessment: PAN-OS not impacted under the product restrictions described in its rationale"
                    }
                ],
            )
            a["exposure"] = [{"category": "publisher_applicability_rationale", "details": cells[1]}]
            out["cves"].append(cid)
            out["assessments"].append(a)
    out["cves"] = sorted(set(out["cves"]))
    out["warnings"] = [
        "Extraction restricted to benchmark CVEs. The publisher may include the vulnerable OSS package but reports no exploitable product scenario. Preserve this rationale; it is not a claim that the dependency is absent or patched."
    ]
    return out
