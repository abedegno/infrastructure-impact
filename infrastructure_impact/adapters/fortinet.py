"""Reviewed fortinet source normalization."""

import re
from urllib.parse import urlsplit

from .common import HTML, assessment, base, cves


def fortinac_release(raw, url, vendor):
    tree = HTML(raw).root
    text = tree.text()
    if "Applies to the FortiNAC-F product only" not in text:
        raise ValueError("Expected FortiNAC-F release scope missing")
    out = base(vendor, url, "FortiNAC-F-7.4.1-release-CVEs", "FortiNAC-F 7.4.1 resolved CVEs")
    out.update(source_format="Vendor release notes HTML", document_status="published")
    for row in tree.find({"tr"}):
        t = row.text()
        if "FortiNAC F 7.4.1 is no longer vulnerable" not in t:
            continue
        for cid in cves(t):
            out["cves"].append(cid)
            out["assessments"].append(
                assessment(
                    cid,
                    "FortiNAC-F (FortiNAC-OS) 7.4.1",
                    "fixed",
                    "CVE references table / " + t.split()[0],
                    [{"version": "7.4.1", "status": "fixed"}],
                    [
                        {
                            "category": "vendor_fix",
                            "details": "7.4.1",
                            "availability": "vendor_reports_fixed",
                        }
                    ],
                )
            )
    out["cves"] = sorted(set(out["cves"]))
    out["warnings"] = [
        "Applies only to FortiNAC-F on FortiNAC-OS, excludes CentOS appliances. No publication or release date established by this page."
    ]
    return out


def fortinet_release(raw, url, vendor):
    if "/fortinac-f/" in url:
        return fortinac_release(raw, url, vendor)
    path = urlsplit(url).path
    m = re.match(r"/document/(fortigate|fortiproxy)/(\d+\.\d+\.\d+)/", path)
    if not m:
        raise ValueError("Unsupported Fortinet release-note product/version scope")
    product = {"fortigate": "FortiOS", "fortiproxy": "FortiProxy"}[m[1]]
    version = m[2]
    tree = HTML(raw).root
    nodes = list(tree.find({"h1", "h2", "h3", "h4", "p", "tr"}))
    out = base(
        vendor, url, f"{product}-{version}-release-CVEs", f"{product} {version} resolved CVEs"
    )
    out.update(source_format="Vendor release notes HTML", document_status="published")
    active = False
    explicit = False
    expected = f"{product} {version} is no longer vulnerable"
    for n in nodes:
        text = n.text()
        if n.tag in ("h1", "h2", "h3", "h4"):
            active = text.lower() == "common vulnerabilities and exposures"
            explicit = False
            continue
        if not active:
            continue
        if n.tag == "p" and expected in text:
            explicit = True
        if n.tag != "tr":
            continue
        if expected not in text and not explicit:
            continue
        for cid in cves(text):
            out["cves"].append(cid)
            out["assessments"].append(
                assessment(
                    cid,
                    product + " " + version,
                    "fixed",
                    "Common Vulnerabilities and Exposures / bug " + text.split()[0],
                    [{"version": version, "status": "fixed"}],
                    [
                        {
                            "category": "vendor_fix",
                            "details": version,
                            "availability": "vendor_reports_fixed",
                        }
                    ],
                )
            )
    out["cves"] = sorted(set(out["cves"]))
    out["assessments"] = list(
        {(a["cve_id"], a["product_id"]): a for a in out["assessments"]}.values()
    )
    out["warnings"] = [
        "Exact release-note product/version only. A fixed release does not establish which earlier releases were affected. Publication date and public availability have not been verified."
    ]
    if not out["assessments"]:
        raise ValueError("No explicit product/version CVE fix statements in expected section")
    return out
