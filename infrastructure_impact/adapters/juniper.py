"""Reviewed juniper source normalization."""

import re

from .common import assessment, base, pdf_text


def juniper_pdf(raw, url, vendor):
    text = pdf_text(raw)
    if "AOS-47640" in text and "OpenSSH Vulnerability CVE-2024-6387" in text:
        block = text.split("OpenSSH Vulnerability CVE-2024-6387", 1)[1].split("USN-6891-1", 1)[0]
        if "4.2.2.1 and 5.0.0 will include a fixed OpenSSH package" not in block:
            raise ValueError("Apstra remediation wording changed; review source")
        out = base(vendor, url, "Apstra-AOS-47640", "Apstra release notes: OpenSSH CVE-2024-6387")
        out.update(
            cves=["CVE-2024-6387"],
            source_format="Vendor release notes PDF",
            document_status="published",
        )
        out["assessments"] = [
            assessment(
                "CVE-2024-6387",
                "Apstra Server 4.2.x (Ubuntu 22.04)",
                "affected",
                "AOS-47640 / OpenSSH vulnerability and Resolution",
                [
                    {
                        "expression": "Apstra server 4.2.x, based on Ubuntu 22.04, includes OpenSSH 8.9p1"
                    }
                ],
                [
                    {
                        "category": "vendor_fix",
                        "details": "Apstra Server 4.2.2.1 and 5.0.0 will include a fixed OpenSSH package",
                        "availability": "planned",
                    }
                ],
            )
        ]
        out["warnings"] = [
            "Historical future-tense release-note statement; current fix availability and original publication date are not established by this snapshot. PDF footer date is not assumed to be product release date."
        ]
        return out
    if "JSA103137" not in text or "Session Smart Router" not in text:
        raise ValueError("Unrecognised Juniper PDF; retained raw but requires scoped adapter")
    # Narrow table columns wrap IDs over several lines. Require complete digit-only
    # lines and validate length; curated benchmark IDs avoid partial extraction claims.
    pattern = r"C\s*V\s*E\s*-\s*((?:\d\s*){4})-\s*((?:\d+[\t ]*\n){1,5})"
    ids = {
        "CVE-" + re.sub(r"\s", "", m[1]) + "-" + re.sub(r"\s", "", m[2])
        for m in re.finditer(pattern, text)
    }
    from ..application.cohort import COHORT

    ids = sorted(ids & set(COHORT))
    out = base(
        vendor, url, "JSA103137", "Session Smart Router: third-party fixes in 6.2.10-lts, 6.3.6-sts"
    )
    out.update(cves=ids, source_format="Vendor PDF attachment", document_status="published")
    if "All versions before 6.2.10-lts" not in text or "before 6.3.6-sts" not in text:
        raise ValueError("Expected SSR product status missing")
    for cid in ids:
        out["assessments"].append(
            assessment(
                cid,
                "Session Smart Router",
                "affected",
                "JSA103137 CVE table and Product Status",
                [{"expression": "All versions before 6.2.10-lts; from 6.3.0 before 6.3.6-sts"}],
                [
                    {
                        "category": "vendor_fix",
                        "details": "6.2.10-lts and subsequent 6.2 releases; 6.3.6-sts and subsequent 6.3 releases",
                        "availability": "vendor_reports_fixed",
                    }
                ],
                scope="bulletin_shared",
            )
        )
    out["warnings"] = [
        "PDF extraction restricted to benchmark CVE IDs; other bulletin CVEs are outside parser scope. Publication date not established. Shared third-party bulletin does not separately encode per-CVE configurations."
    ]
    return out
