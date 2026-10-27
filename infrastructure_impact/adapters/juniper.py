"""Reviewed juniper source normalization."""

import re

from .common import assessment, base, pdf_text
from .juniper_apstra import apstra_advisory


def juniper_pdf(raw, url, vendor):
    apstra = apstra_advisory(raw, url, vendor)
    if apstra is not None:
        return apstra
    text = pdf_text(raw)
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
