"""Reviewed 0100 EOS fix and backport scope; no upstream-version matching."""

from hashlib import sha256

from .arista import arista_software
from .arista_scoped import article
from .common import assessment

URL = "https://www.arista.com/en/support/advisories-notices/security-advisory/19904-security-advisory-0100"
SPANS = {
    "resolution": (
        "Resolution CVE-2024-6387",
        "Hotfix The following hotfix",
        "44e5dba16a680beb38c2c238ff8d89e3b3fbcf74bb5a8a3d734d2448b06c6adb",
    ),
    "platforms": (
        "Affected Platforms Arista EOS-based products",
        "Mitigation For both",
        "6465a12d712321d792adac36527121735a86210f3b5106987d8d57c084595459",
    ),
    "mitigation": (
        "Mitigation For both",
        "Resolution CVE-2024-6387",
        "cf8aeec7da55add0b0d0c8c9ee95398da1223f68ce9224f01e9398412749fb29",
    ),
}


def openssh_scope(raw, url, vendor):
    if url != URL or vendor != "arista":
        raise ValueError("Unreviewed Arista OpenSSH route")
    node, _ = article(raw, url, "0100")
    text = node.text()
    spans = {}
    for name, (start, end, expected) in SPANS.items():
        if text.count(start) != 1 or text.count(end) != 1:
            raise ValueError("OpenSSH section boundary changed")
        span = text[text.index(start) : text.index(end)]
        if sha256(span.encode()).hexdigest() != expected:
            raise ValueError("OpenSSH publisher scope changed; source review required")
        spans[name] = span
    out = arista_software(raw, url, vendor)
    if set(out["cves"]) != {"CVE-2024-6387", "CVE-2024-6409"}:
        raise ValueError("OpenSSH tracked CVE scope changed")
    platform_scope = spans["platforms"].split("Arista Wireless Access Points", 1)[0]
    backport = "The publisher reports that security patches were backported without incrementing the OpenSSH package version string in the listed fixed EOS trains. A scanner version match alone cannot establish vulnerability. Exact image contents and package patch identifiers remain unverified."
    for cid, versions in (
        ("CVE-2024-6387", ["4.32.2F and later releases in the 4.32.x train"]),
        (
            "CVE-2024-6409",
            [
                "4.34.1F and later releases in the 4.34.x train",
                "4.33.4M and later releases in the 4.33.x train",
                "4.32.6M and later releases in the 4.32.x train",
            ],
        ),
    ):
        locator = "Resolution / " + cid + " / Arista EOS-based products"
        claim = assessment(
            cid,
            "Arista EOS",
            "fixed",
            locator,
            [{"expression": v} for v in versions],
            [
                {
                    "category": "vendor_fix",
                    "availability": "vendor_reports_fixed",
                    "details": "Publisher EOS fixed-release statement; historical download availability and installed image are unverified.",
                    "source_locator": locator,
                }
            ],
        )
        claim["platforms"] = [platform_scope]
        claim["exposure"] = [
            {
                "category": "publisher_backport_statement",
                "details": backport,
                "source_locator": "Resolution / Vulnerability Scanner Advisory",
            },
            {
                "category": "publisher_mitigation_context",
                "details": "Publisher mitigation context recommends restricting SSH access. Disabling the authentication timeout can leave resources open to denial of service; it is a temporary mitigation, not an available software fix. Actual device configuration is unknown.",
                "source_scope": "advisory_context_requires_product_configuration_review",
                "source_locator": "Mitigation",
            },
            {
                "category": "publisher_platform_scope",
                "details": platform_scope,
                "source_locator": "Affected Platforms / Arista EOS-based products",
            },
        ]
        out["assessments"].append(claim)
    out["warnings"].append(
        "Reviewed EOS fix and backport statements supplement the existing software assessments. Version strings do not establish package patch state; no image digest, installed service configuration, exact hardware support matrix, lifecycle or historical availability is established. Other product fixes are outside this supplemental EOS extraction."
    )
    return out
