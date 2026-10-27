"""Two reviewed UCS release-note defects; no PDF-wide CVE or version inference."""

import re
from hashlib import sha256
from urllib.parse import urlsplit

from .common import assessment, base, cves, pdf_text

URL = "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/release/notes/b_release-notes-for-cisco-ucs-rack-server-software-release-4_2_3.pdf"
TITLE = "Release Notes for Cisco UCS Rack Server Software, Release 4.2(3)"
IDENTITY = "Cisco-UCS-Rack-4.2.3-OpenSSH-fixes"
PROFILES = (
    {
        "defect": "CSCwk62266",
        "next_defect": "CSCwi59840",
        "release": "4.2(3m)",
        "cve": "CVE-2024-6387",
        "permitted_cves": {"CVE-2024-6387", "CVE-2006-5051"},
        "product": "Cisco UCS servers",
        "section_prefix_sha256": "ce068fbad14b0db48e612d9a81313fa8cbc1da5e028002b4a336818a3b4d77a5",
        "body_sha256": "d87a9d9ed52aa56526cc499ccf714ea61c05cb89ae1f9a9f67691a37dfa0b16d",
    },
    {
        "defect": "CSCwi59840",
        "next_defect": "CSCwj41082",
        "release": "4.2(3l)",
        "cve": "CVE-2023-48795",
        "permitted_cves": {"CVE-2023-48795"},
        "product": "Cisco IMC",
        "section_prefix_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "body_sha256": "c50a48945ffb0638fcaf86a9d11ef538dddd39a8524a4b0f3d2be1857ef75d53",
    },
)


def security_fixes(raw, url, vendor):
    if url != URL:
        actual, expected = urlsplit(url), urlsplit(URL)
        if (actual.hostname, actual.path) == (expected.hostname, expected.path):
            raise ValueError("Reviewed UCS PDF URL parameters changed")
        return None
    if vendor != "cisco" or not isinstance(raw, bytes) or not raw.startswith(b"%PDF"):
        raise ValueError("Reviewed UCS source must be a Cisco PDF")
    text = " ".join(pdf_text(raw, layout=True).split())
    if not text.startswith(TITLE + " "):
        raise ValueError("Reviewed UCS document title changed")
    out = base(vendor, url, IDENTITY, "Cisco UCS Rack 4.2(3): scoped OpenSSH security fixes")
    out.update(source_format="Vendor release notes PDF", document_status="published")
    for profile in PROFILES:
        start = "Defect ID - " + profile["defect"]
        end = "Defect ID - " + profile["next_defect"]
        if text.count(start) != 1 or text.count(end) != 1:
            raise ValueError("Reviewed UCS defect boundary missing or ambiguous")
        prefix, rest = text.split(start)
        headings = re.findall(r"Security Fixes in Release [^ ]+", prefix)
        if not headings or headings[-1] != "Security Fixes in Release " + profile["release"]:
            raise ValueError("Reviewed UCS fixed-release heading changed")
        section_prefix = prefix.rsplit(headings[-1], 1)[1].strip()
        if sha256(section_prefix.encode()).hexdigest() != profile["section_prefix_sha256"]:
            raise ValueError("Reviewed UCS section context changed; source review required")
        if end not in rest:
            raise ValueError("Reviewed UCS defect boundary order changed")
        body = rest.split(end)[0].strip()
        # The reviewed normalized span includes its trailing section heading and,
        # for Terrapin, the known page footer/running header. Hash the entire span
        # rather than dropping those lines and accidentally ending at a header.
        if (
            sha256(body.encode()).hexdigest() != profile["body_sha256"]
            or set(cves(body)) != profile["permitted_cves"]
        ):
            raise ValueError("Reviewed UCS defect text or scope changed; source review required")
        locator = "Security Fixes in Release " + profile["release"] + " / " + profile["defect"]
        claim = assessment(
            profile["cve"],
            profile["product"],
            "fixed",
            locator,
            [{"expression": profile["release"]}],
            [
                {
                    "category": "vendor_fix",
                    "availability": "vendor_reports_fixed",
                    "details": "The publisher lists "
                    + profile["defect"]
                    + " in the security-fix section for release "
                    + profile["release"]
                    + ". Exact hardware applicability and download availability remain unverified.",
                    "source_locator": locator,
                }
            ],
        )
        claim["product_context"] = [["release_series", "Cisco UCS Rack Server Software 4.2(3)"]]
        claim["exposure"] = [
            {
                "category": "fixed_only_statement",
                "details": "A release-specific fix statement does not establish a prior affected version range, every UCS model, or the OpenSSH version shipped in this release.",
                "source_locator": locator,
            }
        ]
        out["cves"].append(profile["cve"])
        out["assessments"].append(claim)
    out["cves"].sort()
    out["warnings"] = [
        "Only the two reviewed defect sections are normalized. Background regression CVE references, upstream OpenSSH version ranges and neighboring processor/IMC defects do not broaden product, version or CVE scope.",
        "PDF cover publication/modification dates describe the whole release-note document, not the first disclosure or availability of these fixes. CVE-specific publication/update dates and historical download availability remain unverified.",
        "These are fixed-only release statements. Earlier affected builds and individual hardware models are not enumerated. UCS server-management evidence does not establish ASA, FTD, IOS or other Cisco product exposure.",
    ]
    return out
