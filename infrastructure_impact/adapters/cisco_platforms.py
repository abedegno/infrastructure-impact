"""One reviewed per-CVE CSAF platform bridge, without generic prose matching."""

import hashlib
import json
import re

from .switching import extract as switching_extract

URL = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fast-Zqr6DD5/csaf/cisco-sa-fast-Zqr6DD5.json"
REVIEWED_SHA256 = "e38453288e918dcba73661b7c7fa507c4521b695bd8cfdfd9099cd08af4bbe69"
CVES = {"CVE-2021-1375", "CVE-2021-1376"}
PLATFORM_SENTENCE = (
    "A vulnerability in the fast reload feature of Cisco IOS XE Software running on "
    "Cisco Catalyst 3650, Cisco Catalyst 3850, Cisco Catalyst 9300, and Cisco Catalyst "
    "9300L Series Switches could allow"
)


def extract(raw, url, vendor, document):
    result = switching_extract(raw, url, vendor, document)
    if vendor != "cisco" or url != URL:
        return result
    digest = hashlib.sha256(raw).hexdigest()
    if digest != REVIEWED_SHA256:
        result["issues"].append("reviewed_platform_scope_changed")
        return result
    source = json.loads(raw)
    notes = source.get("document", {}).get("notes", [])
    vulnerabilities = source.get("vulnerabilities", [])
    valid = (
        document.get("advisory_id") == "cisco-sa-fast-Zqr6DD5"
        and set(document.get("cves", [])) == CVES
        and len(vulnerabilities) == 2
        and {v.get("cve") for v in vulnerabilities} == CVES
        and len(notes) > 3
        and notes[1].get("title") == "Vulnerable Products"
        and notes[3].get("title") == "Details"
    )
    details = notes[3].get("text", "") if valid else ""
    warning = re.search(
        r"[Aa] software release that is affected by one of the vulnerabilities "
        r"may not be affected by the other vulnerability\.",
        details,
    )
    headings = list(re.finditer(r"(?m)^(CVE-2021-137[56]):[^\r\n]*", details))
    sections = {}
    for i, heading in enumerate(headings):
        end = headings[i + 1].start() if i + 1 < len(headings) else len(details)
        sections[heading[1]] = " ".join(details[heading.start() : end].split())
    if (
        not valid
        or not warning
        or len(headings) != 2
        or set(sections) != CVES
        or not all(PLATFORM_SENTENCE in text and len(text) <= 4000 for text in sections.values())
    ):
        result["issues"].append("reviewed_platform_scope_changed")
        return result
    for claim in result["claims"]:
        cid = claim["cve_id"]
        if cid not in sections or claim["family"] != "cisco-iosxe" or claim["status"] != "affected":
            continue
        # Keep the CSAF's CVE/product-ID status and version branch untouched.
        # Both exact names are repeated in this CVE's reviewed Details section.
        claim["named_platforms"] = ["Cisco Catalyst 9300", "Cisco Catalyst 9300L"]
        claim["platform_bindings"] = [
            {
                "platform": platform,
                "model": model,
                "basis": "publisher_explicit",
                "source": {
                    "source_url": url,
                    "source_sha256": digest,
                    "retrieved_at": None,
                    "source_locator": f"/document/notes/3 (Details / {cid})",
                },
            }
            for platform, model in [
                ("Cisco Catalyst 9300", "9300"),
                ("Cisco Catalyst 9300L", "9300L"),
            ]
        ]
        claim["scope_level"] = "model_qualified"
        claim["conditions"].extend([warning[0], sections[cid]])
    return result
