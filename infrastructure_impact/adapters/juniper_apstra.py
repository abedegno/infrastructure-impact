"""Exact-route Apstra PDF issue scopes, separate from neighbouring issues and SRX."""

from urllib.parse import urlsplit

from .common import assessment, base, pdf_text

PREFIX = "https://supportportal.juniper.net/sfc/servlet.shepherd/document/download/"
WORKAROUND_URL = PREFIX + "069Dp00000FJIxcIAH"
PLANNED_URL = PREFIX + "069Dp00000FJIqkIAH"
HEADING = "OpenSSH Vulnerability CVE-2024-6387 in Apstra Server Version 4.2.x (AOS-47640)"
PARAGRAPH = "Apstra server version 4.2.x, which is based on Jammy Ubuntu 22.04 includes OpenSSH version 8.9p1, is exposed to a security vulnerability identified as CVE-2024-6387."
PLANNED = "Apstra Server Version 4.2.2.1 and 5.0.0 will include a fixed OpenSSH package."
WORKAROUND = "We recommend modifying the SSHD configuration according to the Ubuntu Security Team's guidance on CVE-2024-6387 to mitigate the risk. Contact Juniper Apstra Support for assistance."
COMMANDS = "Set LoginGraceTime to 0 in /etc/ssh/sshd_config sudo systemctl restart sshd"
PROFILES = {
    WORKAROUND_URL: {
        "title": "Juniper Apstra Version 4.2.0 Release Notes",
        "identity": "Apstra-4.2.0-AOS-47640",
        "next_heading": "SSH Terrapin Vulnerability Workaround Using SSH aes128-gcm or aes256-gcm Ciphers Is Not Supported by Apstra Paramiko SSH Client (AOS-44336)",
        "body": PARAGRAPH + " Workaround " + WORKAROUND + " " + COMMANDS,
    },
    PLANNED_URL: {
        "title": "Juniper Apstra Version 5.0.0, 5.0.1 Release Notes",
        "identity": "Apstra-AOS-47640",  # Preserve the existing reviewed record identity.
        "next_heading": "USN-6891-1(Python vulnerabilities) from Tenable scan report (AOS-48042)",
        "body": PARAGRAPH + " Resolution " + PLANNED,
    },
}


def scoped_issue(raw, url, vendor):
    profile = PROFILES.get(url)
    if profile is None:
        parsed = urlsplit(url)
        if any(
            (parsed.hostname, parsed.path) == (urlsplit(u).hostname, urlsplit(u).path)
            for u in PROFILES
        ):
            raise ValueError("Reviewed Apstra PDF URL parameters changed")
        return None
    if vendor != "juniper" or not isinstance(raw, bytes) or not raw.startswith(b"%PDF"):
        raise ValueError("Reviewed Apstra source must be a Juniper PDF")
    text = " ".join(pdf_text(raw, layout=True).split())
    if not text.startswith(profile["title"] + " ") or text.count(HEADING) != 1:
        raise ValueError("Reviewed Apstra document/issue identity changed")
    tail = text.split(HEADING, 1)[1].strip()
    if tail.count(profile["next_heading"]) != 1:
        raise ValueError("Apstra neighbouring-issue boundary changed")
    block = tail.split(profile["next_heading"], 1)[0].strip()
    if block != profile["body"]:
        raise ValueError("Apstra issue scope or remediation wording changed; review source")
    return profile, block


def apstra_advisory(raw, url, vendor):
    scoped = scoped_issue(raw, url, vendor)
    if scoped is None:
        return None
    profile, _ = scoped
    out = base(vendor, url, profile["identity"], "Apstra release notes: OpenSSH CVE-2024-6387")
    out.update(
        cves=["CVE-2024-6387"],
        source_format="Vendor release notes PDF",
        document_status="published",
    )
    planned = url == PLANNED_URL
    claim = assessment(
        "CVE-2024-6387",
        "Apstra Server 4.2.x (Ubuntu 22.04)",
        "affected",
        "AOS-47640 / OpenSSH vulnerability and " + ("Resolution" if planned else "Workaround"),
        [{"expression": "Apstra server 4.2.x, based on Ubuntu 22.04, includes OpenSSH 8.9p1"}],
        [
            {
                "category": "vendor_fix" if planned else "workaround",
                "details": "Apstra Server 4.2.2.1 and 5.0.0 will include a fixed OpenSSH package"
                if planned
                else COMMANDS,
                "availability": "planned" if planned else "partial_mitigation",
                "source_locator": "AOS-47640 / " + ("Resolution" if planned else "Workaround"),
            }
        ],
    )
    claim["product_context"] = [["product_name", "Apstra Server"], ["product_version", "4.2.x"]]
    claim["exposure"] = [
        {
            "category": "publisher_component_reference",
            "details": "The publisher explicitly associates Apstra Server 4.2.x, Jammy Ubuntu 22.04 and OpenSSH 8.9p1 with CVE-2024-6387. This is separate from SRX/Junos appliance scope.",
            "source_locator": HEADING,
        },
        {
            "category": "document_scope",
            "details": profile["title"]
            + ". The component statement describes Apstra Server 4.2.x; document-title versions do not broaden that scope or establish a running deployment.",
        },
    ]
    out["assessments"] = [claim]
    out["warnings"] = [
        "Only the bounded AOS-47640 issue is normalized. Adjacent Terrapin/Paramiko client and Python issues supply no CVEs, fixes or component versions to this record. Separate document editions are not a before/after observation sequence.",
        "Publisher advisory publication/update dates and actual release availability are unverified. PDF footer dates are not treated as first disclosure or product release dates. Future-tense fixes remain planned; a workaround is not a verified fixed build. Apstra evidence never establishes SRX or Junos exposure.",
    ]
    return out


def apstra_component_reference(raw, url, vendor):
    scoped = scoped_issue(raw, url, vendor)
    if scoped is None:
        return None
    profile, _ = scoped
    return {
        "state": "scoped",
        "blocks": [
            {
                "locator": HEADING + " / component paragraph",
                "text": PARAGRAPH,
                "cves": ["CVE-2024-6387"],
            }
        ],
        "components": {"openssh": ["8.9p1"]},
        "component_scope": "Publisher AOS-47640 reference for Apstra Server 4.2.x on Jammy Ubuntu 22.04 in "
        + profile["title"]
        + ". It explicitly names CVE-2024-6387. This is not a complete component manifest or installed-device inventory; backports, exact builds and deployment exposure remain unverified. Document-title versions, SRX/Junos products and sibling issues are outside the component claim.",
    }
