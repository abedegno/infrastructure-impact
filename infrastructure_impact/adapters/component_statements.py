"""Reviewed publisher upgrade statements, distinct from deployment inventories."""

import re
from urllib.parse import urlsplit

from .common import HTML, cves

JUNIPER_URL = "https://www.juniper.net/documentation/us/en/software/junos/release-notes/24.2/junos-evo-release-notes-24.2r1/topics/new-features/feature-descriptions/authentication-access-control.html"
HPE_URL = "https://support.hpe.com/hpesc/public/api/document/sd00004028en_us?page=GUID-C4AB7B5A-16C4-4C37-9C86-17365FE3B258.html"
VERSION = r"\d+(?:\.\d+){1,3}[a-z]{0,3}(?:p\d+)?"
LIMITS = "A publisher component-upgrade reference, not a complete manifest or running-appliance inventory. No security purpose, CVE applicability, backport status, downloadable fix or historical release availability is inferred."


def recognized(url, expected):
    """Unrelated routes may fall back; alternate parameters on this route may not."""
    actual, known = urlsplit(url), urlsplit(expected)
    if (actual.hostname, actual.path) != (known.hostname, known.path):
        return False
    if url != expected:
        raise ValueError("Reviewed component statement URL changed")
    return True


def result(component, version, locator, statement, scope):
    return dict(
        state="scoped",
        blocks=[dict(locator=locator, text=statement, cves=cves(statement))],
        components={component: [version]},
        component_scope=scope + " " + LIMITS,
    )


def juniper_component_statement(raw, url, vendor):
    if not recognized(url, JUNIPER_URL):
        return None
    if vendor != "juniper":
        raise ValueError("Component statement vendor mismatch")
    root = HTML(raw).root
    if [h.text() for h in root.find({"h1"})] != ["Authentication and Access Control"]:
        raise ValueError("Reviewed Junos release-note heading changed")
    candidates = [
        n.text() for n in root.find({"li"}) if n.text().startswith("OpenSSH upgrade to version ")
    ]
    if len(candidates) != 1:
        raise ValueError("Reviewed Junos component statement missing or ambiguous")
    match = re.match(
        r"OpenSSH upgrade to version ("
        + VERSION
        + r") \(([^)]+)\)\s*—Starting in Junos OS Evolved Release 24\.2R1, we've upgraded the version of OpenSSH from ("
        + VERSION
        + r") to ("
        + VERSION
        + r")\. ",
        candidates[0],
    )
    if not match or match[1] != match[4]:
        raise ValueError("Junos OpenSSH target version or release qualifier changed")
    # Only the destination version is a reference for this release. The prior
    # component version in the same sentence is not a second current version.
    return result(
        "openssh",
        match[4],
        "Authentication and Access Control / OpenSSH upgrade",
        candidates[0],
        "Junos OS Evolved 24.2R1; publisher-listed platforms: "
        + match[2]
        + ". Not a Junos OS or SRX-wide statement.",
    )


def hpe_component_statement(raw, url, vendor):
    if not recognized(url, HPE_URL):
        return None
    if vendor != "hpe":
        raise ValueError("Component statement vendor mismatch")
    root = HTML(raw).root
    if [h.text() for h in root.find({"h1"})] != [
        "Enhancements"
    ] or "The following enhancements are part of iLO 6 1.57 release:" not in root.text():
        raise ValueError("Reviewed iLO release enhancement identity changed")
    candidates = [n.text() for n in root.find({"li"}) if "OpenSSL" in n.text()]
    if len(candidates) != 1:
        raise ValueError("iLO OpenSSL statement missing or ambiguous")
    match = re.fullmatch(
        r"Upgradation of OpenSSL from v(" + VERSION + r") to v(" + VERSION + r")\.", candidates[0]
    )
    if not match:
        raise ValueError("Reviewed iLO component-upgrade syntax changed")
    return result(
        "openssl",
        match[2],
        "iLO 6 1.57 / Enhancements / OpenSSL",
        candidates[0],
        "HPE iLO 6 firmware 1.57 enhancement statement; supported server models and other iLO generations are not established by this page.",
    )
