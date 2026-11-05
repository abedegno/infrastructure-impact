"""Reviewed SA-0202/0203 applicability and SA-0204 advance-notice boundaries."""

import re

from .arista_legacy_scope import article, children, one
from .common import assessment, cves

PREFIX = "https://www.arista.com/en/support/advisories-notices/security-advisory/"
FORMAT = "Arista reviewed current applicability HTML"
NOTICE_FORMAT = "Arista reviewed advance notice HTML"
ROUTES = {
    "0202": ("24853-security-advisory-0202", ["CVE-2026-111497"]),
    "0203": ("25023-security-advisory-0203", ["CVE-2026-98432"]),
}
PRODUCTS = {
    "0202": "VeloCloud Orchestrator",
    "0203": "Arista Network Detection and Response (NDR) Security Platform",
}
AFFECTED = "The following products are affected by this vulnerability:"
UNAFFECTED = {
    "0202": "The following product versions and platforms are not affected by this vulnerability:",
    "0203": "The following product versions and platforms are not affected by this vulnerability. Please note, at this point this is an assessment of required configuration for exploitation, ie MPTCP being enabled, not of the vulnerable ipv4 code being present. Products with vulnerable ipv4 code will have fixed releases over time:",
}
TRIAGE = {
    "0202": "The following product versions and platforms are undergoing triage to determine if they are affected by this vulnerability:",
    "0203": "The following product versions and platforms are under triage to determine if they are by this vulnerability:",
}
NOTICE_SLUG = "25024-security-advisory-0204"


def inline(node):
    """Only the observed visible inline emphasis; hidden/nested scope is unsupported."""
    if node.attrs or any(n.tag not in {"b", "strong", "br"} or n.attrs for n in children(node)):
        raise ValueError("Unreviewed Arista scope markup")
    for n in children(node):
        inline(n)
    if not node.text() or cves(node.text()):
        raise ValueError("Empty or CVE-bearing Arista local scope")
    return node.text()


def leaves(node):
    items = children(node)
    if (
        node.tag != "ul"
        or node.attrs
        or not items
        or any(n.tag != "li" for n in items)
        or any(isinstance(c, str) and c.strip() for c in node.children)
    ):
        raise ValueError("Incomplete Arista scope list")
    values = [inline(n) for n in items]
    if len(values) != len(set(values)):
        raise ValueError("Repeated Arista local scope")
    return values


def nonempty(nodes):
    return [n for n in nodes if n.text()]


def context(nodes, locator):
    return {
        "category": "publisher_applicability",
        "details": "\n".join(n.text() for n in nodes),
        "source_scope": "advisory_context_requires_product_configuration_review",
        "source_locator": locator,
    }


def parse(raw: bytes, url: str, vendor: str) -> dict:
    number = next((n for n, (slug, _) in ROUTES.items() if url == PREFIX + slug), None)
    if number is None:
        raise ValueError("Unreviewed current Arista route")
    _, out, sections = article(raw, url, vendor, number, routes=ROUTES)
    out["source_format"] = FORMAT
    # The older article helper checks route/header/tracking IDs and revision dates.
    dates = [row["date"] for row in out["timeline"]]
    if dates != sorted(dates):
        raise ValueError("Current Arista revision chronology changed")
    product = PRODUCTS[number]
    software = nonempty(sections.get("Affected Software", []))
    if number == "0203":
        qualification = one((n for n in software if n.tag == "p"), "MPTCP qualification")
        if "MPTCP must be enabled at the kernel level." not in qualification.text():
            raise ValueError("Arista MPTCP prerequisite changed")
        software = [n for n in software if n is not qualification]
    if (
        len(software) != 2
        or software[0].tag != ("div" if number == "0202" else "h4")
        or inline(software[0]) != product
    ):
        raise ValueError("Current Arista software grouping changed")
    versions = leaves(software[1])
    pattern = (
        r"\d+(?:\.\d+){3} and below releases in the \d+\.\d+\.\d+ train"
        if number == "0202"
        else r"All versions prior to and including \d+\.\d+\.\d+"
    )
    if any(not re.fullmatch(pattern, value) for value in versions):
        raise ValueError("Unreviewed current Arista version expression")
    platform = nonempty(sections.get("Affected Platforms", []))
    if len(platform) != 6 or [n.tag for n in platform] != ["div", "ul"] * 3:
        raise ValueError("Current Arista status/list boundaries changed")
    if [inline(platform[i]) for i in (0, 2, 4)] != [AFFECTED, UNAFFECTED[number], TRIAGE[number]]:
        raise ValueError("Current Arista status markers changed")
    affected_platforms = leaves(platform[1])
    expected_platform = product + (
        " (Formerly VeloCloud Orchestrator by Broadcom)"
        if number == "0202"
        else " (Formerly Awake NDR)"
    )
    if affected_platforms != [expected_platform]:
        raise ValueError("Arista affected product attribution changed")
    excluded = children(platform[3])
    if (
        len(excluded) < 3
        or [n.tag for n in excluded[:2]] != ["li", "ul"]
        or inline(excluded[0]) != "Arista EOS-based products:"
        or any(n.tag != "li" for n in excluded[2:])
    ):
        raise ValueError("Arista EOS exclusion boundary changed")
    eos_platforms = leaves(excluded[1])
    other_products = [inline(n) for n in excluded[2:]]
    triage = leaves(platform[5])
    if len(set(other_products + triage + affected_platforms)) != len(
        other_products + triage + affected_platforms
    ):
        raise ValueError("Conflicting Arista product statuses")
    configuration = nonempty(sections.get("Required Configuration for Exploitation", []))
    if (
        not configuration
        or configuration[0].tag != "h4"
        or inline(configuration[0]) != product
        or not all(n.tag == "p" for n in configuration[1:])
        or len(configuration) < 2
    ):
        raise ValueError("Arista product configuration boundary changed")
    required = (
        ("Brotli-compressed response", "outbound HTTP client", "automatic decompression")
        if number == "0202"
        else ("disable MPTCP on NDR appliances", "not user-operable")
    )
    if any(value not in " ".join(n.text() for n in configuration) for value in required):
        raise ValueError("Current Arista configuration qualification changed")
    affected = assessment(
        out["cves"][0],
        product,
        "affected",
        "Affected Software / " + product,
        [{"expression": v} for v in versions],
    )
    affected["platforms"] = affected_platforms
    affected["exposure"] = [
        context(configuration, "Required Configuration for Exploitation / " + product)
    ]
    if number == "0203":
        affected["exposure"].append(
            context([qualification], "Affected Software / MPTCP qualification")
        )
    eos = assessment(
        out["cves"][0],
        "Arista EOS",
        "unaffected",
        "Affected Platforms / not affected / Arista EOS-based products",
    )
    eos["platforms"] = eos_platforms
    eos["exposure"] = [context([platform[2]], "Affected Platforms / not affected qualifier")]
    out["assessments"] = [affected, eos]
    for status, labels, marker in [
        ("unaffected", other_products, platform[2]),
        ("investigating", triage, platform[4]),
    ]:
        for label in labels:
            claim = assessment(
                out["cves"][0], label, status, "Affected Platforms / " + status + " / " + label
            )
            claim["exposure"] = [context([marker], "Affected Platforms / " + status + " qualifier")]
            out["assessments"].append(claim)
    resolution = nonempty(sections.get("Resolution", []))
    if not resolution:
        raise ValueError("Current Arista resolution context missing")
    if number == "0202":
        # Scope fixes only to the same explicitly named product, never the EOS exclusions.
        start = next(
            (
                i
                for i, n in enumerate(resolution)
                if n.tag == "div"
                and n.text() == "The issue is fixed in the following product releases:"
            ),
            None,
        )
        if (
            start is None
            or len(resolution[start:]) != 3
            or resolution[start + 1].tag != "div"
            or inline(resolution[start + 1]) != product
        ):
            raise ValueError("Current Arista fixed-release grouping changed")
        fixes = leaves(resolution[start + 2])
        if any(
            not re.fullmatch(r"\d+(?:\.\d+){3} and later releases in the \d+\.\d+\.\d+ train", v)
            for v in fixes
        ):
            raise ValueError("Current Arista fixed-release expression changed")
        affected["remediations"] = [
            {
                "category": "vendor_fix",
                "details": v,
                "availability": "vendor_reports_fixed",
                "source_locator": "Resolution / " + product,
            }
            for v in fixes
        ]
    elif (
        "This section will be updated once fixed releases are available for the underlying kernel issue or to disable MPTCP."
        not in " ".join(n.text() for n in resolution)
    ):
        raise ValueError("Arista planned defense-in-depth resolution changed")
    for name in ("Mitigation", "Resolution"):
        out["notes"].append(
            {
                "category": "publisher_context",
                "text": "\n".join(n.text() for n in sections.get(name, [])),
                "source_locator": name,
            }
        )
    out["warnings"].append(
        "Only explicitly listed platforms are excluded; omitted platforms remain unknown. Literal slash labels are not expanded. Source-wide severity and planned defense-in-depth fixes do not establish platform exposure, available releases or required upgrades."
    )
    return out


def advance_notice(raw: bytes, url: str, vendor: str) -> dict:
    a, out, _ = article(raw, url, vendor, "0204", routes={"0204": (NOTICE_SLUG, [])})
    if url != PREFIX + NOTICE_SLUG or cves(a.text()):
        raise ValueError("Arista advance notice identity or CVE scope changed")
    nodes = children(a)
    headings = [n for n in nodes if n.tag == "h4"]
    expected = [
        "Advance Notice for Publication of November 10, 2026 Security Advisories Release",
        "Update Type:",
        "Overview:",
        "Background:",
        "Scope of the Upcoming Release:",
        "Next Steps for Our Customers:",
    ]
    if [n.text() for n in headings[:6]] != expected:
        raise ValueError("Arista advance-notice headings changed")
    groups = {}
    current = None
    for n in nodes:
        if n.tag == "h4":
            current = n.text() if n.text() in expected[1:] else None
            if current in groups:
                raise ValueError("Repeated advance-notice field")
            if current:
                groups[current] = []
        elif current and n.text():
            if n.tag != "p":
                raise ValueError("Unreviewed advance-notice field layout")
            groups[current].append(n.text())
    if (
        set(groups) != set(expected[1:])
        or any(not values for values in groups.values())
        or groups["Update Type:"] != ["Informational"]
    ):
        raise ValueError("Arista informational notice fields changed")
    if (
        "Arista is providing advance notice for multiple Security Advisories scheduled for publication on November 10, 2026."
        not in " ".join(groups["Overview:"])
        or "This notice is intended solely to help Arista customers prepare for the upcoming releases."
        not in " ".join(groups["Next Steps for Our Customers:"])
    ):
        raise ValueError("Arista positive advance-notice markers changed")
    out["source_format"] = NOTICE_FORMAT
    out["notes"] = [
        {"category": "publisher_context", "text": "\n".join(values), "source_locator": label}
        for label, values in groups.items()
    ]
    out["warnings"] = [
        "Advance publication notice only. Scheduled dates and possible products do not establish present CVE assessments, fix availability or upgrade events."
    ]
    return out
