"""Reviewed older applicability boundaries; no missing-CVE or configuration inference."""

import re

from .arista_scoped import (
    article,
    leading_inline,
    reviewed_sections,
    section_context,
    version_expressions,
)
from .common import Node, assessment, cves


def tracked(a):
    return cves(
        " ".join(
            n.text()
            for n in a.children
            if isinstance(n, Node)
            and n.tag == "p"
            and "The CVE-ID tracking this issue:" in n.text()
        )
    )


def finish(out, ids, context):
    out.update(
        cves=ids,
        document_status="published",
        source_format="Arista reviewed applicability boundaries HTML",
    )
    for claim in out["assessments"]:
        claim["exposure"] = context
    out["warnings"] = [
        "Only reviewed local applicability statements are normalized. Configuration prerequisites and exclusions remain ordered publisher context. Resolution does not establish a downloadable fix, public release availability or automatic appliance matching."
    ]
    return out


def radius(raw, url, vendor):
    a, out = article(raw, url, "0101")
    ids = tracked(a)
    if vendor != "arista" or ids != ["CVE-2024-3596"]:
        raise ValueError("Reviewed RADIUS CVE identity changed")
    sections = reviewed_sections(a, ("Affected Software and Platforms", "Unaffected Platforms"))
    required = sections.get("Required Configuration for Exploitation", [])
    if not all(
        s in " ".join(n.text() for n in required)
        for s in (
            "RADIUS is configured.",
            "RADIUS is configured without using RadSec",
            "RADIUS is used for non-EAP authentication",
        )
    ):
        raise ValueError("RADIUS applicability prerequisites changed")
    context = section_context(sections) + [
        dict(
            category="publisher_unaffected_platforms",
            details="\n".join(n.text() for n in sections.get("Unaffected Platforms", [])),
            source_scope="advisory_context_requires_product_configuration_review",
            source_locator="Unaffected Platforms",
        )
    ]
    groups = {}
    current = None
    for n in sections.get("Affected Software and Platforms", []):
        if n.tag == "h4":
            current = n.text()
            if current in groups:
                raise ValueError("Repeated RADIUS product section")
            groups[current] = []
        elif current:
            groups[current].append(n)
        else:
            raise ValueError("Unbound RADIUS applicability content")
    expected = {
        "EOS Products",
        "WI-FI Access Points",
        "Cloudvision Products",
        "Arista 7130 Systems running MOS",
        "DMF/CCF/MCD",
        "Arista Edge Threat Management - Arista NG Firewall",
    }
    if set(groups) != expected:
        raise ValueError("Reviewed RADIUS product groups changed")
    for group, nodes in groups.items():
        lists = [n for n in nodes if n.tag == "ul"]
        if len(lists) != 1:
            raise ValueError("RADIUS product list boundary changed")
        items = [n for n in lists[0].children if isinstance(n, Node) and n.tag == "li"]
        if group == "EOS Products":
            if (
                len(items) != 1
                or leading_inline(items[0])
                != "The following EOS products running versions 4.34.0F and older are affected:"
            ):
                raise ValueError("Reviewed EOS RADIUS version qualifier changed")
            platforms = [n.text() for n in items[0].find({"li"})]
            if not platforms:
                raise ValueError("EOS RADIUS platforms missing")
            claim = assessment(
                ids[0],
                "Arista EOS",
                "affected",
                "Affected Software and Platforms / EOS Products",
                [dict(expression="4.34.0F and older")],
            )
            claim["platforms"] = platforms
            out["assessments"].append(claim)
            continue
        qualifiers = [n.text() for n in nodes if n.tag in {"p", "div"}]
        qualifier = " ".join(qualifiers)
        if (
            not qualifier.startswith("All versions")
            or "are affected if they are running the affected configuration" not in qualifier
        ):
            raise ValueError("RADIUS configuration qualifier missing")
        if not items or any(list(n.find({"ul", "ol"})) for n in items):
            raise ValueError("RADIUS product scope changed")
        for item in items:
            out["assessments"].append(
                assessment(
                    ids[0],
                    item.text(),
                    "affected",
                    "Affected Software and Platforms / " + group,
                    [dict(expression=qualifier)],
                )
            )
    return finish(out, ids, context)


def continuation(raw, url, vendor):
    a, out = article(raw, url, "0094")
    sections = reviewed_sections(a)
    ids = cves(" ".join(n.text() for n in sections.get("Description", [])))
    if vendor != "arista" or len(ids) != 9:
        raise ValueError("Reviewed HTTP/2 reference cohort changed")
    products = {
        "Streaming Telemetry Agent (TerminAttr) versions:": (
            "CVE-2023-45288",
            "Arista Streaming Telemetry Agent (TerminAttr)",
        ),
        "EOS release version:": ("CVE-2023-45288", "Arista EOS"),
        "WI-FI Access Points versions:": ("CVE-2023-45288", "Arista Wireless Access Points"),
        "Awake Security versions": ("CVE-2024-28182", "Arista Awake NDR"),
    }
    current_cve = product = None
    seen = set()
    for n in sections.get("Affected Software", []):
        text = n.text()
        if n.tag == "p" and text.startswith(
            "Please consult the section on Required Configuration for Exploitation"
        ):
            continue
        if n.tag == "h4":
            match = re.fullmatch(
                r"The following product releases are affected by (CVE-\d{4}-\d+):", text
            )
            if not match or match[1] not in ids:
                raise ValueError("HTTP/2 local CVE grouping changed")
            current_cve, product = match[1], None
        elif n.tag == "div" and text in products:
            expected_cve, product = products[text]
            if current_cve != expected_cve:
                raise ValueError("HTTP/2 product outside local CVE scope")
        elif n.tag == "ul" and product and product not in seen:
            out["assessments"].append(
                assessment(
                    current_cve,
                    product,
                    "affected",
                    "Affected Software / " + current_cve + " / " + product,
                    version_expressions(n),
                )
            )
            seen.add(product)
        elif text:
            raise ValueError("Unreviewed HTTP/2 affected software content")
    if seen != {p for _, p in products.values()} or not sections.get(
        "Required Configuration for Exploitation"
    ):
        raise ValueError("HTTP/2 product groups or prerequisites missing")
    return finish(out, ids, section_context(sections))


def xz_unaffected(raw, url, vendor):
    a, out = article(raw, url, "0095")
    sections = reviewed_sections(a)
    ids = tracked(a)
    if (
        vendor != "arista"
        or ids != ["CVE-2024-3094"]
        or "No Arista products are affected. Individual products are listed below." not in a.text()
        or "The following product versions and platforms are NOT affected by this vulnerability:"
        not in " ".join(n.text() for n in sections.get("Affected Platforms", []))
    ):
        raise ValueError("Reviewed publisher-wide xz exclusion changed")
    out["assessments"] = [
        assessment(
            ids[0],
            "Arista products (publisher-wide current statement)",
            "unaffected",
            "Vulnerability Assessment / No Arista products are affected.",
            [],
        )
    ]
    return finish(out, ids, section_context(sections))


def restricted_cloud_notice(raw, url, vendor):
    a, out = article(raw, url, "0092")
    sections = reviewed_sections(a)
    if (
        vendor != "arista"
        or cves(a.text())
        or "BUG 880654" not in a.text()
        or "This issue is NOT present in the standard offerings" not in a.text()
        or [n.text() for n in sections.get("Affected Software", []) if n.tag == "ul"]
        != [
            "CVP on AWS AMIs with CentOS version 7.9.2009 CVP on GCP GCP image with CentOS version 7.9.2009 (crc32c hash: Rvd78A==)"
        ]
    ):
        raise ValueError("Reviewed restricted-cloud non-CVE scope changed")
    out.update(document_status="published", source_format="Arista security notice without CVE")
    for name in (
        "Description",
        "Affected Software",
        "Affected Platforms",
        "Required Configuration for Exploitation",
        "Mitigation",
        "Resolution",
    ):
        if not sections.get(name):
            raise ValueError("Restricted-cloud notice context missing")
        out["notes"].append(
            dict(
                category="publisher_context",
                text="\n".join(n.text() for n in sections[name]),
                source_locator=name,
            )
        )
    out["warnings"] = [
        "A restricted AWS/GCP offering is named, with explicit exclusions for standard CloudVision offerings and an unreleased GCP image. No CVE identifier is supplied. No CVE mapping, standard-product exposure, historical public availability or concealment is inferred."
    ]
    return out
