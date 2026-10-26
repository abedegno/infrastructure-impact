"""Reviewed exceptional Arista layouts; no upstream-to-appliance inference."""

import re
from urllib.parse import urlsplit

from .common import HTML, Node, assessment, base, cves, iso_date

SOFTWARE = {
    "EOS Versions": "Arista EOS",
    "Wi-Fi Access Points Versions": "Arista Wi-Fi Access Points",
    "CloudVision Appliance Software (CVA) Versions": "CloudVision Appliance Software (CVA)",
    "DANZ Monitoring Fabric (DMF) Versions": "DANZ Monitoring Fabric (DMF)",
    "Arista Multi Cloud Director (MCD) Versions": "Arista Multi Cloud Director (MCD)",
    "Arista Converged Cloud Fabric (CCF) Versions": "Arista Converged Cloud Fabric (CCF)",
    "Arista Network Detection and Response (NDR) Versions": "Arista Network Detection and Response (NDR)",
    "CloudVision Portal (CVP) Versions": "CloudVision Portal (CVP)",
}


def article(raw, url, number):
    slug = urlsplit(url).path.rsplit("/", 1)[-1]
    if not slug.endswith("-security-advisory-" + number):
        raise ValueError("Unexpected Arista advisory identity")
    tree = HTML(raw).root
    nodes = [n for n in tree.find({"div"}) if "item-page" in (n.attrs.get("class") or "").split()]
    if len(nodes) != 1 or not any(
        "Security Advisory " + number in n.text() for n in nodes[0].find({"h2"})
    ):
        raise ValueError("Reviewed Arista article boundary/identity changed")
    a = nodes[0]
    dates = [
        cells[1]
        for row in a.find({"tr"})
        if len(cells := [c.text() for c in row.find({"td"})]) == 3 and cells[0] == "1.0"
    ]
    if len(dates) != 1:
        raise ValueError("Initial Arista publication row missing")
    return a, base("arista", url, slug, "Arista Security Advisory " + number, iso_date(dates[0]))


def non_cve_security_notice(raw, url, vendor):
    a, out = article(raw, url, "0146")
    if (
        vendor != "arista"
        or cves(a.text())
        or not any(
            n.attrs.get("href") == "https://github.com/advisories/GHSA-hrxh-6v49-42gf"
            for n in a.find({"a"})
        )
        or "Affected Software" not in a.text()
    ):
        raise ValueError("Reviewed non-CVE security notice changed")
    out.update(document_status="published", source_format="Arista security notice without CVE")
    out["warnings"] = [
        "The reviewed article names a GHSA and product applicability but contains no CVE identifier. Retained as a security notice, not a CVE impact assessment. No GHSA-to-CVE mapping, blanket unaffectedness, available fix or concealment is inferred."
    ]
    return out


def leading_inline(n):
    text = []
    for child in n.children:
        if isinstance(child, Node) and child.tag not in {"b", "strong", "span", "a", "br"}:
            break
        text.append(child.text() if isinstance(child, Node) else child)
    return " ".join(" ".join(text).split())


def grouped_software(raw, url, vendor):
    a, out = article(raw, url, "0147")
    if vendor != "arista":
        raise ValueError("Unexpected vendor")
    nodes = list(a.find({"h2", "h3", "h4", "div", "ul", "p"}))
    header = a.text().split("Description", 1)[0]
    ids = cves(header)
    if not ids:
        raise ValueError("CVE identity header missing")
    out.update(
        cves=ids, document_status="published", source_format="Arista CVE-grouped software HTML"
    )
    # Preserve complete publisher prerequisites and hardware scope. The software
    # list supplies claims; configuration prose and bug references cannot broaden it.
    context = []
    section = None
    for n in a.find({"h2", "h3", "h4", "p", "pre", "ul", "div"}):
        if n.tag in {"h2", "h3"} and n.text() in {
            "Affected Platforms",
            "Required Configuration for Exploitation",
        }:
            section = n.text()
        elif n.tag == "h2":
            section = "Advisory Description" if n.text() == "Description" else None
        if section and n.tag == "div":
            marker = leading_inline(n)
            if marker and (cves(marker) or "following" in marker.lower()):
                context.append(
                    dict(category="publisher_scope", details=marker, source_scope=section)
                )
        if section and n.tag in {"p", "pre", "h3", "h4", "li"} and n.text():
            context.append(dict(category="publisher_scope", details=n.text(), source_scope=section))
    context = [
        dict(
            category="publisher_" + section.lower().replace(" ", "_"),
            details="\n".join(row["details"] for row in context if row["source_scope"] == section),
            source_scope="advisory_context_requires_product_configuration_review",
            source_locator=section,
        )
        for section in dict.fromkeys(row["source_scope"] for row in context)
    ]
    active = False
    product = None
    group = None
    seen = set()
    for n in nodes:
        text = n.text()
        if n.tag in {"h2", "h3"}:
            active = text == "Affected Software"
            product = group = None
        if not active:
            continue
        if n.tag == "h4":
            product = SOFTWARE.get(text)
            group = None
            if product is None and text != "Impact on DANZ Monitoring Fabric (DMF)":
                raise ValueError("Unreviewed Arista product heading")
        elif n.tag == "div" and cves(leading_inline(n)):
            marker = leading_inline(n)
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}(?:\s+and\s+CVE-\d{4}-\d{4,})*", marker, re.I):
                raise ValueError("Unreviewed CVE grouping marker")
            group = cves(marker)
            if not set(group) <= set(ids):
                raise ValueError("Product group outside header CVE scope")
        elif n.tag == "ul":
            if not product or not group:
                raise ValueError("Unbound Arista product/version list")
            versions = [c.text() for c in n.children if isinstance(c, Node) and c.tag == "li"]
            if not versions or any(
                not v
                or cves(v)
                or re.search(
                    r"\b(not affected|not vulnerable|not impacted|unaffected|fixed|except|excluding|unless)\b",
                    v,
                    re.I,
                )
                for v in versions
            ):
                raise ValueError("Unreviewed version list")
            for cid in group:
                key = cid, product
                if key in seen:
                    raise ValueError("Repeated product/CVE list requires explicit review")
                seen.add(key)
                claim = assessment(
                    cid,
                    product,
                    "affected",
                    "Affected Software / " + product + " / " + ", ".join(group),
                    [dict(expression=v) for v in versions],
                    scope="bulletin_shared" if len(group) > 1 else "cve_specific",
                )
                claim["exposure"] = context
                out["assessments"].append(claim)
    if not seen:
        raise ValueError("No bound software/version statements")
    out["warnings"] = [
        "Only explicit Affected Software lists and their local CVE groups are normalized. An unclosed publisher div does not carry a prior product or CVE group across headings. Hardware/configuration context must be reviewed against the original source; no version arithmetic or inventory matching is performed. Description/bug references do not override software-list CVE bindings. Unlisted-product exclusions and resolution blocks are not independently normalized or verified."
    ]
    return out


REVIEWED_SOFTWARE = {
    "0105": {
        "Arista Edge Threat Management - Arista NG Firewall Versions": "Arista Edge Threat Management - Arista NG Firewall"
    },
    "0116": {"CVP Versions": "CloudVision Portal (on-premises)"},
    "0123": {
        "Arista Edge Threat Management - Arista Next Generation Firewall (NGFW) Versions": "Arista Edge Threat Management - Arista Next Generation Firewall (NGFW)"
    },
    "0124": {
        "Danz Monitoring Fabric": "DANZ Monitoring Fabric (DMF)",
        "Converged Cloud Fabric": "Arista Converged Cloud Fabric (CCF)",
        "CloudVision Appliance software": "CloudVision Appliance Software (CVA)",
        "Multi-Cloud Director": "Arista Multi Cloud Director (MCD)",
    },
    "0129": {
        "VMware SD-WAN Edge by VeloCloud (SD-WAN Edge)": "VMware SD-WAN Edge by VeloCloud (SD-WAN Edge)"
    },
    "0130": {
        "VMware SD-WAN by VeloCloud (VeloCloud)": "VMware SD-WAN by VeloCloud (publisher Orchestrator context)"
    },
    "0131": {"VeloCloud Orchestrator": "VeloCloud Orchestrator"},
    "0133": {
        "Arista Edge Threat Management - Arista Next Generation Firewall (NGFW) Versions": "Arista Edge Threat Management - Arista Next Generation Firewall (NGFW)"
    },
    "0135": {
        "cEOS Version": "Arista cEOS-lab",
        "Docker SWIX Extension Versions associated with the below EOS versions (Available in the Arista Download portal under Extensions section)": "Arista Docker SWIX extension",
        "Arista 7130 Systems running MOS": "Arista 7130 Systems running MOS",
    },
    "0136": {
        "CloudVision Portal": "CloudVision Portal",
        "VeloCloud Orchestrator (Formerly VeloCloud Orchestrator by Broadcom)": "VeloCloud Orchestrator",
        "VeloCloud Gateway (Formerly VeloCloud Gateway by Broadcom)": "VeloCloud Gateway",
        "VeloCloud Edge (Formerly VeloCloud Edge by Broadcom)": "VeloCloud Edge",
        "CloudVision AGNI - Virtual or physical appliance": "CloudVision AGNI physical appliance DCA-AGNI-100",
        "Netvisor Software": "Netvisor Software",
    },
    "0138": {
        "VeloCloud Orchestrator (Formerly VeloCloud Orchestrator by Broadcom)": "VeloCloud Orchestrator",
        "VeloCloud Gateway (Formerly VeloCloud Gateway by Broadcom)": "VeloCloud Gateway",
    },
    "0139": {
        "EOS Versions": "Media Control Service (MCS) on CloudVision eXchange (CVX)",
        "DMF Versions": "DANZ Monitoring Fabric (DMF)",
    },
    "0140": {"EOS Versions": "Arista EOS"},
}
SECTION_NAMES = {
    "Description",
    "Vulnerability Assessment",
    "Required Configuration for Exploitation, Indicators of Compromise and Mitigation Options",
    "Hotfix",
    "References",
    "Affected Software",
    "Affected Platforms",
    "Required Configuration for Exploitation",
    "Indicators of Compromise",
    "Mitigation",
    "Resolution",
    "Detection using CloudVision",
    "For More Information",
    "Open a Service Request",
}


def reviewed_sections(a):
    """Bound sibling sections, retaining exclusion labels and nested lists in order."""
    sections = {}
    current = None
    depth = 0
    for node in a.children:
        if not isinstance(node, Node):
            continue
        nested_context_heading = (
            current
            == "Required Configuration for Exploitation, Indicators of Compromise and Mitigation Options"
            and node.tag in {"h2", "h3", "h4"}
            and int(node.tag[1]) > depth
        )
        if (
            node.tag in {"h2", "h3", "h4"}
            and node.text() in SECTION_NAMES
            and not nested_context_heading
        ):
            current = node.text()
            depth = int(node.tag[1])
            if current in sections:
                raise ValueError("Repeated Arista section requires review")
            sections[current] = []
        elif current and node.text():
            sections[current].append(node)
    return sections


def section_context(sections):
    return [
        dict(
            category="publisher_" + name.lower().replace(" ", "_"),
            details="\n".join(n.text() for n in sections.get(name, [])),
            source_scope="advisory_context_requires_product_configuration_review",
            source_locator=name,
        )
        for name in (
            "Description",
            "Affected Platforms",
            "Required Configuration for Exploitation",
            "Required Configuration for Exploitation, Indicators of Compromise and Mitigation Options",
        )
        if sections.get(name)
    ]


def reviewed_software(raw, url, vendor):
    number = urlsplit(url).path.rsplit("-", 1)[-1]
    if vendor != "arista" or number not in REVIEWED_SOFTWARE:
        raise ValueError("Unreviewed Arista software layout")
    a, out = article(raw, url, number)
    headers = [
        n.text()
        for n in a.children
        if isinstance(n, Node) and n.tag == "p" and "tracking this issue:" in n.text()
    ]
    sections = reviewed_sections(a)
    ids = cves(" ".join(headers))
    if number in {"0105", "0123", "0133"}:
        descriptions = [
            n.text()
            for n in sections.get("Description", [])
            if n.tag == "p" and re.search(r"\bCVE\s*:", n.text())
        ]
        expected = {"0105": 9, "0123": 3, "0133": 6}[number]
        if len(descriptions) != expected or any(len(cves(t)) != 1 for t in descriptions):
            raise ValueError("NGFW per-CVE descriptions changed")
        ids = cves(" ".join(descriptions))
    if number == "0124":
        ids = cves(a.text().split("Description", 1)[0])
        if len(ids) != 5 or set(ids) != set(
            cves(" ".join(n.text() for n in sections.get("Description", [])))
        ):
            raise ValueError("Arista suite CVE scope changed")
    if not ids:
        raise ValueError("Explicit Arista tracking CVEs missing")
    context = section_context(sections)
    if not sections.get("Affected Platforms") or not sections.get("Description"):
        raise ValueError("Arista applicability context missing")
    if number in {"0116", "0124", "0135", "0136", "0139", "0140"} and not sections.get(
        "Required Configuration for Exploitation"
    ):
        raise ValueError("Arista exploitation prerequisites missing")
    if number == "0116":
        if not sections.get("Mitigation"):
            raise ValueError("CVP onboarding-token context missing")
        context.append(
            dict(
                category="publisher_mitigation_context",
                details="\n".join(n.text() for n in sections["Mitigation"]),
                source_scope="advisory_context_requires_product_configuration_review",
                source_locator="Mitigation",
            )
        )
    groups = {}
    product = None
    for node in sections.get("Affected Software", []):
        if number in {"0105", "0138"} and node.tag == "ul":
            for item in node.children:
                if not isinstance(item, Node) or item.tag != "li":
                    continue
                product = REVIEWED_SOFTWARE[number].get(leading_inline(item))
                lists = [n for n in item.children if isinstance(n, Node) and n.tag == "ul"]
                if not product or len(lists) != 1 or product in groups:
                    raise ValueError("Unreviewed Arista nested product list")
                groups[product] = version_expressions(lists[0])
        elif node.tag in {"h4", "div", "p"} and node.text() in REVIEWED_SOFTWARE[number]:
            product = REVIEWED_SOFTWARE[number].get(node.text())
            if not product:
                raise ValueError("Unreviewed Arista product heading")
        elif node.tag == "ul":
            if not product or product in groups:
                raise ValueError("Unbound or repeated Arista version list")
            if number == "0136" and product == "CloudVision AGNI physical appliance DCA-AGNI-100":
                if not node.text().startswith("AGNI Physical Appliance DCA-AGNI-100 "):
                    raise ValueError("AGNI physical appliance qualifier changed")
                groups[product] = [dict(expression=node.text())]
            else:
                groups[product] = version_expressions(node)
        elif (
            number in {"0129", "0130", "0131"}
            and node.tag == "div"
            and node.text() == "Versions"
            and product
        ):
            continue
        elif not node.text():
            continue
        elif node.tag == "div" and number == "0139":
            # Keep the local MCS-only restriction as well as advisory-wide context.
            if node.text():
                context.append(
                    dict(
                        category="publisher_software_restriction",
                        details=node.text(),
                        source_scope="Affected Software",
                        source_locator="Affected Software / " + str(product),
                    )
                )
        else:
            raise ValueError("Unreviewed content in Arista affected software section")
    if set(groups) != set(REVIEWED_SOFTWARE[number].values()):
        raise ValueError("Reviewed Arista software groups missing")
    out.update(
        cves=ids,
        document_status="published",
        source_format="Arista reviewed sibling software sections HTML",
    )
    for product, versions in groups.items():
        for cid in ids:
            claim = assessment(
                cid,
                product,
                "affected",
                "Affected Software / " + product,
                versions,
                scope="bulletin_shared" if len(ids) > 1 else "cve_specific",
            )
            claim["exposure"] = context
            out["assessments"].append(claim)
    notices = [
        n.text()
        for n in a.children
        if isinstance(n, Node) and n.tag == "p" and n.text().startswith("NOTICE:")
    ]
    if notices:
        out["notes"].append(dict(category="publisher_republication", text="\n".join(notices)))
        out["warnings"].append(
            "Publisher identifies this as a repost of an older VMware advisory; the revision-table initial date is not established as first Arista disclosure."
        )
    for name in ("Mitigation", "Resolution"):
        if sections.get(name):
            out["notes"].append(
                dict(
                    category="publisher_" + name.lower(),
                    text="\n".join(n.text() for n in sections[name]),
                    source_locator=name,
                )
            )
    foreign_resolution_ids = set(
        cves(" ".join(n.text() for n in sections.get("Resolution", [])))
    ) - set(ids)
    if foreign_resolution_ids:
        out["warnings"].append(
            "Resolution section names CVEs outside the tracking scope: "
            + ", ".join(sorted(foreign_resolution_ids))
            + ". No CVE-specific fix is inferred from this inconsistent section."
        )
    out["warnings"] += [
        "Only explicit affected software lists are normalized. Publisher platform exclusions, triage and configuration prerequisites remain ordered advisory context; they do not establish blanket product exposure. Resolution and mitigation remain advisory notes, including planned releases; no available fixed firmware or automatic inventory match is inferred."
    ]
    return out


def version_expressions(node):
    values = [n.text() for n in node.children if isinstance(n, Node) and n.tag == "li"]
    if not values or any(
        not v
        or cves(v)
        or re.search(
            r"\b(not affected|not vulnerable|not impacted|unaffected|fixed|except|excluding|unless)\b",
            v,
            re.I,
        )
        for v in values
    ):
        raise ValueError("Unreviewed Arista affected range")
    if any(
        any(isinstance(c, Node) and c.tag in {"ul", "ol"} for c in n.children)
        for n in node.children
        if isinstance(n, Node)
    ):
        raise ValueError("Nested version conditions require review")
    return [dict(expression=v) for v in values]


def airsnitch_notice(raw, url, vendor):
    a, out = article(raw, url, "0141")
    sections = reviewed_sections(a)
    if (
        vendor != "arista"
        or cves(a.text())
        or "AirSnitch" not in a.text()
        or "BUG 1787021" not in a.text()
        or [n.text() for n in sections.get("Affected Software", [])]
        != [
            "None",
            "Note: this is an architectural configuration dependency rather than an issue with the product itself.",
        ]
    ):
        raise ValueError("Reviewed Arista AirSnitch notice changed")
    out.update(document_status="published", source_format="Arista security notice without CVE")
    for name in (
        "Description",
        "Affected Software",
        "Affected Platforms",
        "Required Configuration for Exploitation",
        "Mitigation",
    ):
        if not sections.get(name):
            raise ValueError("AirSnitch applicability context missing")
        out["notes"].append(
            dict(
                category="publisher_context",
                text="\n".join(n.text() for n in sections[name]),
                source_locator=name,
            )
        )
    out["warnings"] = [
        "Publisher describes a configuration-dependent AirSnitch risk with no CVE identifier. At the dated source review, the linked CSAF was a draft envelope without vulnerability entries. Retained as a security notice with context; no CVE mapping, blanket unaffectedness, software fix or concealment is inferred."
    ]
    return out
