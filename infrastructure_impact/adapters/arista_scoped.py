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
