"""Two reviewed single-CVE PSIRT range lists; solutions are not fix certification."""

import json
import re
from hashlib import sha256
from urllib.parse import urlsplit

from .common import HTML, Node, assessment, base, cves, iso_date

ROUTES = {
    "FG-IR-23-165": {
        "cve": "CVE-2023-37930",
        "products": {"FortiOS", "FortiProxy"},
        "component": "SSL-VPN",
        "context": "The publisher describes an authenticated VPN user and SSL-VPN web mode. This is not an unauthenticated, configuration-independent exposure statement.",
        "discrepancy": "For the FortiOS 6.4 train, Affected Products includes 6.4.14 while Solutions separately names both 6.4.14 and 6.4.15. This unresolved publisher discrepancy is retained; neither candidate is certified as a safe upgrade boundary by this parser.",
        "sections": {
            "Title": "3a070907d30082ba4d3ad7f56a370f84410f31e58ae09b9ed056515db2de3e68",
            "Summary": "deea863895a01518f97d682d73a8f2df4ee16ac1d68b7ce1255bb12c69365171",
            "Affected Products": "b4601e9cce2edcd2f5978ce7b83f5d077ceb3c133f96f63afeea67ba122e6458",
            "Solutions": "2d889e99ef3cfc8070dd8f302739dc86ec8e7b07da32d174c2aa079d919333d0",
        },
    },
    "FG-IR-23-261": {
        "cve": "CVE-2023-40721",
        "products": {"FortiOS", "FortiProxy", "FortiPAM", "FortiSwitchManager"},
        "component": "CLI",
        "context": "The publisher describes authenticated, privileged CLI access. Remote unauthenticated exposure is not established by this advisory.",
        "discrepancy": None,
        "sections": {
            "Title": "5013e0f6bbd0bfc9d23e96740ca0ea6fdfda6796297fbfb077c0151d918c3ff5",
            "Summary": "ab1789bd06dbfe38d2f7b36c2457c49f94666af85660a24bda8926fc5df58116",
            "Affected Products": "178bb7d72d0d94d7eef87861ff4668c76e349f5f5eed68904b926f832a5898c8",
            "Solutions": "1f6c89a070cc935a56dd6a7937f96f1741b78ef08df86d0653c57648c5fddddc",
        },
    },
}


def section_sha256(node):
    def value(item):
        if isinstance(item, str):
            return " ".join(item.split())
        return [
            item.tag,
            sorted(item.attrs.items()),
            [value(c) for c in item.children if not isinstance(c, str) or c.strip()],
        ]

    return sha256(
        json.dumps(value(node), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def sections(tree):
    found = {}
    titles = list(tree.find({"h1"}))
    if len(titles) != 1:
        raise ValueError("Expected one PSIRT article title")
    found["Title"] = titles[0]
    for node in tree.find({"div"}):
        if "detail-item" not in node.attrs.get("class", "").split():
            continue
        headings = list(node.find({"h2"}))
        if not headings or headings[0].text() not in {"Summary", "Affected Products", "Solutions"}:
            continue
        name = headings[0].text()
        if name in found:
            raise ValueError("Duplicate reviewed PSIRT article section")
        found[name] = node
    if set(found) != {"Title", "Summary", "Affected Products", "Solutions"}:
        raise ValueError("Required PSIRT range section missing")
    return found


def lines(node):
    if isinstance(node, str):
        return node
    if node.tag in {"h2", "h3", "h4"}:
        return ""
    if node.tag == "br":
        return "\n"
    return "".join(lines(c) for c in node.children) + ("\n" if node.tag in {"p", "li"} else "")


def range_advisory(raw, url, vendor):
    parsed = urlsplit(url)
    identity = parsed.path.rsplit("/", 1)[-1]
    if (
        vendor != "fortinet"
        or parsed.hostname not in {"www.fortiguard.com", "fortiguard.fortinet.com"}
        or parsed.path != "/psirt/" + identity
        or identity not in ROUTES
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Unreviewed Fortinet single-CVE range route")
    spec = ROUTES[identity]
    tree = HTML(raw).root
    scoped = sections(tree)
    if set(spec["sections"]) != set(scoped) or any(
        section_sha256(node) != spec["sections"][name] for name, node in scoped.items()
    ):
        raise ValueError("Fortinet range article scope changed; review required")
    meta = {}
    keys = {"IR Number", "CVE ID", "Published Date", "Updated Date", "Attack Type", "Component"}
    for row in tree.find({"tr"}):
        cells = [n.text() for n in row.children if isinstance(n, Node) and n.tag == "td"]
        if len(cells) == 2 and cells[0] in keys:
            if cells[0] in meta:
                raise ValueError("Duplicate PSIRT identity metadata")
            meta[cells[0]] = cells[1]
    if (
        meta.get("IR Number") != identity
        or cves(meta.get("CVE ID", "")) != [spec["cve"]]
        or meta.get("Component") != spec["component"]
        or meta.get("Attack Type") != "Authenticated"
        or not meta.get("Published Date")
        or not set(cves(scoped["Summary"].text())) <= {spec["cve"]}
    ):
        raise ValueError("Contradictory PSIRT identity or prerequisite scope")
    groups, seen = {}, set()
    for text in lines(scoped["Affected Products"]).splitlines():
        text = text.strip()
        if not text:
            continue
        match = re.fullmatch(
            r"(Forti[A-Za-z0-9-]+) (version \d+(?:\.\d+)*(?: through \d+(?:\.\d+)*)?|\d+\.\d+ all versions(?: are not affected)?)",
            text,
        )
        if not match or text in seen:
            raise ValueError("Unreviewed or repeated PSIRT product range")
        seen.add(text)
        status = "unaffected" if text.endswith(" are not affected") else "affected"
        groups.setdefault((match[1], status), []).append(dict(expression=text))
    if {product for product, _ in groups} != spec["products"]:
        raise ValueError("PSIRT product population changed")
    out = base(
        vendor,
        url,
        identity,
        scoped["Title"].text(),
        iso_date(meta["Published Date"]),
        iso_date(meta.get("Updated Date")),
    )
    out.update(
        cves=[spec["cve"]],
        document_status="published",
        source_format="Fortinet reviewed single-CVE range-list HTML",
    )
    for (product, status), versions in groups.items():
        claim = assessment(
            spec["cve"],
            product,
            status,
            "Affected Products / " + product + " / " + status,
            versions,
        )
        claim["product_id"] += ":" + status
        claim["exposure"] = [
            dict(
                category="publisher_prerequisite",
                details=spec["context"],
                source_locator="Summary / Attack Type / Component",
                source_scope="single_cve_advisory_context",
            )
        ]
        if product == "FortiOS" and status == "affected" and spec["discrepancy"]:
            claim["exposure"].append(
                dict(
                    category="publisher_solution_discrepancy",
                    details=spec["discrepancy"],
                    source_locator="Affected Products / Solutions",
                    source_scope="FortiOS 6.4 train only",
                )
            )
        out["assessments"].append(claim)
    out["warnings"] = [
        "Only explicit affected and unaffected version expressions are normalized. Reviewed title, summary, affected-products and solutions structure is fingerprint-bound. Authentication and service context remain attached. Solution suggestions, workarounds, virtual patches and other product mentions are not promoted to verified fixes or inferred prior affectedness."
    ]
    if spec["discrepancy"]:
        out["warnings"].append(spec["discrepancy"])
    return out
