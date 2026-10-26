"""Reviewed fortinet source normalization."""

import re
from datetime import date
from urllib.parse import urlsplit

from .common import HTML, Node, assessment, base, cves, iso_date


def document_history(raw, url, vendor):
    """Publisher-reported documentation changes, never firmware availability."""
    match = re.fullmatch(
        r"/document/(fortigate|fortiproxy)/(\d+\.\d+\.\d+)/[^/]+/4/change-log", urlsplit(url).path
    )
    if not match:
        return None
    if vendor != "fortinet" or urlsplit(url).hostname != "docs.fortinet.com":
        raise ValueError("Expected official Fortinet documentation source")
    product = {"fortigate": "FortiOS", "fortiproxy": "FortiProxy"}[match[1]]
    tree = HTML(raw).root
    if f"{product} {match[2]}" not in tree.text():
        raise ValueError("Publisher change-log product/version changed")
    tables = [
        t
        for t in tree.find({"table"})
        if [h.text() for h in t.find({"th"})] == ["Date", "Change Description"]
    ]
    if len(tables) != 1:
        raise ValueError("Expected one dated documentation change log")
    events = []
    for index, row in enumerate(tables[0].find({"tr"})):
        cells = [c.text() for c in row.find({"td"})]
        if not cells:
            continue
        if len(cells) != 2 or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", cells[0]):
            raise ValueError("Unreviewed publisher change-log row")
        date.fromisoformat(cells[0])
        ids = cves(cells[1])
        if cells[1] in ("Initial release.", "Initial document release."):
            kind = "initial_document_release"
        elif ids and re.search(r"\bAdded CVE-", cells[1]):
            kind = "cve_references_added"
        else:
            continue
        events.append(
            dict(
                publisher_date=cells[0],
                kind=kind,
                cve_ids=ids,
                source_locator=f"Change log / row {index}",
            )
        )
    if sum(e["kind"] == "initial_document_release" for e in events) != 1:
        raise ValueError("Unique initial document release entry required")
    return dict(product=product, version=match[2], events=events)


def investigation_advisory(raw, url, vendor):
    """Reviewed shared-CVE investigation lists, separate from empty CSAF exports."""
    path = urlsplit(url).path
    if (
        vendor != "fortinet"
        or urlsplit(url).hostname not in ("www.fortiguard.com", "fortiguard.fortinet.com")
        or not re.fullmatch(r"/psirt/FG-IR-\d{2}-\d+", path)
    ):
        raise ValueError("Expected canonical Fortinet PSIRT advisory")
    tree = HTML(raw).root
    meta = {}
    for row in tree.find({"tr"}):
        cells = [n.text() for n in row.children if isinstance(n, Node) and n.tag == "td"]
        if len(cells) == 2:
            meta[cells[0]] = cells[1]
    if meta.get("IR Number") != path.rsplit("/", 1)[-1]:
        raise ValueError("Fortinet advisory identity missing or contradictory")
    titles = list(tree.find({"h1"}))
    if len(titles) != 1 or not meta.get("Published Date"):
        raise ValueError("Expected advisory heading and publisher date")
    details = [n for n in tree.find({"div"}) if "detail-item" in n.attrs.get("class", "").split()]
    summaries = [d for d in details if any(h.text() == "Summary" for h in d.find({"h2"}))]
    if len(summaries) != 1:
        raise ValueError("Expected one explicit CVE summary")
    ids = []
    for paragraph in summaries[0].find({"p"}):
        text = paragraph.text()
        found = cves(text)
        if len(found) != 1 or not text.startswith(found[0] + " - "):
            raise ValueError("Unreviewed CVE summary scope")
        ids += found
    if not ids or not set(cves(meta.get("CVE ID", ""))) <= set(ids):
        raise ValueError("Missing or contradictory CVE identity")
    lists = [
        d
        for d in details
        if any(
            h.text()
            == "Fortinet is currently investigating the impact of these CVEs over Fortinet Products."
            for h in d.find({"h6"})
        )
    ]
    if len(lists) != 1:
        raise ValueError("Shared CVE investigation scope missing")
    if any(isinstance(n, Node) and n.tag not in ("h6", "h4", "p") for n in lists[0].children):
        raise ValueError("Unreviewed investigation-list section layout")

    def lines(node):
        if isinstance(node, str):
            return node
        if node.tag == "br":
            return "\n"
        return "".join(lines(c) for c in node.children)

    products = {}
    status = None
    headings = {
        "Products under investigation:": "investigating",
        "Products confirmed NOT impacted:": "unaffected",
    }
    seen_headings = set()
    for node in lists[0].find({"h4", "p"}):
        if node.tag == "h4":
            if node.text() not in headings or node.text() in seen_headings:
                raise ValueError("Unreviewed or duplicate product status heading")
            seen_headings.add(node.text())
            status = headings[node.text()]
            continue
        if not status:
            raise ValueError("Unscoped product list")
        for product in lines(node).splitlines():
            product = product.strip()
            if not product:
                continue
            if (
                not re.fullmatch(r"Forti[A-Za-z0-9][A-Za-z0-9 .()/+-]*", product)
                or product in products
            ):
                raise ValueError("Unreviewed or conflicting product list entry")
            products[product] = status
    if set(headings) != seen_headings or not products:
        raise ValueError("Incomplete investigation product lists")
    out = base(
        vendor,
        url,
        meta["IR Number"],
        titles[0].text(),
        iso_date(meta["Published Date"]),
        iso_date(meta.get("Updated Date")),
    )
    out.update(
        source_format="Fortinet PSIRT investigation HTML",
        document_status="published",
        cves=sorted(set(ids)),
    )
    out["assessments"] = [
        assessment(
            cid,
            product,
            status,
            "detail-item / shared CVE investigation / " + product,
            scope="bulletin_shared" if len(out["cves"]) > 1 else "cve_specific",
        )
        for cid in out["cves"]
        for product, status in products.items()
    ]
    out["warnings"] = [
        "Reviewed HTML investigation lists apply to the explicitly scoped summary CVEs. Shared bulletin statements are not independent per-CVE assessments. An empty structured export is not evidence of no impact. No version bounds, fix availability or prior affectedness are inferred."
    ]
    return out


def fortinac_release(raw, url, vendor):
    tree = HTML(raw).root
    text = tree.text()
    if "Applies to the FortiNAC-F product only" not in text:
        raise ValueError("Expected FortiNAC-F release scope missing")
    out = base(vendor, url, "FortiNAC-F-7.4.1-release-CVEs", "FortiNAC-F 7.4.1 resolved CVEs")
    out.update(source_format="Vendor release notes HTML", document_status="published")
    for row in tree.find({"tr"}):
        t = row.text()
        if "FortiNAC F 7.4.1 is no longer vulnerable" not in t:
            continue
        for cid in cves(t):
            out["cves"].append(cid)
            out["assessments"].append(
                assessment(
                    cid,
                    "FortiNAC-F (FortiNAC-OS) 7.4.1",
                    "fixed",
                    "CVE references table / " + t.split()[0],
                    [{"version": "7.4.1", "status": "fixed"}],
                    [
                        {
                            "category": "vendor_fix",
                            "details": "7.4.1",
                            "availability": "vendor_reports_fixed",
                        }
                    ],
                )
            )
    out["cves"] = sorted(set(out["cves"]))
    out["warnings"] = [
        "Applies only to FortiNAC-F on FortiNAC-OS, excludes CentOS appliances. No publication or release date established by this page."
    ]
    return out


def fortinet_release(raw, url, vendor):
    if "/fortinac-f/" in url:
        return fortinac_release(raw, url, vendor)
    path = urlsplit(url).path
    m = re.match(r"/document/(fortigate|fortiproxy)/(\d+\.\d+\.\d+)/", path)
    if not m:
        raise ValueError("Unsupported Fortinet release-note product/version scope")
    product = {"fortigate": "FortiOS", "fortiproxy": "FortiProxy"}[m[1]]
    version = m[2]
    tree = HTML(raw).root
    nodes = list(tree.find({"h1", "h2", "h3", "h4", "p", "tr"}))
    out = base(
        vendor, url, f"{product}-{version}-release-CVEs", f"{product} {version} resolved CVEs"
    )
    out.update(source_format="Vendor release notes HTML", document_status="published")
    active = False
    explicit = False
    expected = f"{product} {version} is no longer vulnerable"
    for n in nodes:
        text = n.text()
        if n.tag in ("h1", "h2", "h3", "h4"):
            active = text.lower() == "common vulnerabilities and exposures"
            explicit = False
            continue
        if not active:
            continue
        if n.tag == "p" and expected in text:
            explicit = True
        if n.tag != "tr":
            continue
        if expected not in text and not explicit:
            continue
        for cid in cves(text):
            out["cves"].append(cid)
            out["assessments"].append(
                assessment(
                    cid,
                    product + " " + version,
                    "fixed",
                    "Common Vulnerabilities and Exposures / bug " + text.split()[0],
                    [{"version": version, "status": "fixed"}],
                    [
                        {
                            "category": "vendor_fix",
                            "details": version,
                            "availability": "vendor_reports_fixed",
                        }
                    ],
                )
            )
    out["cves"] = sorted(set(out["cves"]))
    out["assessments"] = list(
        {(a["cve_id"], a["product_id"]): a for a in out["assessments"]}.values()
    )
    out["warnings"] = [
        "Exact release-note product/version only. A fixed release does not establish which earlier releases were affected. Publication date and public availability have not been verified."
    ]
    if not out["assessments"]:
        raise ValueError("No explicit product/version CVE fix statements in expected section")
    return out
