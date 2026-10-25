"""Reviewed arista source normalization."""

import re
from urllib.parse import urlsplit

from .common import HTML, assessment, base, cves, iso_date


def arista_software(raw, url, vendor):
    tree = HTML(raw).root
    nodes = list(tree.find({"h1", "h2", "h3", "h4", "p", "li", "div"}))
    title = next(
        (n.text() for n in nodes if "Security Advisory " in n.text() and n.tag in ("h1", "h2")),
        None,
    )
    if not title:
        raise ValueError("Arista advisory title missing")
    out = base(vendor, url, urlsplit(url).path.rsplit("/", 1)[-1], title)
    out.update(source_format="Arista affected software HTML", document_status="published")
    header = tree.text().split("Vulnerability Assessment", 1)[0]
    ids = cves(header)
    tracked = next(
        (n.text() for n in nodes if n.tag == "p" and "The CVE-ID tracking this issue:" in n.text()),
        None,
    )
    if tracked:
        ids = cves(tracked)
    shared_ids = list(ids)
    active = False
    product = None
    groups = {}
    shared_groups = set()
    for n in nodes:
        t = n.text()
        if n.tag in ("h2", "h3"):
            active = t == "Affected Software"
            product = None
        if not active:
            continue
        if n.tag == "p" and "product releases are affected for" in t:
            ids = cves(t)
            product = None
        elif (
            n.tag == "p"
            and t == "No Arista software products are presently impacted by these vulnerabilities."
        ):
            for cid in shared_ids:
                key = (
                    cid,
                    "Arista software products (publisher-wide current statement)",
                    "unaffected",
                )
                groups.setdefault(key, []).append({"expression": t})
                if len(shared_ids) > 1:
                    shared_groups.add(key)
        elif (
            n.tag == "p"
            and t
            == "CloudVision CUE cloud service delivery and Arista Edge Threat Management were impacted but have already been upgraded to unaffected PHP versions with correct patches."
        ):
            for cid in shared_ids:
                for service in (
                    "CloudVision CUE cloud service delivery",
                    "Arista Edge Threat Management",
                ):
                    key = (cid, service, "fixed")
                    groups.setdefault(key, []).append({"expression": t})
                    if len(shared_ids) > 1:
                        shared_groups.add(key)
        elif n.tag == "h4" and t.endswith("versions:"):
            product = t.removesuffix("versions:").strip() + " (source platform scope applies)"
        elif (
            n.tag == "div"
            and len(t) < 120
            and re.fullmatch(r"[A-Za-z][A-Za-z0-9 ()/-]* Versions:?", t)
        ):
            product = re.sub(r" Versions:?$", "", t) + " (source platform scope applies)"
        elif n.tag == "li" and product and ids:
            state = "unaffected" if re.search(r"not (?:impacted|affected)", t, re.I) else "affected"
            for cid in ids:
                key = (cid, product, state)
                groups.setdefault(key, []).append({"expression": t})
                if len(ids) > 1:
                    shared_groups.add(key)
    for (cid, product, status), versions in groups.items():
        a = assessment(
            cid,
            product,
            status,
            "Affected Software / " + product,
            versions,
            scope="bulletin_shared" if (cid, product, status) in shared_groups else "cve_specific",
        )
        a["product_id"] = product + ":" + status
        out["assessments"].append(a)
        out["cves"].append(cid)
    out["cves"] = sorted(set(out["cves"]))
    for row in tree.find({"tr"}):
        cells = [c.text() for c in row.find({"td"})]
        if len(cells) == 3 and cells[0] == "1.0":
            out["published_at"] = iso_date(cells[1])
    out["warnings"] = [
        "Software/service statements only; consult source Affected Platforms before applying to hardware. A current unaffected statement does not erase historical exposure. Cloud-service fix statements do not establish a downloadable fixed firmware version."
    ]
    if not out["published_at"]:
        out["warnings"].append("Publication date not extracted.")
    if not out["assessments"]:
        raise ValueError("No scoped Arista software statements")
    return out
