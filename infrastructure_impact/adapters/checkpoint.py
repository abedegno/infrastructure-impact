"""Reviewed checkpoint source normalization."""

import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .common import HTML, assessment, base, cves


def checkpoint_records(raw, url):
    """Official product advisory index, deliberately distinct from IPS signatures."""
    if urlsplit(url).hostname != "iapi-services-ucs.checkpoint.com":
        raise ValueError("Expected Check Point public product advisory endpoint")
    records = json.loads(raw)
    if not isinstance(records, list):
        raise ValueError("Expected advisory list")

    def stamp(ms):
        return (
            datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat()
            if isinstance(ms, (int, float))
            else None
        )

    result = []
    for row in records:
        ids = cves(row.get("cveId", ""))
        if not ids or not row.get("enable", True):
            continue
        out = base(
            "checkpoint",
            url,
            row.get("skId") or str(row["id"]),
            row.get("summary", ""),
            stamp(row.get("published")),
            stamp(row.get("updated")),
        )
        out.update(
            cves=ids,
            source_format="Check Point public advisory JSON",
            document_status="published",
            advisory_url=row.get("url"),
        )
        for i, p in enumerate(row.get("products", [])):
            expression = str(p.get("affected", "")).strip()
            status = (
                "unaffected"
                if expression.lower() == "none"
                else "unknown"
                if not expression or expression.lower() in ("details in sk", "no jumbo")
                else "affected"
            )
            product = f"{p['name']} {p.get('version', '')}".strip()
            for cid in ids:
                out["assessments"].append(
                    assessment(
                        cid,
                        product,
                        status,
                        f"record[id={row['id']}].products[{i}]",
                        [{"version": p.get("version", ""), "expression": expression}],
                        scope="bulletin_shared" if len(ids) > 1 else "cve_specific",
                    )
                )
        out["warnings"].append(
            "Affected release expressions are retained verbatim; numeric take thresholds do not establish fix availability. Active index does not enumerate all historical advisories."
        )
        result.append(out)
    return result


def checkpoint_article(raw, url, vendor):
    """Only reviewed public SK layouts; never treat the IPS catalogue as exposure."""
    if urlsplit(url).hostname != "support.checkpoint.com":
        raise ValueError("Expected Check Point support article")
    s = raw.decode() if isinstance(raw, bytes) else raw
    match = re.search(r"<script\b[^>]*\bid=[\"\']__NEXT_DATA__[\"\'][^>]*>(.*?)</script>", s, re.S)
    if not match:
        raise ValueError("Public server-rendered article data missing")
    data = json.loads(match[1])["props"]["pageProps"]["data"]
    if data.get("solutionBlockReason") or not data.get("solution"):
        raise ValueError("Article solution unavailable; no product claims extracted")
    identity = data["id"]
    out = base(vendor, url, identity, data["title"], updated=data.get("lastModified"))
    out.update(source_format="Public SK article embedded JSON", document_status="published")
    tree = HTML(data["solution"]).root
    text = tree.text()
    if identity == "sk182459":
        cid = "CVE-2024-6387"
        out["cves"] = [cid]
        fix = re.search(r"R81\.10\.10 Build (\d+)", text)
        if not fix:
            raise ValueError("Expected Quantum Spark firmware table missing")
        for n in tree.find({"p"}):
            t = n.text()
            if cid not in t or "vulnerable" not in t:
                continue
            if t.startswith(
                "Quantum Spark appliances that run the R81.10.x versions are vulnerable"
            ):
                product = "Quantum Spark R81.10.x"
                status = "affected"
            elif t.startswith(
                "Quantum Spark appliances that run the versions R80.20.x or lower are not vulnerable"
            ):
                product = "Quantum Spark R80.20.x and earlier"
                status = "unaffected"
            elif t.startswith(
                "Gaia OS versions (on all Check Point appliances and servers other than Quantum Spark) are not vulnerable"
            ):
                product = "Gaia OS (excludes Quantum Spark)"
                status = "unaffected"
            else:
                continue
            rem = (
                [
                    {
                        "category": "vendor_fix",
                        "details": fix[0],
                        "availability": "vendor_reports_fixed",
                        "source_scope": "Quantum Spark download table; consult hardware columns",
                    }
                ]
                if status == "affected"
                else []
            )
            a = assessment(
                cid,
                product,
                status,
                "props.pageProps.data.solution / Important Notes",
                [{"expression": t}],
                rem,
            )
            out["assessments"].append(a)
        if len(out["assessments"]) != 3:
            raise ValueError("Reviewed Quantum Spark applicability paragraphs changed")
        first = re.search(r"(\d{1,2} [A-Za-z]+ \d{4}) First release of this article", text)
        if first:
            out["published_at"] = datetime.strptime(first[1], "%d %B %Y").date().isoformat()
    elif identity == "sk181833":
        if "This problem was fixed. The fix is included starting from: Check Point R82" not in text:
            raise ValueError("Reviewed Check Point R82 fix statement changed")
        cid = "CVE-2023-48795"
        out["cves"] = [cid]
        out["assessments"] = [
            assessment(
                cid,
                "Check Point Scalable Platforms (article scope)",
                "fixed",
                "props.pageProps.data.solution / opening fix statement",
                [{"version": "R82", "status": "fixed"}],
                [
                    {
                        "category": "vendor_fix",
                        "details": "Check Point R82",
                        "availability": "vendor_reports_fixed",
                    }
                ],
            )
        ]
        out["warnings"].append(
            "Earlier-version exploitability depends on enabled SSH ciphers; this extraction makes no blanket affected/unaffected claim for R81.20 and earlier. Product label follows article metadata."
        )
    else:
        raise ValueError("Unreviewed Check Point SK layout")
    out["warnings"].append(
        "Public article solution only; internal CMS fields are excluded. dateCreated is not assumed to be first public disclosure. Background CVEs do not expand the advisory scope."
    )
    return out


def checkpoint_release_listing(raw, url, vendor):
    """Public metadata only; never retrieve entitlement-controlled firmware."""
    if urlsplit(url).hostname != "support.checkpoint.com" or not re.fullmatch(
        r"/results/download/\d+", urlsplit(url).path
    ):
        raise ValueError("Expected official public download metadata page")
    text = raw.decode() if isinstance(raw, bytes) else raw
    match = re.search(r'<script\b[^>]*\bid=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', text, re.S)
    if not match:
        raise ValueError("Public download metadata unavailable")
    data = json.loads(match[1])["props"]["pageProps"]["data"]
    identity = re.fullmatch(r"(.+?) [Bb]uild (\d+) for .+", data["title"])
    if not identity:
        raise ValueError("Unsupported firmware title/version scope")
    return {
        "schema_version": 1,
        "vendor": vendor,
        "source_url": url,
        "title": data["title"],
        "product": data["product"],
        "version": identity[1] + " Build " + identity[2],
        "platforms": [m.strip() for m in data["models"].split(",")],
        "reported_published_at": data["datePublished"],
        "artifact_filename": data["fileName"],
        "artifact_sha256": data["sha256"].lower(),
        "availability_basis": "publisher_dated_listing",
        "evidence_locator": "props.pageProps.data / public title, models, datePublished, fileName, sha256",
        "limitations": "Public listing metadata only. File access may require entitlement. Historical availability and CVE/product linkage are not independently verified.",
    }
