"""Exact reviewed NAT notice and MOVEit non-impact HTML boundaries."""

import json
import re
from datetime import date
from urllib.parse import urlsplit, urlunsplit

from .common import HTML, Node, assessment, base, cves

BASE = "https://security.paloaltonetworks.com/"
NAT = "PAN-SA-2021-0002"
MOVE = "PAN-SA-2023-0003"
HTML_URLS = {BASE + NAT, BASE + MOVE}
IDENTITIES = {NAT, MOVE, "PAN-SA-2025-0005"}
NOTICE_FORMAT = "Reviewed NAT informational notice HTML"
TITLES = {
    NAT: f"{NAT} Informational: PAN-OS: NAT slipstreaming v1.0 and v2.0 attacks",
    MOVE: f"{MOVE} Informational Bulletin: Impact of MOVEit Vulnerabilities "
    "(CVE-2023-34362, CVE-2023-35036, CVE-2023-35708)",
}
MOVE_CVES = {"CVE-2023-34362", "CVE-2023-35036", "CVE-2023-35708"}
MOVE_PRODUCTS = {
    "AutoFocus",
    "Bridgecrew",
    "Cloud NGFW",
    "Cortex Data Lake",
    "Cortex XDR",
    "Cortex XDR Agent",
    "Cortex Xpanse",
    "Cortex XSOAR",
    "Enterprise Data Loss Prevention",
    "Exact Data Matching CLI",
    "Expanse",
    "Expedition Migration Tool",
    "GlobalProtect App",
    "IoT Security",
    "Okyo Garde",
    "Palo Alto Networks App for Splunk",
    "PAN-OS",
    "Prisma Access",
    "Prisma Cloud",
    "Prisma Cloud Compute",
    "Prisma SD-WAN (CloudGenix)",
    "Prisma SD-WAN ION",
    "SaaS Security",
    "User-ID Agent",
    "WildFire Appliance (WF-500)",
    "WildFire Cloud",
}
RATIONALE = (
    "Palo Alto Networks does not use MOVEit Transfer and is not impacted by these vulnerabilities."
)


def representation_guard(raw, url):
    """Known HTML-only policies cannot be bypassed with a structured entry point."""
    routes = {BASE + prefix + i for i in IDENTITIES for prefix in ("", "json/", "csaf/")}
    structured = raw.lstrip().startswith("{" if isinstance(raw, str) else b"{")
    parts = urlsplit(url)
    route = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    if route in routes and (structured or url not in {BASE + i for i in IDENTITIES}):
        raise ValueError("Reviewed PAN bulletin requires its canonical HTML representation")
    if structured:
        document = json.loads(raw)
        tracking = document.get("document", {}).get("tracking", {})
        if tracking.get("id") in IDENTITIES:
            raise ValueError("Reviewed PAN bulletin identity requires canonical HTML")


def _sections(article, expected):
    sections, current = {}, None
    for node in article.children:
        if not isinstance(node, Node):
            continue
        if node.tag == "h3":
            current = node.text()
            if current in sections:
                raise ValueError("Duplicate reviewed bulletin section")
            sections[current] = []
        elif current is not None:
            sections[current].append(node)
    if list(sections) != expected:
        raise ValueError("Reviewed bulletin sections changed")
    return sections


def parse_bulletin(raw, url, vendor):
    if url not in HTML_URLS:
        raise ValueError("Unknown reviewed bulletin route")
    identity = url.rsplit("/", 1)[-1]
    articles = [n for n in HTML(raw).root.find({"div"}) if n.attrs.get("id") == "content"]
    if len(articles) != 1:
        raise ValueError("Reviewed bulletin article boundary changed")
    article = articles[0]
    titles = list(article.find({"h2"}))
    summaries = [
        n for n in article.find({"div"}) if "sa_summary" in n.attrs.get("class", "").split()
    ]
    if len(titles) != 1 or titles[0].text() != TITLES[identity] or len(summaries) != 1:
        raise ValueError("Reviewed bulletin identity or summary changed")
    summary = summaries[0].text()
    if not summary.startswith("Informational "):
        raise ValueError("Reviewed bulletin classification changed")
    dates = {}
    for label, key in [("Published", "published_at"), ("Updated", "updated_at")]:
        values = re.findall(r"\b" + label + r"\s+(\d{4}-\d{2}-\d{2})\b", summary)
        if len(values) != 1:
            raise ValueError("Reviewed bulletin date missing or ambiguous")
        dates[key] = date.fromisoformat(values[0]).isoformat()
    if dates["updated_at"] < dates["published_at"]:
        raise ValueError("Reviewed bulletin dates conflict")
    context = "Exploitation Status" if identity == MOVE else "Required Configuration for Exposure"
    sections = _sections(
        article,
        [
            "Description",
            "Product Status",
            context,
            "Solution",
            "Workarounds and Mitigations",
            "Timeline",
        ],
    )
    texts = {name: " ".join(n.text() for n in nodes) for name, nodes in sections.items()}
    tables = [
        n
        for parent in sections["Product Status"]
        for n in ([parent] if parent.tag == "table" else parent.find({"table"}))
    ]
    if len(tables) != 1 or list(tables[0].find({"table"})):
        raise ValueError("Reviewed product table missing or ambiguous")
    rows = [[n.text() for n in row.find({"th", "td"})] for row in tables[0].find({"tr"})]
    if not rows or rows[0] != ["Versions", "Affected", "Unaffected"]:
        raise ValueError("Reviewed product table columns changed")
    products = [row[0] for row in rows[1:] if len(row) == 3]
    if (
        len(products) != len(rows) - 1
        or len(products) != len(set(products))
        or any(row[1:] != ["None", "All"] for row in rows[1:])
    ):
        raise ValueError("Reviewed explicit non-impact rows changed")
    out = base(vendor, url, identity, TITLES[identity])
    out.update(dates, document_status="published")
    if identity == NAT:
        if (
            cves(article.text())
            or products != ["PAN-OS"]
            or texts[context] != "Cannot be exposed."
            or "A PAN-OS software upgrade is not required to mitigate NAT slipstreaming attacks."
            not in texts["Solution"]
        ):
            raise ValueError("Reviewed NAT notice scope changed")
        signatures = re.findall(r"NAT Slipstreaming Detection \((\d+)\)", texts["Solution"])
        if signatures != ["59667", "59668", "59669", "59671", "59672"]:
            raise ValueError("Reviewed NAT mitigation signatures changed")
        out["source_format"] = NOTICE_FORMAT
        out["notes"] = [
            {"category": name, "text": text} for name, text in texts.items() if name != "Timeline"
        ]
        out["warnings"] = [
            "Notice-scoped product and mitigation statements only. No CVE or firmware fix is established; signature and browser versions are not PAN-OS releases."
        ]
    else:
        if (
            set(cves(texts["Description"])) != MOVE_CVES
            or set(cves(article.text())) != MOVE_CVES
            or RATIONALE not in texts["Description"]
            or set(products) != MOVE_PRODUCTS
            or texts["Solution"] != "No software updates are required at this time."
        ):
            raise ValueError("Reviewed MOVEit non-impact scope changed")
        out["source_format"] = "Reviewed MOVEit non-impact product table HTML"
        out["cves"] = sorted(MOVE_CVES)
        for product in products:
            for cid in out["cves"]:
                claim = assessment(
                    cid,
                    product,
                    "unaffected",
                    f"div#content / Product Status / table / row[product={product}] / Unaffected",
                )
                claim["exposure"] = [
                    {"category": "publisher_applicability_rationale", "details": RATIONALE},
                    {
                        "category": "publisher_product_status",
                        "details": "Affected: None; Unaffected: All",
                    },
                ]
                out["assessments"].append(claim)
        out["warnings"] = [
            "Explicit vendor non-impact claims only. The product table does not establish a firmware fix, patch event, dependency inventory or applicability outside these three CVEs."
        ]
    return out


def retain_notice(document):
    return (
        document.get("advisory_id") == NAT
        and document.get("source_url") == BASE + NAT
        and document.get("source_format") == NOTICE_FORMAT
        and not document.get("cves")
        and not document.get("assessments")
    )
