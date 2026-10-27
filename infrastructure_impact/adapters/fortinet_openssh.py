"""Reviewed regreSSHion table and explicit Fortinet assessment lists."""

import re
from urllib.parse import urlsplit

from .common import HTML, Node, assessment, base, cves, iso_date

ID = "FG-IR-24-258"
CVE = "CVE-2024-6387"
TITLE = "OpenSSH regreSSHion Attack (CVE-2024-6387)"


def reviewed_route(url):
    parsed = urlsplit(url)
    return (
        parsed.scheme == "https"
        and parsed.hostname in {"www.fortiguard.com", "fortiguard.fortinet.com"}
        and parsed.path == "/psirt/" + ID
        and not parsed.query
        and not parsed.fragment
    )


def one(values, label):
    values = list(values)
    if len(values) != 1:
        raise ValueError("Expected one reviewed Fortinet " + label)
    return values[0]


def direct(node, tags=None):
    return [c for c in node.children if isinstance(c, Node) and (tags is None or c.tag in tags)]


def lines(node):
    if isinstance(node, str):
        return node
    return "\n" if node.tag == "br" else "".join(lines(c) for c in node.children)


def solution(text, status):
    if status == "unaffected":
        if text != "Not Applicable":
            raise ValueError("Unreviewed Fortinet unaffected-row solution")
        return [{"category": "publisher_solution", "details": text, "availability": "not_a_fix"}]
    if text == "Migrate to a fixed release":
        availability = "unknown"
    elif re.fullmatch(r"Upgrade to (upcoming  ?)?\d+(?:\.\d+)+ or above", text):
        availability = "planned" if "upcoming " in text else "vendor_reports_fixed"
    else:
        raise ValueError("Unreviewed Fortinet upgrade or availability qualifier")
    return [{"category": "vendor_upgrade", "details": text, "availability": availability}]


def context(locator):
    return [
        {
            "category": "publisher_applicability",
            "source_scope": "advisory_context_requires_product_configuration_review",
            "source_locator": locator
            + "; post-table OS/library/ASLR qualifications, workarounds and mitigations",
            "details": "Review the publisher OS/library and ASLR qualifications and SSH prerequisites. An exploitability qualification is not blanket unaffectedness. No installed dependency, enabled service, deployment exposure or actual release availability is inferred.",
        }
    ]


def product_list(paragraph, heading):
    if list(paragraph.find({"ul", "ol", "table"})):
        raise ValueError("Nested Fortinet assessment condition requires review")
    values = [" ".join(v.split()) for v in lines(paragraph).splitlines() if v.strip()]
    if not values or values[0] != heading:
        raise ValueError("Fortinet explicit assessment heading changed")
    products = []
    for value in values[1:]:
        match = re.fullmatch(r"-\s+(Forti[A-Za-z0-9][A-Za-z0-9 .()/+-]*)", value)
        if not match or match[1] in products:
            raise ValueError("Unreviewed or repeated Fortinet assessment product")
        products.append(match[1])
    if not products:
        raise ValueError("Empty Fortinet explicit assessment list")
    return products


def openssh_advisory(raw, url, vendor="fortinet"):
    if not reviewed_route(url) or vendor != "fortinet":
        raise ValueError("Unreviewed Fortinet OpenSSH advisory route")
    root = HTML(raw).root
    if one(root.find({"h1"}), "advisory title").text() != TITLE:
        raise ValueError("Fortinet OpenSSH title changed")
    meta = {}
    metadata = one(
        (t for t in root.find({"table"}) if "meta" in t.attrs.get("class", "").split()),
        "metadata table",
    )
    for row in metadata.find({"tr"}):
        cells = [n.text() for n in direct(row, {"td"})]
        if len(cells) != 2 or cells[0] in meta:
            raise ValueError("Unreviewed or duplicate Fortinet advisory metadata")
        meta[cells[0]] = cells[1]
    if meta.get("IR Number") != ID or cves(meta.get("CVE ID", "")) != [CVE]:
        raise ValueError("Fortinet OpenSSH advisory/CVE identity changed")
    if not meta.get("Published Date") or not meta.get("Updated Date"):
        raise ValueError("Fortinet dated metadata missing")
    details = [n for n in root.find({"div"}) if "detail-item" in n.attrs.get("class", "").split()]
    summary = one(
        (d for d in details if any(h.text() == "Summary" for h in d.find({"h2"}))), "CVE summary"
    )
    if [h.text() for h in summary.find({"h2"})] != ["Summary", CVE]:
        raise ValueError("Fortinet local summary CVE boundary changed")
    tables = []
    for d in details:
        for table in d.find({"table"}):
            rows = list(table.find({"tr"}))
            if rows and [c.text() for c in direct(rows[0], {"th", "td"})] == [
                "Version",
                "Affected",
                "Solution",
            ]:
                if any(
                    c.attrs.get("colspan") or c.attrs.get("rowspan")
                    for c in direct(rows[0], {"th", "td"})
                ):
                    raise ValueError("Fortinet version table header spans require review")
                tables.append(table)
    table = one(tables, "version/affected/solution table")
    prose = one(
        (
            d
            for d in details
            if any(p.text().startswith("Products NOT Impacted:") for p in d.find({"p"}))
        ),
        "post-table assessment context",
    )
    if any(n.tag != "p" for n in direct(prose)):
        raise ValueError("Fortinet assessment-context layout changed")
    fields = {}
    fixed = {}
    labels = {
        "Vulnerable OpenSSH versions:",
        "OpenSSH versions confirmed not vulnerable:",
        "Please note:",
        "Products Under Investigation:",
        "Products NOT Impacted:",
        "Workarounds:",
        "Mitigations:",
    }
    for paragraph in direct(prose, {"p"}):
        text = paragraph.text()
        cloud = re.fullmatch(
            r"Fortinet has remediated this issue in (FortiDevSec|FortiLANCloud) version (\d+(?:\.\d+)+); and the customers do not need to perform any action\.",
            text,
        )
        if cloud:
            if cloud[1] in fixed:
                raise ValueError("Duplicate Fortinet remediation statement")
            fixed[cloud[1]] = cloud[2]
            continue
        label = next((label for label in labels if text.startswith(label)), None)
        if label is None or label in fields:
            raise ValueError("Unreviewed Fortinet assessment or configuration paragraph")
        fields[label] = paragraph
    if set(fields) != labels or set(fixed) != {"FortiDevSec", "FortiLANCloud"}:
        raise ValueError("Fortinet assessment/qualification scope incomplete")
    if not all(
        value in fields["Please note:"].text()
        for value in ["OpenBSD", "glibc-linux", "64bits", "ASLR"]
    ):
        raise ValueError("Fortinet OS/library/exploitability context changed")
    out = base(
        "fortinet", url, ID, TITLE, iso_date(meta["Published Date"]), iso_date(meta["Updated Date"])
    )
    out.update(
        cves=[CVE],
        source_format="Fortinet reviewed OpenSSH table and explicit assessment HTML",
        document_status="published",
    )
    seen = set()
    branch_statuses = {}
    affected_products = set()
    for row in list(table.find({"tr"}))[1:]:
        cells = direct(row, {"th", "td"})
        if len(cells) != 3 or any(
            c.attrs.get("colspan") or c.attrs.get("rowspan") or list(c.find({"ul", "ol", "table"}))
            for c in cells
        ):
            raise ValueError("Fortinet version row structure changed")
        label, affected, upgrade = [c.text() for c in cells]
        match = re.fullmatch(r"(Forti[A-Za-z0-9-]+(?: Cloud)?) (\d+(?:\.\d+)+)", label)
        if not match or (label, affected) in seen:
            raise ValueError("Fortinet product/train row identity changed")
        seen.add((label, affected))
        product, train = match[1], match[2]
        status = "unaffected" if affected == "Not affected" else "affected"
        if label in branch_statuses and branch_statuses[label] != status:
            raise ValueError(
                "Conflicting Fortinet train-wide and affected-range statements require review"
            )
        branch_statuses[label] = status
        if status == "affected" and not re.fullmatch(
            r"\d+(?:\.\d+)+(?: through \d+(?:\.\d+)+| all versions)?", affected
        ):
            raise ValueError("Unreviewed Fortinet affected version expression")
        if affected.endswith(" all versions") and affected.removesuffix(" all versions") != train:
            raise ValueError("Fortinet all-versions expression does not match its literal train")
        if status == "affected":
            affected_products.add(product)
        locator = "Version/Affected/Solution table / " + label
        claim = assessment(
            CVE,
            product,
            status,
            locator,
            [{"expression": affected, "status": status}],
            solution(upgrade, status),
        )
        claim["product_id"] = "table:" + label + ":" + affected
        claim["product_context"] = [["product_name", product], ["product_version", train]]
        claim["exposure"] = context(locator)
        out["assessments"].append(claim)
    if not seen:
        raise ValueError("Fortinet version table empty")
    scoped_products = set()
    for heading, status in [
        ("Products Under Investigation:", "investigating"),
        ("Products NOT Impacted:", "unaffected"),
    ]:
        for product in product_list(fields[heading], heading):
            if product in scoped_products or product in affected_products:
                raise ValueError("Conflicting Fortinet explicit product scopes require review")
            scoped_products.add(product)
            locator = "Post-table explicit list / " + heading + " / " + product
            claim = assessment(CVE, product, status, locator)
            claim["product_id"] = "explicit-list:" + product
            claim["product_context"] = [["product_name", product]]
            claim["exposure"] = context(locator)
            out["assessments"].append(claim)
    for product, version in fixed.items():
        if product in scoped_products or product in affected_products:
            raise ValueError("Fortinet remediation/product assessment conflict requires review")
        claim = assessment(
            CVE,
            product,
            "fixed",
            "Post-table publisher remediation statement / " + product,
            [{"version": version, "status": "fixed", "versionType": "custom"}],
            [
                {
                    "category": "vendor_fix",
                    "details": version,
                    "availability": "vendor_reports_fixed",
                }
            ],
        )
        claim["product_id"] = "publisher-remediation:" + product
        claim["product_context"] = [
            ["product_name", product],
            [
                "publisher_action_requirement",
                "No customer action reported; deployment mode not established",
            ],
        ]
        claim["exposure"] = [
            {
                "category": "publisher_remediation",
                "source_scope": "fixed_statement_without_prior_exposure_inference",
                "source_locator": claim["evidence_locator"],
                "details": "The publisher reports remediation without customer action. Prior exposure, deployment mode, build applicability and actual release availability are not independently verified.",
            }
        ]
        out["assessments"].append(claim)
    out["warnings"] = [
        "Only the single locally identified CVE supplies product claims. Historical CVEs in upstream OpenSSH version explanations are references, not additional appliance assessments. Explicit NOT Impacted lists do not apply to unlisted products.",
        "Literal train/range expressions and planned upgrades are retained without version arithmetic. OS/library/ASLR and SSH prerequisites require source review. Fixed-only statements do not establish prior affectedness; no cloud deployment mode or independently available firmware is inferred from a no-customer-action statement.",
    ]
    return out
