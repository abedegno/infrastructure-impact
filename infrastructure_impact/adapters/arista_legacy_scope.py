"""Reviewed 2020/2021 Arista product/model boundaries and local CVE matrices."""

import re
from urllib.parse import urlsplit

from .arista_scoped import leading_inline, reviewed_sections
from .common import HTML, Node, assessment, base, cves, iso_date

ROUTES = {
    "57": ("11997-security-advisory-57", ["CVE-2020-26569"]),
    "58": ("11998-security-advisory-58", ["CVE-2020-3702"]),
    "61": ("12135-security-advisory-61", ["CVE-2020-25684", "CVE-2020-25685", "CVE-2020-25686"]),
    "62": ("12166-security-advisory-62", ["CVE-2020-28362"]),
    "63": (
        "12602-security-advisory-63",
        [
            "CVE-2020-24586",
            "CVE-2020-24587",
            "CVE-2020-24588",
            "CVE-2020-26139",
            "CVE-2020-26140",
            "CVE-2020-26141",
            "CVE-2020-26142",
            "CVE-2020-26143",
            "CVE-2020-26144",
            "CVE-2020-26145",
            "CVE-2020-26146",
            "CVE-2020-26147",
        ],
    ),
}
AFFECTED = "The following products are affected by this vulnerability:"
UNAFFECTED = "The following products are not affected:"


def one(values, label):
    values = list(values)
    if len(values) != 1:
        raise ValueError("Expected one reviewed Arista " + label)
    return values[0]


def children(node, tags=None):
    return [c for c in node.children if isinstance(c, Node) and (tags is None or c.tag in tags)]


def leaf_items(node):
    items = children(node)
    if not items or any(
        c.tag != "li" or list(c.find({"ul", "ol", "table"})) or not c.text() for c in items
    ):
        raise ValueError("Nested or empty Arista list requires scope review")
    return [c.text() for c in items]


def labelled_list(node, marker, *, sibling=False):
    nodes = children(node)
    if node.tag != "ul" or not nodes or nodes[0].tag != "li" or leading_inline(nodes[0]) != marker:
        raise ValueError("Reviewed Arista applicability marker changed")
    if (
        sibling
        and len(nodes) == 2
        and nodes[1].tag == "ul"
        and not list(nodes[0].find({"ul", "ol"}))
    ):
        return nodes[1]  # Reviewed 0057 publisher markup closes its label before the child list.
    if len(nodes) != 1:
        raise ValueError("Arista labelled-list boundary changed")
    return one(children(nodes[0], {"ul"}), "local labelled list")


def article(raw, url, vendor, number, *, routes=None):
    slug, expected_ids = (ROUTES if routes is None else routes)[number]
    parsed = urlsplit(url)
    if (
        vendor != "arista"
        or parsed.hostname != "www.arista.com"
        or parsed.path != "/en/support/advisories-notices/security-advisory/" + slug
    ):
        raise ValueError("Unreviewed older Arista route")
    root = HTML(raw).root
    a = one(
        (n for n in root.find({"div"}) if "item-page" in n.attrs.get("class", "").split()),
        "article",
    )
    heading = one(
        (n for n in a.find({"h2"}) if n.text().startswith("Security Advisory ")), "advisory heading"
    )
    if heading.text() not in {
        f"Security Advisory {int(number):04d}",
        f"Security Advisory {int(number):04d} PDF",
    }:
        raise ValueError("Older Arista advisory identity changed")
    revision_tables = []
    for candidate in a.find({"table"}):
        rows = list(candidate.find({"tr"}))
        if rows and [n.text() for n in children(rows[0], {"td", "th"})] == [
            "Revision",
            "Date",
            "Changes",
        ]:
            revision_tables.append(candidate)
    table = one(revision_tables, "revision table")
    revisions = []
    for row in list(table.find({"tr"}))[1:]:
        cells = [c.text() for c in children(row, {"td", "th"})]
        if len(cells) != 3 or not re.fullmatch(r"\d+\.\d+", cells[0]):
            raise ValueError("Older Arista revision row changed")
        value = iso_date(cells[1])
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value or ""):
            raise ValueError("Older Arista revision date changed")
        revisions.append({"number": cells[0], "date": value, "summary": cells[2]})
    initial = one((r for r in revisions if r["number"] == "1.0"), "initial revision")
    if len({r["number"] for r in revisions}) != len(revisions):
        raise ValueError("Conflicting older Arista revision identity")
    latest = max(revisions, key=lambda r: tuple(map(int, r["number"].split("."))))
    out = base(
        "arista",
        url,
        slug,
        "Arista Security Advisory " + f"{int(number):04d}",
        initial["date"],
        latest["date"],
    )
    out.update(
        cves=expected_ids,
        timeline=revisions,
        source_format="Arista reviewed older product/model HTML",
        document_status="published",
    )
    sections = reviewed_sections(
        a, ("Symptoms", "For More Information", "For More Information:", "Open a Service Request:")
    )
    if number != "63":
        tracked = cves(
            " ".join(
                n.text()
                for n in a.children
                if isinstance(n, Node) and n.tag == "p" and "CVE-ID" in n.text()
            )
        )
        if tracked != expected_ids:
            raise ValueError("Older Arista tracked CVE scope changed")
    headers = [n.text() for n in children(a, {"h4"}) if n.text().startswith("Updated:")]
    if headers and iso_date(headers[0].split(":", 1)[1].strip()) != latest["date"]:
        out["warnings"].append(
            "Publisher update header and latest revision-table date differ; updated_at uses the reported latest numbered revision date. Neither is an observed historical retrieval date."
        )
    return a, out, sections


def context(number):
    details = {
        "57": "EVPN VxLAN configuration and the listed X-series hardware scope require review in Description, Symptoms and Affected Platforms. Explicit inter-VLAN routing is distinguished by the publisher.",
        "58": "The publisher restricts applicability to listed AP models, radio/encryption settings and the conditions in Description and Symptoms. Its dated support statement does not establish current support or lifecycle status.",
        "61": "DNS-server/proxy configuration is required. The publisher exclusions carry a native-Linux customization caveat; review Description, Symptoms and the starred Affected Platforms note before using an unaffected statement.",
        "62": "TLS/client-certificate feature prerequisites and the EOS gRIBI qualification require source review. The common platform list spans multiple software classes and does not map every platform to each software row.",
        "63": "Model/CVE cells come only from the local Affected Platforms matrix. The all-available-versions expression is a dated publisher statement. Resolution is model-specific; no fixed-version cutoff or actual fix availability is inferred.",
    }
    return [
        {
            "category": "publisher_applicability",
            "details": details[number],
            "source_scope": "advisory_context_requires_product_configuration_review",
            "source_locator": "Description; Vulnerability Assessment / Affected Software and Affected Platforms; Symptoms; Resolution",
        }
    ]


def add(out, number, product, status, locator, *, versions=(), platforms=(), identity=None):
    for cid in out["cves"]:
        claim = assessment(
            cid,
            product,
            status,
            locator,
            [{"expression": v} for v in versions],
            scope="bulletin_shared" if len(out["cves"]) > 1 else "cve_specific",
        )
        claim["product_id"] = identity or product + ":" + status
        claim["platforms"] = list(platforms)
        claim["exposure"] = context(number)
        out["assessments"].append(claim)


def exclusions(out, number, node):
    items = children(node)
    if not items:
        raise ValueError("Empty Arista exclusion list")
    for item in items:
        if item.tag != "li":
            raise ValueError("Unreviewed Arista exclusion list structure")
        nested = children(item, {"ul"})
        label = leading_inline(item)
        if not label:
            raise ValueError("Empty Arista exclusion label")
        if nested:
            expected = {"57": "Arista EOS-based products:", "58": "Arista Wireless Access Points:"}
            if label != expected.get(number) or len(nested) != 1:
                raise ValueError("Unreviewed Arista product/model exclusion")
            models = leaf_items(nested[0])
            product = "Arista EOS" if number == "57" else "Arista Wireless Access Points"
            add(
                out,
                number,
                product,
                "unaffected",
                "Vulnerability Assessment / explicit model exclusions",
                platforms=models,
            )
        else:
            if list(item.find({"ol", "table", "ul"})):
                raise ValueError("Unreviewed nested exclusion")
            add(
                out,
                number,
                label,
                "unaffected",
                "Vulnerability Assessment / explicit product exclusions",
            )


def paragraph_ranges(out, number, sections):
    nodes = sections.get("Vulnerability Assessment", [])
    markers = [
        (i, n.text())
        for i, n in enumerate(nodes)
        if n.tag == "p" and n.text() in {"Affected Software", "Affected Platforms"}
    ]
    if len(markers) != 2 or [v for _, v in markers] != ["Affected Software", "Affected Platforms"]:
        raise ValueError("Older Arista software/platform paragraph boundaries changed")
    soft = nodes[markers[0][0] + 1 : markers[1][0]]
    platform = nodes[markers[1][0] + 1 :]
    product = "Arista EOS"
    if number in {"57", "61"}:
        if (
            len(soft) != 2
            or soft[0].tag != "p"
            or soft[0].text() != {"57": "EOS", "61": "EOS Versions"}[number]
            or soft[1].tag != "ul"
        ):
            raise ValueError("Older EOS software-list scope changed")
        versions = leaf_items(soft[1])
    else:
        if len(soft) != 1:
            raise ValueError("Older AP build scope changed")
        versions = leaf_items(labelled_list(soft[0], "AP Build versions"))
        product = "Arista Wireless Access Points"
    expression = (
        r"\d[\d.A-Za-z-]* and below releases in the \d+\.\d+\.x train\.?"
        if number in {"57", "61"}
        else r"\d[\d.A-Za-z-]* and below releases in the \d+(?:\.\d+)+ train\.?"
    )
    if any(not re.fullmatch(expression, value) for value in versions):
        raise ValueError("Unreviewed older Arista version expression")
    if number == "61":
        if (
            len(platform) != 4
            or platform[0].tag != "p"
            or not platform[0]
            .text()
            .startswith("This vulnerability affects all EOS products including")
            or platform[1].text() != "The following products are not affected * :"
            or platform[2].tag != "ul"
            or "DNS Proxy is not enabled" not in platform[3].text()
        ):
            raise ValueError("DNS proxy product caveat or platform boundary changed")
        add(
            out,
            number,
            product,
            "affected",
            "Vulnerability Assessment / Affected Software / EOS Versions",
            versions=versions,
        )
        exclusions(out, number, platform[2])
    else:
        expected_count = 2 if number == "57" else 3
        if len(platform) != expected_count:
            raise ValueError("Older Arista platform block changed")
        marker = (
            AFFECTED
            if number == "57"
            else "This vulnerability is applicable to following Arista Wireless Access Point platforms:"
        )
        models = leaf_items(labelled_list(platform[0], marker))
        if number == "58" and (
            "end of sale" not in platform[1].text() or "2023" not in platform[1].text()
        ):
            raise ValueError("Older AP dated support qualifier changed")
        add(
            out,
            number,
            product,
            "affected",
            "Vulnerability Assessment / Affected Software and affected models",
            versions=versions,
            platforms=models,
        )
        exclusions(out, number, labelled_list(platform[-1], UNAFFECTED, sibling=number == "57"))


def tls_software(out, sections):
    nodes = sections.get("Affected Software", [])
    expected = {
        "CloudVision Portal:": "CloudVision Portal (CVP)",
        "EOS:": "Arista EOS",
        "TerminAttr:": "Arista Streaming Telemetry Agent (TerminAttr)",
        "MOS:": "Arista 7130 Systems running MOS",
    }
    if len(nodes) != 2 * len(expected):
        raise ValueError("Older TLS software groups changed")
    seen = set()
    for label, versions in zip(nodes[::2], nodes[1::2]):
        key = label.text()
        if label.tag != "p" or key not in expected or key in seen or versions.tag != "ul":
            raise ValueError("Unreviewed older TLS software boundary")
        seen.add(key)
        expressions = leaf_items(versions)
        if any(not re.match(r"^(?:\d|TerminAttr-v\d|MOS-\d)", value) for value in expressions):
            raise ValueError("Older TLS version qualifier changed")
        add(
            out,
            "62",
            expected[key],
            "affected",
            "Vulnerability Assessment / Affected Software / " + key,
            versions=expressions,
        )
    nodes = sections.get("Affected Platforms", [])
    if len(nodes) != 1 or nodes[0].tag != "ul":
        raise ValueError("Older TLS common platform list changed")
    groups = children(nodes[0])
    if len(groups) != 2 or [leading_inline(n) for n in groups] != [AFFECTED, UNAFFECTED]:
        raise ValueError("Older TLS affected/unaffected group boundary changed")
    leaf_items(one(children(groups[0], {"ul"}), "TLS common affected platform list"))
    exclusions(out, "62", one(children(groups[1], {"ul"}), "TLS explicit unaffected list"))


def wifi_matrix(out, sections):
    nodes = sections.get("Vulnerability Assessment", [])
    tables = [
        n
        for n in nodes
        if n.tag == "table" and any(c.text() == "CVE ID" for c in n.find({"td", "th"}))
    ]
    table = one(tables, "local Wi-Fi CVE/model matrix")
    rows = list(table.find({"tr"}))
    header_cells = children(rows[0], {"td", "th"})
    header = [c.text() for c in header_cells]
    index = nodes.index(table)
    if index < 1 or nodes[index - 1].tag != "p" or nodes[index - 1].text() != "Affected Platforms":
        raise ValueError("Wi-Fi matrix is outside the reviewed affected-platforms boundary")
    if any(c.attrs.get("colspan") or c.attrs.get("rowspan") for c in header_cells):
        raise ValueError("Wi-Fi matrix header spans require review")
    known = {
        "Access Points C-250 C-260 C-230 C-235 C-200",
        "Access Points C-120 C-130 C-100 C-110 O-105 W-118",
        "Access Points C-75 O-90 C-65 W-68",
    }
    if len(header) != 4 or header[0] != "CVE ID" or set(header[1:]) != known:
        raise ValueError("Wi-Fi CVE/model matrix headers changed")
    groups = [label.removeprefix("Access Points ").split() for label in header[1:]]
    seen = set()
    software = [
        n
        for n in nodes
        if n.tag == "ul"
        and n.text() == "All available versions of Wi-Fi AP software as per the impact matrix below"
    ]
    one(software, "Wi-Fi dated software expression")
    index = nodes.index(software[0])
    if index < 1 or nodes[index - 1].tag != "p" or nodes[index - 1].text() != "Affected Software":
        raise ValueError("Wi-Fi software-expression boundary changed")
    for row in rows[1:]:
        cells = children(row, {"td", "th"})
        values = [c.text() for c in cells]
        if (
            len(values) != 4
            or any(c.attrs.get("colspan") or c.attrs.get("rowspan") for c in cells)
            or values[0] not in out["cves"]
            or values[0] in seen
            or any(v not in {"Y", "N"} for v in values[1:])
        ):
            raise ValueError("Unreviewed Wi-Fi matrix CVE, cell or span")
        seen.add(values[0])
        for models, value in zip(groups, values[1:]):
            claim = assessment(
                values[0],
                "Arista Wireless Access Points",
                "affected" if value == "Y" else "unaffected",
                "Vulnerability Assessment / Affected Platforms matrix / "
                + values[0]
                + " / "
                + ", ".join(models),
                [{"expression": software[0].text()}],
            )
            claim["product_id"] = "wifi-model-group:" + ",".join(models)
            claim["platforms"] = models
            claim["exposure"] = context("63")
            out["assessments"].append(claim)
    if seen != set(out["cves"]):
        raise ValueError("Incomplete Wi-Fi CVE/model matrix")
    out["warnings"].append(
        "Only twelve local matrix CVEs supply product claims. Other vulnerability identifiers mentioned outside that matrix are references only. Y/N are interpreted only in this reviewed Affected Platforms table; columns preserve literal model labels, including C-235. Model-specific resolution dates do not establish observed historical fix availability."
    )


def older_scope(raw, url, vendor):
    slug = urlsplit(url).path.rsplit("/", 1)[-1]
    number = next((key for key, value in ROUTES.items() if value[0] == slug), None)
    if number is None:
        raise ValueError("Unreviewed older Arista advisory")
    a, out, sections = article(raw, url, vendor, number)
    if not sections.get("Description") or not sections.get("Symptoms"):
        raise ValueError("Older Arista applicability context missing")
    if number in {"57", "58", "61"}:
        paragraph_ranges(out, number, sections)
    elif number == "62":
        tls_software(out, sections)
    else:
        wifi_matrix(out, sections)
        references = sorted(set(cves(a.text())) - set(out["cves"]))
        if references:
            out["warnings"].append(
                "Other identifiers occur outside the local impact matrix and supply no product claims: "
                + ", ".join(references)
            )
    if not out["assessments"]:
        raise ValueError("No reviewed older Arista statements")
    out["warnings"].append(
        "Only reviewed local software/model statements are normalized. Nested exclusions never become blanket product-family unaffectedness. Configuration prerequisites, source model labels and dated lifecycle statements require source review. Shared multi-CVE ranges remain shared; no automatic version matching, complete inventory or first historical fix availability is inferred."
    )
    return out
