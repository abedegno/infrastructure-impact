"""Reviewed SA-0137 tunnel and platform ownership; no version arithmetic."""

from .arista_current_scope import context, leaves, nonempty
from .arista_legacy_scope import children, one
from .arista_scoped import article, leading_inline
from .common import Node, assessment, cves, iso_date

URL = "https://www.arista.com/en/support/advisories-notices/security-advisory/24005-security-advisory-0137"
CSAF = "https://www.arista.com/assets/data/SecurityAdvisories/CSAF/arista_networks_security_advisory_137_CSAF.json"
CSAF_ID = "Arista Networks Security Advisory 137"
ID = "24005-security-advisory-0137"
CVES = ["CVE-2026-7473"]
FORMAT = "Arista reviewed SA-0137 tunnel applicability HTML"
VERSIONS = [f"All releases in the 4.{n}.x train" for n in range(36, 29, -1)] + [
    "All releases in trains older than 4.30.x",
    "All releases in trains newer than 4.36.x",
]
AFFECTED = [
    "7020R Series",
    "7280R/R2Series",
    "7500R/R2 Series",
    "7280R3 Series",
    "7500R3 Series",
    "7800R3 Series",
]
LIMITED = "Limited exposure (IP-in-IPv6 and GUEv6) on:"
YES = "The following products are affected by this vulnerability:"
NO = "The following product versions and platforms are not affected by this vulnerability:"
EOS = "Arista EOS-based products:"


def parse(raw, url, vendor):
    if url != URL or vendor != "arista":
        raise ValueError("Unreviewed SA-0137 route")
    a, out = article(raw, url, "0137")
    heading = one(
        (n for n in a.find({"h2"}) if n.text().startswith("Security Advisory ")), "heading"
    )
    if " ".join(" ".join(c for c in heading.children if isinstance(c, str)).split()) not in {
        "Security Advisory 0137",
        "Security Advisory 0137 .",
    }:
        raise ValueError("SA-0137 heading identity changed")
    nodes = children(a)
    description = next(
        i for i, n in enumerate(nodes) if n.tag == "h2" and n.text() == "Description"
    )
    if cves(" ".join(n.text() for n in nodes[:description] if n.tag == "p")) != CVES:
        raise ValueError("SA-0137 header CVE scope changed")
    # Retain nested mitigation headings together; only EOS Versions may nest
    # inside the reviewed software section.
    sections, current = {}, None
    for n in nodes[description:]:
        if n.tag in {"h2", "h3"} and (current != "Mitigation" or n.tag == "h2"):
            current = n.text()
            if current in sections:
                raise ValueError("Repeated SA-0137 section")
            sections[current] = []
        elif current:
            sections[current].append(n)
    expected = [
        "Description",
        "Vulnerability Assessment",
        "Affected Software",
        "Affected Platforms",
        "Required Configuration for Exploitation",
        "Indicators of Compromise",
        "Mitigation",
        "Resolution",
        "Hotfix",
        "For More Information",
    ]
    if list(sections)[: len(expected)] != expected:
        raise ValueError("SA-0137 heading boundary changed")
    software = nonempty(sections["Affected Software"])
    if (
        len(software) != 2
        or software[0].tag != "h4"
        or software[0].text() != "EOS Versions"
        or leaves(software[1]) != VERSIONS
    ):
        raise ValueError("SA-0137 EOS versions changed")
    platform = nonempty(sections["Affected Platforms"])
    if (
        len(platform) != 4
        or [n.tag for n in platform] != ["div", "ul", "div", "ul"]
        or platform[0].text() != YES
        or platform[2].text() != NO
        or platform[0].attrs
        or platform[2].attrs
    ):
        raise ValueError("SA-0137 platform status boundaries changed")
    if platform[1].attrs or any(isinstance(c, str) and c.strip() for c in platform[1].children):
        raise ValueError("Unreviewed SA-0137 positive list qualifier")
    positive = children(platform[1])
    if len(positive) != 1 or positive[0].tag != "li" or leading_inline(positive[0]) != EOS:
        raise ValueError("SA-0137 affirmative ownership changed")
    if (
        positive[0].attrs
        or [n.tag for n in children(positive[0])] != ["br", "ul"]
        or any(n.attrs for n in children(positive[0], {"br"}))
        or " ".join(" ".join(c for c in positive[0].children if isinstance(c, str)).split()) != EOS
    ):
        raise ValueError("Unreviewed SA-0137 positive group qualifier")
    nested = one(children(positive[0], {"ul"}), "affected platform list")
    items = children(nested)
    if (
        nested.attrs
        or len(items) != 6
        or any(n.tag != "li" or n.attrs for n in items)
        or [leading_inline(n) for n in items] != AFFECTED
    ):
        raise ValueError("SA-0137 affected platform groups changed")
    for i, n in enumerate(items):
        if i != 2 and children(n):
            raise ValueError("Unreviewed SA-0137 platform qualifier")
    tail = items[2]
    if [(n.tag, n.attrs, n.text()) for n in children(tail)] != [
        ("br", {}, ""),
        ("div", {"class": "clear5"}, ""),
    ] or tail.text() != AFFECTED[2] + " " + LIMITED:
        raise ValueError("SA-0137 limited exposure boundary changed")
    negative = children(platform[3])
    if any(isinstance(c, str) and c.strip() for c in platform[3].children):
        raise ValueError("Unreviewed SA-0137 negative list qualifier")
    if (
        platform[3].attrs
        or len(negative) < 3
        or [n.tag for n in negative[:2]] != ["li", "ul"]
        or negative[0].text() != EOS
        or children(negative[0])
    ):
        raise ValueError("SA-0137 negative EOS ownership changed")
    excluded = leaves(negative[1])
    # Preserve the publisher placement of CVX without calling it EOS software.
    cvx = "CloudVision eXchange, virtual or physical appliance"
    if len(excluded) != 30 or excluded[-1] != cvx or any(n.tag != "li" for n in negative[2:]):
        raise ValueError("SA-0137 negative group boundary changed")
    other_list = Node("ul")
    other_list.children = negative[2:]
    others = leaves(other_list)
    if len(others) != 15 or len(set(excluded + others + AFFECTED)) != len(
        excluded + others + AFFECTED
    ):
        raise ValueError("SA-0137 product status identity changed")
    configuration = nonempty(sections["Required Configuration for Exploitation"])
    config_text = " ".join(n.text() for n in configuration)
    required = [
        "The device must be configured as a tunnel endpoint with a decapsulation IP",
        "Only the IP-in-IPv6 and GUE IPV6 Decap Group scenarios apply to 7280R3 Series, 7500R3 Series, and 7800R3 Series.",
        "the device does not perform tunnel decapsulation and is not exposed to this issue.",
    ]
    if (
        any(value not in config_text for value in required)
        or len([n for n in configuration if n.tag == "table"]) != 1
    ):
        raise ValueError("SA-0137 tunnel prerequisites changed")
    config = context(
        configuration,
        "Required Configuration for Exploitation / protocol table and endpoint prerequisites",
    )
    family = assessment(
        CVES[0],
        "Arista EOS",
        "affected",
        "Affected Software / EOS Versions",
        [{"expression": v} for v in VERSIONS],
    )
    family["exposure"] = [
        config,
        context([platform[1]], "Affected Platforms / affected / EOS groups"),
    ]
    out["assessments"] = [family]
    for i, label in enumerate(AFFECTED):
        claim = assessment(CVES[0], label, "affected", "Affected Platforms / affected / " + label)
        # The validated outer EOS-based list owns the software family; this
        # does not resolve the literal hardware label to a study model.
        claim["product_context"] = [["product_family", "Arista EOS"]]
        claim["platforms"] = [label]
        claim["exposure"] = [config]
        if i >= 3:
            claim["exposure"].append(
                context([tail], "Affected Platforms / affected / embedded limited exposure marker")
            )
        out["assessments"].append(claim)
    for label in excluded + others:
        product = "Arista EOS" if label in excluded[:-1] else label
        claim = assessment(
            CVES[0], product, "unaffected", "Affected Platforms / not affected / " + label
        )
        claim["product_id"] = "unaffected:" + label
        claim["platforms"] = [label]
        claim["exposure"] = [context([platform[2]], "Affected Platforms / not affected marker")]
        out["assessments"].append(claim)
    resolution = " ".join(n.text() for n in sections["Resolution"])
    if not resolution.startswith(
        "No software upgrade path is planned to address this issue"
    ) or "No hotfix is available for these issues." != " ".join(
        n.text() for n in nonempty(sections["Hotfix"])
    ):
        raise ValueError("SA-0137 no software fix statement changed")
    family["remediations"] = [
        {
            "category": "mitigation",
            "details": resolution,
            "availability": "not_a_fix",
            "source_locator": "Resolution",
        }
    ]
    tables = [
        t
        for t in a.find({"table"})
        if [n.text() for n in children(next(t.find({"tr"})), {"td", "th"})]
        == ["Revision", "Date", "Changes"]
    ]
    table = one(tables, "revision table")
    revisions = []
    for row in list(table.find({"tr"}))[1:]:
        cells = [n.text() for n in children(row, {"td", "th"})]
        if len(cells) != 3:
            raise ValueError("SA-0137 revision shape changed")
        revisions.append({"number": cells[0], "date": iso_date(cells[1]), "summary": cells[2]})
    if [(r["number"], r["date"]) for r in revisions] != list(
        zip(
            ["1.0", "1.1", "1.2", "1.3", "1.4"],
            ["2026-05-05", "2026-05-07", "2026-05-13", "2026-05-20", "2026-08-10"],
        )
    ):
        raise ValueError("SA-0137 reviewed revision chronology changed")
    out.update(
        cves=CVES.copy(),
        source_format=FORMAT,
        document_status="published",
        timeline=revisions,
        updated_at=revisions[-1]["date"],
    )
    out["notes"] = [
        {
            "category": "publisher_context",
            "text": "\n".join(n.text() for n in sections[name]),
            "source_locator": name,
        }
        for name in [
            "Required Configuration for Exploitation",
            "Mitigation",
            "Resolution",
            "Hotfix",
        ]
    ]
    out["warnings"] = [
        "Affected EOS family scope is conditional on listed hardware and tunnel configuration. Literal slash labels remain unresolved; no fixed release or hardware alias is inferred."
    ]
    return out


REVIEWED_SHA256 = "5f7b0449565fc1aa4ab5ffe88a0e40dba8f2725ed33824c062e230e3b5035d24"


def draft_shape(raw):
    """Exact publisher placeholder structure, independently of normalized claims."""
    import json

    data = json.loads(raw)
    document = data.get("document", {})
    if (
        document.get("tracking", {}).get("id") != CSAF_ID
        or document.get("tracking", {}).get("status") != "draft"
    ):
        return False
    references = document.get("references", [])
    if [r.get("url") for r in references if r.get("category") == "self"] != [URL]:
        return False
    expected_tree = {
        "branches": [
            {
                "category": "vendor",
                "name": "Arista Networks, Inc.",
                "branches": [
                    {
                        "category": "product_family",
                        "name": "Software Products",
                        "branches": [
                            {
                                "category": "product_name",
                                "name": "EOS",
                                "branches": [
                                    {
                                        "category": "product_version",
                                        "name": "EOS version 1.0.0",
                                        "product": {
                                            "name": "EOS version 1.0.0",
                                            "product_id": "CSAFPID-0",
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    entries = data.get("vulnerabilities", [])
    return (
        data.get("product_tree") == expected_tree
        and len(entries) == 1
        and entries[0].get("cve") == CVES[0]
        and entries[0].get("product_status") == {"first_affected": ["CSAFPID-0"]}
    )
