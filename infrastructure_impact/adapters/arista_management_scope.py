"""Reviewed CloudVision management-appliance scope, not client-device exposure."""

import re
from urllib.parse import urljoin, urlsplit

from .arista_legacy_scope import UNAFFECTED, article, children, labelled_list, leaf_items, one
from .arista_routing_scope import reported_fixes
from .arista_scoped import leading_inline
from .common import assessment

ROUTES = {
    "50": ("11705-security-advisory-50", ["CVE-2020-13881"]),
    "51": ("11706-security-advisory-51", ["CVE-2020-24333"]),
    "52": ("11758-security-advisory-52", ["CVE-2020-13100"]),
}
CONTEXT = {
    "50": "CloudVision Portal base-VM/shell login must use TACACS+; web UI login alone is outside this exposure. Access to logged key material and captured TACACS+ traffic qualify the credential risk. Upgrading stops new key logging; the publisher also recommends changing TACACS+ and administrator passwords after upgrade to address earlier logging.",
    "51": "The API requires an authenticated user with Configlet Management read-only or greater rights. Default network-operator/network-admin roles and qualifying custom roles require review. Disabling the module is a mitigation for custom roles only, not those default roles. The affected-version table and listed fixes are separate publisher statements.",
    "52": "CloudVision eXchange server ControllerOob control-plane processing is in scope. A malformed control-plane packet can restart the server agent or trigger HA failover; the publisher does not expect production-traffic impact. EOS on CVX client switches is explicitly excluded. CP ACLs restrict access to known clients; the hotfix has persistence and agent-restart qualifications.",
}


def text(sections, name):
    return " ".join(n.text() for n in sections.get(name, []))


def require(value, phrases):
    if any(phrase not in value for phrase in phrases):
        raise ValueError("Arista management-appliance qualification changed")


def add(out, number, product, status, locator, *, ranges=(), platforms=()):
    claim = assessment(
        out["cves"][0], product, status, locator, [{"expression": v} for v in ranges]
    )
    claim["platforms"] = list(platforms)
    claim["exposure"] = [
        {
            "category": "publisher_applicability",
            "details": CONTEXT[number],
            "source_scope": "advisory_context_requires_product_configuration_review",
            "source_locator": "Description; Vulnerability Assessment; Mitigation; Resolution",
        }
    ]
    out["assessments"].append(claim)
    return claim


def management_scope(raw, url, vendor):
    slug = urlsplit(url).path.rsplit("/", 1)[-1]
    number = next((n for n, route in ROUTES.items() if route[0] == slug), None)
    if number is None:
        raise ValueError("Unreviewed Arista management advisory")
    _, out, sections = article(raw, url, vendor, number, routes=ROUTES)
    out["source_format"] = "Arista reviewed management-appliance HTML"
    nodes = sections.get("Vulnerability Assessment", [])
    markers = [
        (i, n.text())
        for i, n in enumerate(nodes)
        if n.tag == "p" and n.text() in {"Affected Software", "Affected Platforms"}
    ]
    if [label for _, label in markers] != ["Affected Software", "Affected Platforms"]:
        raise ValueError("Arista management software/platform boundary changed")
    software = nodes[markers[0][0] + 1 : markers[1][0]]
    platform = one(nodes[markers[1][0] + 1 :], "management platform block")
    items = children(platform)
    # These three reviewed pages close the exclusion label before its list.
    # Keep this sibling structure local; do not flatten arbitrary nested lists.
    if platform.tag != "ul" or [n.tag for n in items] != ["li", "li", "ul"]:
        raise ValueError("Arista management platform grouping changed")
    appliance = items[0].text()
    require(
        appliance,
        (
            "This vulnerability affects CloudVision",
            "virtual and physical appliances",
            "versions identified above",
        ),
    )
    if children(items[0]) or leading_inline(items[1]) != UNAFFECTED:
        raise ValueError("Arista appliance/exclusion boundary changed")
    if list(items[1].find({"ul", "ol", "table"})):
        raise ValueError("Arista management exclusion label contains an unreviewed group")
    exclusions = leaf_items(items[2])
    description, resolution = text(sections, "Description"), text(sections, "Resolution")
    if number in {"50", "51"}:
        table = one((n for n in software if n.tag == "table"), "CloudVision version table")
        if any(n.tag not in {"p", "table"} for n in software):
            raise ValueError("Unreviewed CloudVision version context")
        rows = [[c.text() for c in children(row, {"td", "th"})] for row in table.find({"tr"})]
        if (
            len(rows) != 2
            or rows[0] != ["CloudVision Portal"]
            or len(rows[1]) != 1
            or not re.fullmatch(r"All releases prior to \d{4}\.\d+(?:\.\d+)?", rows[1][0])
        ):
            raise ValueError("Unreviewed CloudVision affected-version table")
        affected = add(
            out,
            number,
            "CloudVision Portal",
            "affected",
            "Affected Software / CloudVision Portal table",
            ranges=rows[1],
            platforms=[appliance],
        )
        fixed = re.search(
            r"addressed in the ([\d.,\s]+)(?:,? and) later versions of CloudVision Portal",
            resolution,
        )
        if not fixed:
            raise ValueError("CloudVision reported-fix boundary changed")
        builds = re.findall(r"\d{4}\.\d+(?:\.\d+)?", fixed[1])
        if not builds or re.sub(r"\d{4}\.\d+(?:\.\d+)?|[\s,]", "", fixed[1]):
            raise ValueError("Unreviewed CloudVision fixed-build expression")
        affected["remediations"] = [
            {
                "category": "vendor_fix",
                "details": build,
                "availability": "vendor_reports_fixed",
                "source_locator": "Resolution / CloudVision Portal listed fixes",
            }
            for build in builds
        ]
        if number == "50":
            require(
                description,
                ("TACACS+ authentication for the base operating system", "not for Web UI logins"),
            )
            require(
                resolution,
                (
                    "key will no longer be logged by journald",
                    "both the TACACS+ and Administrator passwords after the upgrade",
                ),
            )
        else:
            if rows[1] != ["All releases prior to 2020.2"] or builds != ["2020.1.2", "2020.2.0"]:
                raise ValueError("Reviewed CloudVision release-cutoff discrepancy changed")
            require(description, ("Configlet Management", "authenticated users", "network-admins"))
            require(
                text(sections, "Mitigation"),
                ("custom roles alone", "cannot be disabled for default roles"),
            )
            affected["remediations"].append(
                {
                    "category": "workaround",
                    "details": "Disable Configlet Management access for qualifying custom roles; unavailable for the default network-operator and network-admin roles.",
                    "availability": "partial_mitigation",
                    "source_locator": "Mitigation / custom-role-only restriction",
                }
            )
            out["warnings"].append(
                "Affected-version table and resolution use different release cutoffs; retained claims are not rewritten to reconcile them."
            )
    else:
        require(
            description,
            ("ControllerOob", "control-plane", "Impact to production traffic is not expected"),
        )
        require(text(sections, "Mitigation"), ("known CVX clients only", "50003 and 50004"))
        require(resolution, ("persistent across reboots", "agents", "restart"))
        if len(software) != 1 or software[0].tag != "ul":
            raise ValueError("CVX version grouping changed")
        ranges = leaf_items(
            labelled_list(software[0], "CloudVision eXchange VM/Appliance:", sibling=True)
        )
        if any(
            not re.fullmatch(
                r"\d[\d.FM]+ (?:and below releases?|to \d[\d.FM]+ releases) in the \d+\.\d+\.x train\.",
                v,
            )
            for v in ranges
        ):
            raise ValueError("Unreviewed CVX version expression")
        affected = add(
            out,
            number,
            "CloudVision eXchange VM/Appliance",
            "affected",
            "Affected Software / CloudVision eXchange version list",
            ranges=ranges,
            platforms=[appliance],
        )
        fixed_lists = [n for n in sections.get("Resolution", []) if n.tag == "ul"]
        reported_fixes(
            affected,
            one(fixed_lists, "CVX fixed-release list"),
            "Resolution / CVX server fixed builds",
        )
        affected["remediations"].append(
            {
                "category": "workaround",
                "details": "Use control-plane ACLs to restrict TCP ports 50003 and 50004 to known CVX clients; this is access restriction, not a software fix.",
                "availability": "partial_mitigation",
                "source_locator": "Mitigation / CP ACLs",
            }
        )
        hotfix = "https://www.arista.com/assets/data/SecurityAdvisories/SA52/SecurityAdvisory0052Hotfix.swix"
        if not any(
            urljoin(url, a.attrs.get("href", "")) == hotfix
            for n in sections["Resolution"]
            for a in n.find({"a"})
        ):
            raise ValueError("CVX publisher hotfix reference changed")
        affected["remediations"].append(
            {
                "category": "vendor_fix",
                "details": "Publisher-listed hotfix extension; persistent installation and agent restart require review. Binary availability and contents are not independently verified.",
                "url": hotfix,
                "release_type": "hotfix_extension",
                "availability": "vendor_reports_fixed",
                "source_locator": "Resolution / hotfix reference and installation qualifications",
            }
        )
    for label in exclusions:
        add(out, number, label, "unaffected", "Affected Platforms / explicit product exclusions")
    return out
