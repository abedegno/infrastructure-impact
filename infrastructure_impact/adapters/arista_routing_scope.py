"""Reviewed older IS-IS, VxLAN/VRF and VLAN routing applicability boundaries."""

import re
from urllib.parse import urlsplit

from .arista_legacy_scope import (
    AFFECTED,
    UNAFFECTED,
    article,
    children,
    labelled_list,
    leaf_items,
)
from .arista_scoped import leading_inline
from .common import assessment

ROUTES = {
    "54": ("11760-security-advisory-54", ["CVE-2020-15897"]),
    "55": ("11995-security-advisory-55", ["CVE-2020-26568"]),
    "56": ("11996-security-advisory-56", ["CVE-2020-15898"]),
}
CONTEXT = {
    "54": "IS-IS must be configured. Malformed link-state PDUs can restart different routing agents in Ribd and multi-agent modes; the affected protocol scope depends on that mode. Platform independence is restricted to the stated EOS versions and configuration.",
    "55": "Both non-default VRFs and VxLAN are required. The publisher distinguishes unintended UDP forwarding from configured inter-VRF routing. Resolution includes post-upgrade decapsulation changes and additional core-facing-interface checks for selected platforms; a listed fixed build does not remove those operational qualifications.",
    "56": "The 7170 and X-Series software branches are separate. X-Series applicability requires SVIs in a VRF with IPv4 or IPv6 routing disabled. For 7170, an SVI is sufficient and the routing-disabled check is not required. Explicit inter-VLAN routing is distinguished from the vulnerability. The common affected-model list is not crossjoined to either branch.",
}


def versions(node):
    values = leaf_items(node)
    if any(
        not re.fullmatch(
            r"(?:\d[\d.A-Za-z-]* and below releases? in the \d+\.\d+\.x train\.?|All releases in the \d+\.\d+\.x train\.?)",
            value,
        )
        for value in values
    ):
        raise ValueError("Unreviewed Arista routing version expression")
    return values


def add(out, number, product, status, locator, *, ranges=(), platforms=(), branch=None):
    claim = assessment(
        out["cves"][0], product, status, locator, [{"expression": v} for v in ranges]
    )
    claim["product_id"] = product + ":" + (branch or status)
    claim["platforms"] = list(platforms)
    claim["exposure"] = [
        {
            "category": "publisher_applicability",
            "details": CONTEXT[number],
            "source_scope": "advisory_context_requires_product_configuration_review",
            "source_locator": "Description; Symptoms; Vulnerability Assessment; Resolution",
        }
    ]
    out["assessments"].append(claim)
    return claim


def reported_fixes(claim, node, locator):
    """Keep normal/special publisher builds separate; never derive affected ranges."""

    def add_build(value, special=False):
        if not re.fullmatch(r"\d+(?:\.\d+)+[FM]", value):
            raise ValueError("Unreviewed Arista fixed-build expression")
        claim["remediations"].append(
            {
                "category": "vendor_fix",
                "details": value,
                "availability": "vendor_reports_fixed",
                "release_type": "special_release" if special else "listed_release",
                "source_locator": locator,
            }
        )

    if node.tag != "ul" or not children(node):
        raise ValueError("Arista fixed-build list missing")
    for item in children(node):
        if item.tag != "li":
            raise ValueError("Arista fixed-build list boundary changed")
        nested = list(item.find({"ul", "ol", "table"}))
        if nested:
            if (
                len(nested) != 1
                or nested[0].tag != "ul"
                or leading_inline(item) not in {"Special releases", "Special releases:"}
            ):
                raise ValueError("Arista special-release branch changed")
            for value in leaf_items(nested[0]):
                add_build(value, True)
        else:
            add_build(item.text())


def exclusions(out, number, node):
    items = children(node)
    marker = "Arista EOS-based products:"
    if number == "55":
        # In this reviewed page, model leaves follow a flat label within the
        # exclusion list. They must not become independent product families.
        labels = leaf_items(node)
        if labels.count(marker) != 1:
            raise ValueError("Arista flat EOS-model exclusion boundary changed")
        index = labels.index(marker)
        if not index or index == len(labels) - 1:
            raise ValueError("Empty Arista product/model exclusions")
        for label in labels[:index]:
            add(out, number, label, "unaffected", "Affected Platforms / product exclusions")
        add(
            out,
            number,
            "Arista EOS",
            "unaffected",
            "Affected Platforms / Arista EOS-based products / model exclusions",
            platforms=labels[index + 1 :],
        )
        return
    if not items or any(n.tag != "li" for n in items):
        raise ValueError("Arista routing exclusions changed")
    for item in items:
        nested = children(item, {"ul"})
        if nested:
            if number != "56" or len(nested) != 1 or children(item)[0].tag != "ul":
                raise ValueError("Unreviewed routing model exclusion")
            # Text preceding the local list supplies the family, not a model.
            if leading_inline(item) != marker:
                raise ValueError("Arista routing model-family label changed")
            add(
                out,
                number,
                "Arista EOS",
                "unaffected",
                "Affected Platforms / Arista EOS-based products / model exclusions",
                platforms=leaf_items(nested[0]),
            )
        else:
            label = item.text()
            if not label or list(item.find({"ul", "ol", "table"})):
                raise ValueError("Unreviewed nested routing exclusion")
            add(out, number, label, "unaffected", "Affected Platforms / product exclusions")


def routing_scope(raw, url, vendor):
    slug = urlsplit(url).path.rsplit("/", 1)[-1]
    number = next((n for n, value in ROUTES.items() if value[0] == slug), None)
    if number is None:
        raise ValueError("Unreviewed Arista routing advisory")
    _, out, sections = article(raw, url, vendor, number, routes=ROUTES)
    context = " ".join(n.text() for n in sections.get("Description", []))
    symptoms = " ".join(n.text() for n in sections.get("Symptoms", []))
    prerequisites = {
        "54": ("IS-IS configured", "Both modes are vulnerable"),
        "55": ("VxLAN Routing and VRFs", "both non-default VRFs and VxLAN configured"),
        "56": (
            "crossing VLAN boundaries",
            "The check for IP routing is not required for this platform",
        ),
    }
    if prerequisites[number][0] not in context or prerequisites[number][1] not in symptoms:
        raise ValueError("Arista routing configuration prerequisites changed")
    resolution_text = " ".join(n.text() for n in sections.get("Resolution", []))
    if not resolution_text:
        raise ValueError("Arista routing resolution context missing")
    if number == "55" and any(
        phrase not in resolution_text
        for phrase in (
            "Post upgrade impact on select platforms:",
            "core-facing interface",
            "revert the default behavior",
        )
    ):
        raise ValueError("Arista post-upgrade configuration qualifications changed")
    if number == "56" and any(
        phrase not in symptoms
        for phrase in (
            "systems configured with VLAN interfaces (SVIs) where the SVI is assigned to a VRF with ip routing disabled",
            "IPv4 or IPv6 routing has been disabled",
            "7170 systems are vulnerable if an SVI is configured in any VLAN",
        )
    ):
        raise ValueError("Arista branch-specific routing prerequisites changed")
    nodes = sections.get("Vulnerability Assessment", [])
    markers = [
        (i, n.text())
        for i, n in enumerate(nodes)
        if n.tag == "p" and n.text() in {"Affected Software", "Affected Platforms"}
    ]
    if len(markers) != 2 or [v for _, v in markers] != ["Affected Software", "Affected Platforms"]:
        raise ValueError("Arista routing software/platform boundaries changed")
    software = nodes[markers[0][0] + 1 : markers[1][0]]
    platform = nodes[markers[1][0] + 1 :]
    if number in {"54", "55"}:
        if len(software) != 1:
            raise ValueError("Arista EOS grouped software boundary changed")
        ranges = versions(labelled_list(software[0], "EOS", sibling=True))
        resolution = sections.get("Resolution", [])
        expected = {
            "54": "The vulnerability has been fixed in the following EOS versions:",
            "55": "The vulnerability is fixed in the following EOS versions:",
        }[number]
        if (
            len(resolution) < 3
            or resolution[1].tag != "p"
            or resolution[1].text() != expected
            or resolution[2].tag != "ul"
        ):
            raise ValueError("Arista EOS fixed-build source boundary changed")
        if number == "54" and len(resolution) != 3:
            raise ValueError("Arista platform-independent resolution scope changed")
        if number == "55" and (
            len(resolution) < 4
            or resolution[3].tag != "p"
            or resolution[3].text() != "Post upgrade impact on select platforms:"
        ):
            raise ValueError("Arista post-upgrade section boundary changed")
    elif len(software) != 2 or software[0].tag != "p" or software[0].text() != "EOS":
        raise ValueError("Arista platform-specific software boundary changed")
    if number == "54":
        if len(platform) != 1 or platform[0].tag != "ul":
            raise ValueError("Arista platform-independent scope changed")
        items = children(platform[0])
        scope = "This is a platform-independent vulnerability and affects all systems running EOS with the versions identified above."
        if (
            len(items) != 3
            or [n.tag for n in items] != ["li", "li", "ul"]
            or items[0].text() != scope
            or items[1].text() != UNAFFECTED
        ):
            raise ValueError("Arista platform-independent exclusion boundary changed")
        claim = add(
            out,
            number,
            "Arista EOS",
            "affected",
            "Affected Software / EOS; Affected Platforms / EOS version scope",
            ranges=ranges,
            platforms=[scope],
        )
        reported_fixes(claim, resolution[2], "Resolution / EOS fixed-build list")
        exclusions(out, number, items[2])
    else:
        if len(platform) != 2:
            raise ValueError("Arista routing platform-list boundary changed")
        models = leaf_items(labelled_list(platform[0], AFFECTED))
        excluded = labelled_list(platform[1], UNAFFECTED)
        if number == "55":
            claim = add(
                out,
                number,
                "Arista EOS",
                "affected",
                "Affected Software / EOS; Affected Platforms / explicit models",
                ranges=ranges,
                platforms=models,
            )
            reported_fixes(
                claim,
                resolution[2],
                "Resolution / EOS fixed-build list; post-upgrade configuration qualifications",
            )
        else:
            branches = children(software[1])
            if (
                software[1].tag != "ul"
                or len(branches) != 4
                or [n.tag for n in branches] != ["li", "ul", "li", "ul"]
                or branches[0].text() != "7170 platforms:"
                or branches[2].text() != "For all X-Series:"
            ):
                raise ValueError("Arista 7170/X-Series software branches changed")
            if "7170 series" not in models:
                raise ValueError("Arista 7170 platform scope missing")
            branch_claims = {}
            for label, node in (("7170 platforms", branches[1]), ("X-Series", branches[3])):
                claim = add(
                    out,
                    number,
                    "Arista EOS",
                    "affected",
                    "Affected Software / " + label,
                    ranges=versions(node),
                    platforms=[label],
                    branch=label + ":affected",
                )
                claim["exposure"].append(
                    {
                        "category": "publisher_common_affected_platform_list",
                        "details": "; ".join(models),
                        "source_scope": "common_advisory_list_not_crossjoined_to_version_branches",
                        "source_locator": "Affected Platforms / affected product list",
                    }
                )
                branch_claims[label] = claim
            resolution = sections.get("Resolution", [])
            if len(resolution) != 2 or resolution[0].tag != "p" or resolution[1].tag != "ul":
                raise ValueError("Arista model-specific resolution boundary changed")
            fixed = children(resolution[1])
            explicit = "Note that the 7170 platforms running versions in EOS release trains 4.22.x, 4.23.x and 4.24.x are not affected."
            if (
                len(fixed) != 2
                or any(n.tag != "li" for n in fixed)
                or not fixed[0].text().startswith("For X-Series platforms,")
                or not fixed[1].text().endswith(explicit)
                or list(fixed[1].find({"ul", "ol", "table"}))
            ):
                raise ValueError("Arista 7170 explicit unaffected train scope changed")
            x_fixes = children(fixed[0], {"ul"})
            if (
                len(x_fixes) != 1
                or leading_inline(fixed[0])
                != "For X-Series platforms, the vulnerability has been fixed in the following EOS versions:"
            ):
                raise ValueError("Arista X-Series fixed-build scope changed")
            reported_fixes(
                branch_claims["X-Series"], x_fixes[0], "Resolution / X-Series fixed-build list"
            )
            fixed_7170 = fixed[1].text().removesuffix(explicit).strip()
            if not re.fullmatch(
                r"For 7170 platforms, the vulnerability has been fixed in \d+(?:\.\d+)+[FM] and above releases in the \d+\.\d+\.x train\.",
                fixed_7170,
            ):
                raise ValueError("Arista 7170 fixed-train expression changed")
            branch_claims["7170 platforms"]["remediations"].append(
                {
                    "category": "vendor_fix",
                    "details": fixed_7170,
                    "availability": "vendor_reports_fixed",
                    "release_type": "publisher_version_range",
                    "source_locator": "Resolution / 7170 fixed release train",
                }
            )
            add(
                out,
                number,
                "Arista EOS",
                "unaffected",
                "Resolution / explicit 7170 unaffected release trains",
                ranges=[explicit],
                platforms=["7170 platforms"],
                branch="7170:explicit_unaffected_trains",
            )
        exclusions(out, number, excluded)
    out["warnings"].append(
        "Reviewed routing configuration and local version/model boundaries only. Fixed builds and special releases are publisher claims, not derived affected-version cutoffs or verified historical release availability. Post-upgrade configuration qualifications remain attached. Only the explicit 7170 unaffected-train statement supplies unaffected versions from Resolution. No complete inventory, automatic appliance version matching or absence of other affected products is inferred."
    )
    return out
