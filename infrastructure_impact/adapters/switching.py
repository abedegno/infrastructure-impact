"""Pure switching evidence extraction. No version comparison or model inference.

CSAF structural product names are matched literally. Reviewed HTML claims and
bundle membership require reviewed bytes or bounded publisher text, URL and locator.
The caller adds retained retrieval time and normalized revision, never this hook.
"""

import copy
import hashlib
import json
import re
from importlib.resources import files

from .cisco_models import STRUCTURAL_NAMES, note_bindings
from .common import HTML, availability, iso_date
from .reviewed_fixes import apply_csaf, arista_assessments, attach_links
from .standards import csaf_products

FAMILIES = {
    "cisco": (
        "cisco-iosxe",
        {"IOS XE", "IOS XE Software", "Cisco IOS XE", "Cisco IOS XE Software"},
    ),
    "aruba": ("aruba-aoscx", {"AOS-CX", "Aruba AOS-CX", "HPE Aruba Networking AOS-CX"}),
    "arista": ("arista-eos", {"EOS", "Arista EOS"}),
}
STATUSES = {
    "known_affected": "affected",
    "first_affected": "affected",
    "last_affected": "affected",
    "known_not_affected": "unaffected",
    "fixed": "fixed",
    "first_fixed": "fixed",
    "recommended": "recommended",
    "under_investigation": "investigating",
}


# Three reviewed associations, not a general train/range comparison. The complete
# source pin owns the mixed-product resolution and its lifecycle qualifications.
ARUBA_FIX_URL = "https://csaf.arubanetworking.hpe.com/2024/hpe_aruba_networking_-_hpesbnw04669.json"
ARUBA_FIX_SHA256 = "07e221b234c64d09ef18a2d291639e2bbca2d6f4bd511dbb6325fee088daa138"
ARUBA_FIX_RULES = {
    ">=10.14.0000|<=10.14.0006_aos-cx": ("10.14.0007_aos-cx", "10.14.0007", 3, 0),
    ">=10.13.0000|<=10.13.1030_aos-cx": ("10.13.1031_aos-cx", "10.13.1031", 4, 1),
    ">=10.10.0000|<=10.10.1130_aos-cx": ("10.10.1131_aos-cx", "10.10.1131", 7, 2),
}


def _aruba_status_locator(child):
    return (
        "/vulnerabilities/0/product_status; "
        f"/product_tree/branches/0/branches/0/branches/{child}/product"
    )


def aruba_reviewed_rule(claim):
    """Identify only a retained, reviewed affected product-section tuple."""
    rule = ARUBA_FIX_RULES.get(claim["product_id"])
    if (
        rule is not None
        and claim["vendor"] == "aruba"
        and claim["advisory_id"] == "HPESBNW04669"
        and claim["cve_id"] == "CVE-2024-6387"
        and claim["family"] == "aruba-aoscx"
        and claim["product"] == "AOS-CX"
        and claim["status"] == "affected"
        and claim["scope"] == "cve_specific"
        and claim["source"]["source_url"] == ARUBA_FIX_URL
        and claim["source"]["source_sha256"] == ARUBA_FIX_SHA256
        and claim["source"]["source_locator"] == _aruba_status_locator(rule[2])
        and claim["version_expressions"]
        == ["vers:semver/" + claim["product_id"].removesuffix("_aos-cx")]
    ):
        return rule
    return None


def aruba_reviewed_fixed(claim, fixed, rule):
    """Require the exact retained fixed sibling, including literal release scope."""
    return (
        all(
            fixed[k] == claim[k]
            for k in (
                "vendor",
                "advisory_id",
                "revision",
                "publisher",
                "cve_id",
                "family",
                "product",
                "scope",
            )
        )
        and fixed["status"] == "fixed"
        and fixed["product_id"] == rule[0]
        and fixed["source"]["source_locator"] == _aruba_status_locator(rule[3])
        and all(
            fixed["source"][k] == claim["source"][k]
            for k in ("source_url", "source_sha256", "retrieved_at")
        )
    )


def _aruba_fix_links(data, claims):
    parent = data.get("product_tree", {}).get("branches", [])
    if not parent or not parent[0].get("branches"):
        return
    parent = parent[0]["branches"][0]
    if parent.get("category") != "product_name" or parent.get("name") != "AOS-CX":
        return
    for claim in claims:
        rule = aruba_reviewed_rule(claim)
        if rule is None:
            continue
        matching = [c for c in claims if aruba_reviewed_fixed(claim, c, rule)]
        if len(matching) != 1 or matching[0]["version_expressions"] != [rule[1]]:
            continue
        fixed = matching[0]
        remediations = [
            r
            for r in fixed["remediations"]
            if r["category"] == "vendor_fix"
            and r["availability"] == "vendor_reports_fixed"
            and r["product_ids"] == [rule[0]]
            and r["source"]["source_locator"] == "/vulnerabilities/0/remediations/0"
            and all(
                r["source"][k] == fixed["source"][k]
                for k in ("source_url", "source_sha256", "retrieved_at")
            )
        ]
        if len(remediations) != 1 or "evidence_text_truncated" in fixed["issues"]:
            continue
        bound = copy.deepcopy(remediations[0])
        bound["product_ids"] = []  # Preserve the publisher's fixed-ID scope on its sibling.
        bound["version_expressions"] = fixed["version_expressions"][:]
        bound["scope_binding"] = dict(
            basis="reviewed_source_sections",
            cve_id=claim["cve_id"],
            source=claim["source"].copy(),
            fixed_product="AOS-CX",
            fixed_product_id=rule[0],
            fixed_source=fixed["source"].copy(),
        )
        claim["remediations"].append(bound)


def _aruba_direct_targets(data, claims, url, digest):
    """Project three literal upgrades from one already affected-owned section.

    This is not a sibling linkage or first-fixed derivation. Preserve the original
    remediation scope and leave the source's cross-train affected range unresolved.
    """
    source_url = "https://csaf.arubanetworking.hpe.com/2022/hpe_aruba_networking_-_2022-004.json"
    source_sha = "6b6ebf1734613aa7dcaeef1946d917dd0686ce4d49183ba6bf0818e7ac182134"
    details_sha = "ba19a6268bf16bda6b8f6eddfe914175a94d34b9fd56e772c6bdf23fa651d55b"
    pairs = {
        ">=10.09.0000|<=10.09.0002": ("10.09.0010", 4),
        ">=10.08.0000|<=10.08.0130": ("10.08.1040", 5),
        ">=10.07.0000|<=10.07.0050": ("10.07.0061", 6),
    }
    if url != source_url or digest != source_sha:
        return
    try:
        vuln = data["vulnerabilities"][15]
        original = vuln["remediations"][0]
        parent = data["product_tree"]["branches"][0]["branches"][0]
        if (
            data["document"]["tracking"]["id"] != "ARUBA-PSA-2022-004"
            or vuln["cve"] != "CVE-2021-41002"
            or len(vuln["remediations"]) != 1
            or parent["category"] != "product_name"
            or parent["name"] != "AOS-CX"
            or original["category"] != "vendor_fix"
            or original["date"] != "2022-04-06T17:00:00.000Z"
            or original["product_ids"] != [*pairs, ">=10.00.0000|<=10.06.0170"]
            or hashlib.sha256(original["details"].encode("utf-8")).hexdigest() != details_sha
        ):
            return
    except (KeyError, IndexError, TypeError, AttributeError):
        return
    for claim in claims:
        rule = pairs.get(claim["product_id"])
        if (
            rule is None
            or claim["vendor"] != "aruba"
            or claim["advisory_id"] != "ARUBA-PSA-2022-004"
            or claim["cve_id"] != "CVE-2021-41002"
            or claim["family"] != "aruba-aoscx"
            or claim["product"] != "AOS-CX"
            or claim["status"] != "affected"
            or claim["scope"] != "cve_specific"
            or claim["version_expressions"] != ["vers:semver/" + claim["product_id"]]
            or claim["source"]
            != _source(
                url,
                digest,
                "/vulnerabilities/15/product_status; "
                f"/product_tree/branches/0/branches/0/branches/{rule[1]}/product",
            )
            or "evidence_text_truncated" in claim["issues"]
            or len(claim["remediations"]) != 1
        ):
            continue
        rem = claim["remediations"][0]
        if (
            rem["category"] == "vendor_fix"
            and rem["availability"] == "vendor_reports_fixed"
            and rem["product_ids"] == [claim["product_id"]]
            and rem["version_expressions"] == []
            and rem["details"] == original["details"]
            and rem["availability_date"] == original["date"]
            and rem["source"] == _source(url, digest, "/vulnerabilities/15/remediations/0")
            and "scope_binding" not in rem
        ):
            rem["version_expressions"] = [rule[0]]


def bindings_resource():
    return json.loads(
        files("infrastructure_impact")
        .joinpath("resources/switching-source-bindings.json")
        .read_text()
    )


def _source(url, digest, locator):
    return dict(source_url=url, source_sha256=digest, retrieved_at=None, source_locator=locator)


def _claim(vendor, document, source, publisher, initial, updated):
    return dict(
        vendor=vendor,
        advisory_id=document["advisory_id"],
        cve_id=None,
        product_id=None,
        product=None,
        revision=None,
        source=source,
        publisher=publisher,
        initial_published_at=initial,
        updated_at=updated,
        family=None,
        named_platforms=[],
        platform_bindings=[],
        status="unknown",
        scope="unresolved",
        scope_level="os_family",
        version_expressions=[],
        conditions=[],
        remediations=[],
        bundle=None,
        scores=[],
        issues=[],
    )


def _bounded(text, issues):
    if not isinstance(text, str) or not text.strip():
        return None
    if len(text) > 4000:
        issues.append("evidence_text_truncated")
    return text[:4000]


def _models(vendor):
    study = json.loads(
        files("infrastructure_impact").joinpath("resources/switching-study.json").read_text()
    )
    result = {}
    for target in study["targets"]:
        if target["vendor"] != vendor:
            continue
        for alias in target["aliases"]:
            result[alias["literal"]] = alias["model"]
        # These are literal structural names, not prose/prefix searches. Numeric
        # IDs alone (750, 9300, etc.) are never interpreted as model evidence.
        for model in target["models"]:
            if vendor == "aruba":
                result["CX " + model] = model
            elif vendor == "arista":
                result["Arista " + model] = model
            elif vendor == "cisco":
                result["Cisco Catalyst " + model] = model
                result["Catalyst " + model] = model
    if vendor == "cisco":
        result.update(STRUCTURAL_NAMES)
    return result


def _availability(details, category, published_date, as_of):
    if not details:
        return "unknown"
    state = availability(details, category, published_date, as_of=as_of)
    text = " ".join(details.split())
    ambiguous = "?" in text or re.search(
        r"\b(?:no|not|never|neither|without|may|might|could|should|possibly|perhaps|potentially|whether)\b|n['’]t\b",
        text,
        re.I,
    )
    if state != "vendor_reports_fixed":
        return "unknown" if state == "planned" and ambiguous else state
    # Handle explicit negatives before any affirmative language. The shared
    # classifier already excludes future dates, partial fixes and workarounds.
    if re.search(
        r"\bunavailable\b|\b(?:not|never) (?:(?:currently|yet|now|generally|publicly|presently|been) )*"
        r"(?:available|released|fixed|resolved)\b|"
        r"\bno (?:(?:fixed|software|security|vendor|official|released|public|available) )*"
        r"(?:fix(?:es)?|patch(?:es)?|updates?|releases?|versions?)\b",
        text,
        re.I,
    ):
        return "unavailable"
    # Unsupported qualifications and questions stay inspectable, but establish
    # neither an available fix nor an affirmative plan.
    if ambiguous:
        return "unknown"
    if re.search(
        r"\b(?:planned|expected|anticipated|pending|forthcoming)\b|\bplans? to\b", text, re.I
    ):
        return "planned"
    # Reviewed CSAF upgrade wording is affirmative only with an explicit numeric
    # AOS-CX release list. Existing category, date, negation and future guards
    # above still apply; product/CVE attribution is handled by the CSAF IDs.
    if re.search(
        r"^The vulnerabilities contained in this advisory can be addressed by patching or "
        r"upgrading to one of the versions listed below AOS-CX [0-9]+\.[0-9]+\.xxxx: "
        r"[0-9]+\.[0-9]+\.[0-9]+ and above\b",
        text,
    ):
        return "vendor_reports_fixed"
    subject = r"(?:fix(?:es)?|patch(?:es)?|updates?|releases?|versions?)"
    positive = (
        r"(?:^|[.!] )(?:(?:a|an|the|these|our) )?(?:(?:fixed|software|firmware|security) )?"
        + subject
        + r" (?:is|are|was|were|has been|have been) (?:(?:now|currently|already) )*(?:available|released)\b|"
        r"(?:^|[.!] )[A-Za-z][A-Za-z0-9 .-]{0,80} (?:has|have) released "
        r"(?:(?:a|an|the|new) )?(?:(?:software|firmware|security) )?" + subject + r"\b|"
        r"(?:^|[.!] )(?:(?:the|this|these) )?(?:issue|vulnerability|vulnerabilities) "
        r"(?:is|are|has been|have been) (?:fixed|resolved)\b|"
        r"(?:^|[.!] )(?:software|firmware|fixes|patches|updates|releases|versions) "
        r"[^.!?]*\bcan be downloaded\b"
    )
    return "vendor_reports_fixed" if re.search(positive, text, re.I) else "unknown"


def _aruba_local_resolution(claim, remediation, ids, as_of):
    """A numeric fixed product must occur in its own publisher resolution section.

    Global lifecycle prose is context, not availability for every listed product.
    This does not bind a sibling affected range to the fixed product.
    """
    if (
        claim["vendor"] != "aruba"
        or claim["family"] != "aruba-aoscx"
        or claim["status"] != "fixed"
        or claim["product_id"] not in ids
        or remediation["category"] != "vendor_fix"
    ):
        return None
    details = remediation["details"] or ""
    sections = re.findall(r"(?m)^- ArubaOS-CX Switches\s*\n((?:[ \t]+-[^\n]+\n?)+)", details)
    if len(sections) != 1:
        return None
    releases = []
    for line in sections[0].splitlines():
        match = re.fullmatch(r"\s*- ([0-9]+\.[0-9]+\.[0-9]+) and above\s*", line)
        if not match:
            return None
        releases.append(match[1])
    resolution = (
        "Software versions with resolution/fixes for the vulnerabilities "
        "covered above, can be downloaded from the HPE Networking Support Portal."
    )
    paragraphs = [" ".join(p.split()) for p in re.split(r"\n[ \t]*\n", details)]
    numeric = [
        v for v in claim["version_expressions"] if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", v)
    ]
    if not numeric or not all(v in releases for v in numeric) or resolution not in paragraphs:
        return None
    # This repair supports the reviewed source structure only. Extra paragraphs
    # may qualify this release, even when their product scope is unspecified.
    # Keep their negative/planned classification, otherwise fail closed. Never
    # reduce arbitrary prose to the affirmative download paragraph alone.
    context = {
        "HPE Aruba Networking",
        resolution,
        "https://networkingsupport.hpe.com/home/",
        "HPE Aruba Networking does not evaluate or patch product branches "
        "that have reached their End of Maintenance (EoM) milestone.",
        "For more information about HPE Aruba Networking products End of "
        "Support policy visit: https://networkingsupport.hpe.com/end-of-life",
    }
    for paragraph in re.split(r"\n[ \t]*\n", details):
        normalized = " ".join(paragraph.split())
        if normalized in context:
            continue
        if re.fullmatch(r"- ArubaOS-CX Switches\s*\n(?:[ \t]+-[^\n]+\n?)+", paragraph):
            continue
        # Both heading and body must match the reviewed foreign product shape.
        # Arbitrary bullets can contain qualifications for this AOS-CX release.
        foreign_shapes = (
            r"- Aruba Fabric Composer\n(?:[ \t]+- [0-9]+\.[0-9]+\.[0-9]+ and above\n?)+",
            r"- EdgeConnect SD-WAN Orchestrator\n[ \t]+-Detailed information on the "
            r"resolution of CVE-2024-6387 can be found at "
            r"https://www\.arubanetworks\.com/techdocs/sdwan-PDFs/docs/advisories/"
            r"orch_resolution_to_cve-2024-6387_latest\.pdf",
            r"-  HPE Networking Instant On\n[ \t]+- Firmware version [0-9]+\.[0-9]+\.[0-9]+ and higher"
            r"\n[ \t]+- No direct customer action is necessary other than to ensure affected "
            r"devices \(APs and Switches in cloud mode\) remain connected to the internet "
            r"to receive automatic updates\.",
        )
        if any(re.fullmatch(shape, paragraph) for shape in foreign_shapes):
            continue
        state = remediation["availability"]
        return state if state in {"unavailable", "partial_mitigation", "planned"} else "unknown"
    # Reuse category/date/future guards against only the source-owned availability
    # statement. Other product sections and EoM prose cannot authorize this claim.
    return _availability(resolution, "vendor_fix", remediation["availability_date"], as_of)


def _csaf(raw, url, vendor, document, digest):
    data = json.loads(raw)
    tracking = data["document"].get("tracking", {})
    publisher = {
        k: tracking.get(s) for k, s in [("id", "id"), ("sequence", "version"), ("status", "status")]
    }
    products = csaf_products(data.get("product_tree", {}))
    groups = {
        g["group_id"]: g.get("product_ids", [])
        for g in data.get("product_tree", {}).get("product_groups", [])
    }
    claims = []
    models = _models(vendor)
    for vi, vuln in enumerate(data.get("vulnerabilities", [])):
        by_pid = {}
        for status, ids in vuln.get("product_status", {}).items():
            for pid in ids:
                by_pid.setdefault(pid, []).append(status)
        if not by_pid:
            claim = _claim(
                vendor,
                document,
                _source(url, digest, f"/vulnerabilities/{vi}"),
                publisher,
                tracking.get("initial_release_date"),
                tracking.get("current_release_date"),
            )
            claim["cve_id"] = vuln.get("cve")
            claim["issues"] = ["product_scope_unresolved"]
            claims.append(claim)
            continue
        # Resolve each publisher scope once. Membership is checked before any
        # claim-local projection; an unresolved group still cannot authorize a fix.
        remediations = []
        for ri, rem in enumerate(vuln.get("remediations", [])):
            ids = rem.get("product_ids", []) + [
                p for group in rem.get("group_ids", []) for p in groups.get(group, [])
            ]
            try:
                ids = set(ids)
            except TypeError:
                # Keep malformed scopes intact for the original membership check.
                # Only an applicable, resolved scope reached set conversion before.
                pass
            unresolved = any(g not in groups for g in rem.get("group_ids", []))
            issues = []
            details = _bounded(rem.get("details"), issues)
            prepared = dict(
                publisher_id=None,
                category=rem.get("category", "unknown"),
                details=details,
                version_expressions=[],
                published_availability=details,
                availability=_availability(
                    details,
                    rem.get("category", "unknown"),
                    rem.get("date"),
                    as_of=tracking.get("current_release_date")
                    or tracking.get("initial_release_date"),
                )
                if details
                else "unknown",
                availability_date=rem.get("date"),
                source=_source(url, digest, f"/vulnerabilities/{vi}/remediations/{ri}"),
            )
            remediations.append((ids, unresolved, prepared, issues))
        for pid, statuses in by_pid.items():
            product = products.get(
                pid,
                {
                    "name": pid,
                    "paths": [],
                    "locator": "/product_tree",
                    "issues": ["product_id_unresolved"],
                },
            )
            at = f"/vulnerabilities/{vi}/product_status; {product['locator']}"
            claim = _claim(
                vendor,
                document,
                _source(url, digest, at),
                publisher,
                tracking.get("initial_release_date"),
                tracking.get("current_release_date"),
            )
            claim.update(
                cve_id=vuln.get("cve"),
                product_id=pid,
                product=product["name"],
                scope="cve_specific" if vuln.get("cve") else "unresolved",
            )
            claim["issues"].extend(product["issues"])
            values = {STATUSES[s] for s in statuses if s in STATUSES}
            claim["status"] = (
                next(iter(values)) if len(values) == 1 else "conflicting" if values else "unknown"
            )
            if any(status not in STATUSES for status in statuses):
                claim["status"] = "unknown"
                claim["issues"].append("product_status_unsupported")
            fields = [field for path in product["paths"] for field in path]
            if not product["issues"]:
                fields.append(("product_name", product["name"], product["locator"]))
            family, names = FAMILIES[vendor]
            if any(name in names for _, name, _ in fields):
                claim["family"] = family
            for category, name, locator in fields:
                if category in {
                    "product_version",
                    "product_version_range",
                    "service_pack",
                    "patch_level",
                }:
                    claim["version_expressions"].append(name)
                if (
                    category in {"product_name", "product_family"}
                    and name in models
                    and claim["family"]
                ):
                    claim["named_platforms"].append(name)
                    binding = dict(
                        platform=name,
                        model=models[name],
                        basis="publisher_explicit",
                        source=_source(url, digest, locator),
                    )
                    if binding not in claim["platform_bindings"]:
                        claim["platform_bindings"].append(binding)
            if vendor == "cisco" and not product["issues"] and not claim["platform_bindings"]:
                owned = note_bindings(
                    data,
                    url,
                    digest,
                    claim["cve_id"],
                    claim["status"],
                    claim["family"],
                    next(
                        (name for _, name, _ in fields if name in FAMILIES["cisco"][1]),
                        claim["product"],
                    ),
                )
                claim["platform_bindings"].extend(owned["bindings"])
                claim["named_platforms"].extend(b["platform"] for b in owned["bindings"])
                claim["conditions"].extend(owned["conditions"])
                claim["issues"].extend(owned["diagnostics"])
            if claim["platform_bindings"]:
                claim["scope_level"] = "model_qualified"
            # Unreviewed notes remain literal CVE context. Scoped threats retain only their own product set.
            for note in vuln.get("notes", []):
                text = _bounded(note.get("text"), claim["issues"])
                if text:
                    claim["conditions"].append(text)
            for threat in vuln.get("threats", []):
                group_ids = threat.get("group_ids", [])
                if any(group not in groups for group in group_ids):
                    claim["issues"].append("threat_product_scope_unresolved")
                    continue
                ids = threat.get("product_ids", []) + [
                    p for group in group_ids for p in groups[group]
                ]
                declared_scope = "product_ids" in threat or "group_ids" in threat
                if (not declared_scope or pid in ids) and threat.get("details"):
                    text = _bounded(threat["details"], claim["issues"])
                    if text:
                        claim["conditions"].append(text)
            for ids, unresolved, prepared, issues in remediations:
                if ids and pid not in ids:
                    continue
                if unresolved:
                    claim["issues"].append("remediation_product_scope_unresolved")
                    continue
                if isinstance(ids, list):
                    # Preserve the failure boundary for an applicable malformed scope.
                    ids = set(ids)
                claim["issues"].extend(issues)
                local_availability = None
                if "evidence_text_truncated" not in issues:
                    local_availability = _aruba_local_resolution(
                        claim,
                        prepared,
                        ids,
                        tracking.get("current_release_date")
                        or tracking.get("initial_release_date"),
                    )
                claim["remediations"].append(
                    {
                        **prepared,
                        "availability": local_availability or prepared["availability"],
                        "product_ids": [pid] if ids and pid is not None else sorted(ids),
                        "version_expressions": [],
                        "source": dict(prepared["source"]),
                    }
                )
            claims.append(claim)
    _aruba_fix_links(data, claims)
    reviewed_issues = apply_csaf(
        data,
        claims,
        url,
        digest,
        tracking.get("current_release_date") or tracking.get("initial_release_date"),
    )
    _aruba_direct_targets(data, claims, url, digest)
    return dict(
        schema_version=1,
        claims=claims,
        bundles=[],
        issues=reviewed_issues if claims else ["product_scope_unresolved"],
    )


# Finite source-section associations; these are not family/version joins. Pins
# cover normalized publisher text inside owned boundaries, not site wrappers.
ARISTA_FIX_RULES = {
    "23115-security-advisory-0128": (
        "CVE-2025-8872",
        "EOS (source platform scope applies)",
        "Affected Software / EOS (source platform scope applies)",
        "Resolution / CVE-2025-8872 / EOS fixed-release list",
    ),
    "24847-security-advisory-0201": (
        "CVE-2026-111943",
        "EOS (source platform scope applies)",
        "Affected Software / EOS (source platform scope applies)",
        "Resolution / EOS",
    ),
    "15438-security-advisory-0075": (
        "CVE-2022-0778",
        "Arista EOS",
        "Vulnerability Assessment / products affected by CVE-2022-0778 / Arista EOS-based products",
        "Resolution / Arista EOS-based products / first fixed-version list",
    ),
}


ARISTA_FIXED_VERSIONS = {
    "23115-security-advisory-0128": [
        "4.34.2F and later releases in the 4.34.x train",
        "4.33.5M and later releases in the 4.33.x train",
        "4.32.8M and later releases in the 4.32.x train",
        "4.31.9M and later releases in the 4.31.x train",
    ],
    "24847-security-advisory-0201": [
        "4.37.0F and later releases in the 4.37.x train",
        "4.36.3.2M and later releases in the 4.36.x train",
        "4.35.7.2M and later releases in the 4.35.x train",
        "4.34.9.2M and later releases in the 4.34.x train",
        "4.33.11.2M and later releases in the 4.33.x train",
    ],
    "15438-security-advisory-0075": [
        "4.27.4 and later releases in the 4.27.x train",
        "4.26.6 and later releases in the 4.26.x train",
        "4.25.9 and later releases in the 4.25.x train",
        "4.24.10 and later release in the 4.24.x train",
        "4.23.12 and later release in the 4.23.x train",
    ],
}


def _arista_events(node):
    # Text events avoid inheriting later MOS prose through malformed nested ULs.
    yield node
    for child in node.children:
        if isinstance(child, str):
            yield child
        else:
            yield from _arista_events(child)


def _arista_section(events, title, tags, start=0, end=None):
    end = len(events) if end is None else end
    matches = [
        i
        for i in range(start, end)
        if not isinstance(events[i], str) and events[i].tag in tags and events[i].text() == title
    ]
    if len(matches) != 1:
        raise ValueError("Reviewed Arista section boundary changed")
    first = matches[0]
    last = next(
        (
            i
            for i in range(first + 1, end)
            if not isinstance(events[i], str)
            and events[i].tag in {"h2", "h3", "h4"}
            and (events[i].tag <= events[first].tag or events[i].text() == "For More Information")
        ),
        end,
    )
    return first, last


def _arista_text(events, start, end):
    return " ".join(" ".join(n for n in events[start:end] if isinstance(n, str)).split())


def _arista_pin(events, start, end, expected):
    if hashlib.sha256(_arista_text(events, start, end).encode()).hexdigest() != expected:
        raise ValueError("Reviewed Arista EOS resolution changed; source review required")


def _arista_fixes(tree, slug, parsed):
    """Read only the three reviewed EOS lists; hotfix/agent/MOS stay separate."""
    from .common import assessment, cves

    rule = ARISTA_FIX_RULES[slug]
    cid = rule[0]
    events = list(_arista_events(tree))
    first, last = _arista_section(events, "Resolution", {"h2", "h3"})
    last = next(
        (
            i
            for i in range(first + 1, last)
            if not isinstance(events[i], str)
            and events[i].tag == "table"
            and any(
                [c.text() for c in row.find({"th", "td"})] == ["Revision", "Date", "Changes"]
                for row in events[i].find({"tr"})
            )
        ),
        last,
    )
    text = _arista_text(events, first, last)
    # Preserve existing affected-only captures lacking a reviewed fix statement.
    # Any release list or fix language must pass review, even negated/planned.
    if (
        slug != "15438-security-advisory-0075"
        and not any(
            not isinstance(n, str) and n.tag in {"ul", "ol", "h3", "h4"}
            for n in events[first + 1 : last]
        )
        and not re.search(r"\b(fix(?:ed|es)?|release|CVE-[0-9]|[0-9]+\.[0-9]+)\b", text, re.I)
    ):
        return []
    metadata = [
        n for n in tree.find({"p"}) if n.text().startswith("The CVE-ID tracking this issue:")
    ]
    if slug == "15438-security-advisory-0075":
        metadata = [n for n in tree.find({"h4"}) if n.text() == cid]
    assessment_start, _ = _arista_section(events, "Vulnerability Assessment", {"h2", "h3"})
    if (
        len(metadata) != 1
        or cves(metadata[0].text()) != [cid]
        or parsed["cves"] != [cid]
        or events.index(metadata[0]) >= assessment_start
    ):
        raise ValueError("Reviewed Arista single-CVE metadata changed")
    if slug == "23115-security-advisory-0128":
        _arista_pin(
            events, first, last, "3914ce1cc07a3021d01b264a002115efcee80d505131b436dff8fcb0865a66a3"
        )
        if [a["product"] for a in parsed["assessments"]] != [rule[1]]:
            raise ValueError("Reviewed Arista EOS-only ownership changed")
        statement = cid + " has been fixed in the following releases:"
        owned_start, owned_end = first, last
    else:
        title = "EOS" if slug == "24847-security-advisory-0201" else "Arista EOS-based products"
        owned_start, owned_end = _arista_section(
            events,
            title,
            {"h3"} if slug == "24847-security-advisory-0201" else {"h4"},
            first + 1,
            last,
        )
        prelude, owned = (
            (
                "29ca139b6332ca4d4a4c4677b7dc687edfd90694235d0708970a2a98201d7c0b",
                "6d685252c621ee1528e97b1903d5fa30334f9c6875c25be4d515751dac27e16f",
            )
            if slug == "24847-security-advisory-0201"
            else (
                "52e4de753d1a96febf448ec325e1c5184c86b2157a9fe57aeafa9b3b2bd0da92",
                "2b1577094a2510008bce6d865044e8c088fb5519dbbf33cd85ce7f5dde56736c",
            )
        )
        _arista_pin(events, first, owned_start, prelude)
        _arista_pin(events, owned_start, owned_end, owned)
        expected_boundary = (
            "Streaming Telemetry Agent (TerminAttr)"
            if slug == "24847-security-advisory-0201"
            else "Arista 7130 Systems running MOS"
        )
        if owned_end == last or events[owned_end].text() != expected_boundary:
            raise ValueError("Reviewed Arista EOS product boundary changed")
        statement = (
            "The issue is fixed in the following product releases:"
            if slug == "24847-security-advisory-0201"
            else "This vulnerability has been fixed in the following EOS version:"
        )
    lists = [n for n in events[owned_start:owned_end] if not isinstance(n, str) and n.tag == "ul"]
    if not lists:
        raise ValueError("Reviewed Arista EOS fixed list missing")
    versions = [n.text() for n in lists[0].children if not isinstance(n, str) and n.tag == "li"]
    if versions != ARISTA_FIXED_VERSIONS[slug]:
        raise ValueError("Reviewed Arista EOS fixed list structure changed")
    fixed = assessment(
        cid,
        "Arista EOS",
        "fixed",
        rule[3],
        [dict(expression=v) for v in versions],
        [
            dict(
                category="vendor_fix",
                availability="vendor_reports_fixed",
                details=statement,
                source_locator=rule[3],
            )
        ],
    )
    return [fixed]


def _arista_legacy_eos(tree, parsed):
    """0075: the EOS nested affected list owns only its literal versions."""
    from .common import Node, assessment, leading_inline

    rule = ARISTA_FIX_RULES["15438-security-advisory-0075"]
    events = list(_arista_events(tree))
    first, last = _arista_section(events, "Vulnerability Assessment", {"h3"})
    first, last = _arista_section(
        events, "The following products are affected by CVE-2022-0778:", {"h4"}, first + 1, last
    )
    lists = [n for n in events[first:last] if not isinstance(n, str) and n.tag == "ul"]
    if not lists:
        raise ValueError("Reviewed Arista EOS affected ownership changed")
    owned = [
        n
        for n in lists[0].children
        if isinstance(n, Node)
        and n.tag == "li"
        and leading_inline(n) == "Arista EOS-based products"
    ]
    if len(owned) != 1:
        raise ValueError("Reviewed Arista EOS affected ownership changed")
    branches = list(owned[0].find({"ul"}))
    if len(branches) != 1:
        raise ValueError("Reviewed Arista EOS affected version boundary changed")
    versions = [n.text() for n in branches[0].children if isinstance(n, Node) and n.tag == "li"]
    if not versions or any(
        not re.fullmatch(
            r"4\.[0-9]+(?:\.[0-9]+)?(?: and below releases? in the 4\.[0-9]+\.x train|\.x train)", v
        )
        for v in versions
    ):
        raise ValueError("Reviewed Arista EOS affected expressions changed")
    parsed["assessments"] = [
        assessment(
            rule[0], "Arista EOS", "affected", rule[2], [dict(expression=v) for v in versions]
        )
    ]


def arista_reviewed_rule(claim):
    """Return the finite identity/product/locator rule, including strict SA0100."""
    slug, cid = claim["advisory_id"], claim["cve_id"]
    if slug == "19904-security-advisory-0100" and cid in {"CVE-2024-6387", "CVE-2024-6409"}:
        return (
            cid,
            "EOS release (source platform scope applies)",
            "Affected Software / EOS release (source platform scope applies)",
            "Resolution / " + cid + " / Arista EOS-based products",
        )
    rule = ARISTA_FIX_RULES.get(slug)
    return rule if rule and rule[0] == cid else None


def _arista_reviewed(raw, url, document, digest):
    """Bridge only reviewed routes, re-reading bytes through the core adapters.

    Shared platform prose is never attached to another assessment. Slash labels
    remain literal unresolved platforms, even when they contain a target token.
    """
    from ..plugins.arista import parse

    routes = {
        "24005-security-advisory-0137": "Arista reviewed SA-0137 tunnel applicability HTML",
        "25048-security-advisory-0226": "Arista reviewed hardware notice HTML",
        "19862-security-advisory-0099": "Arista reviewed reconciliation software HTML",
        "19917-security-advisory-0103": "Arista reviewed reconciliation software HTML",
        "24853-security-advisory-0202": "Arista reviewed current applicability HTML",
        "25023-security-advisory-0203": "Arista reviewed current applicability HTML",
        "19905-security-advisory-0101": "Arista reviewed applicability boundaries HTML",
        "19222-security-advisory-0095": "Arista reviewed applicability boundaries HTML",
        "19904-security-advisory-0100": "Arista affected software HTML",
        "23115-security-advisory-0128": "Arista affected software HTML",
        "15438-security-advisory-0075": "Vendor HTML",
        "24847-security-advisory-0201": "Arista affected software HTML",
        "11996-security-advisory-56": "Arista reviewed older product/model HTML",
        "12135-security-advisory-61": "Arista reviewed older product/model HTML",
        "12166-security-advisory-62": "Arista reviewed older product/model HTML",
        "19221-security-advisory-0094": "Arista reviewed applicability boundaries HTML",
        "24074-security-advisory-0140": "Arista reviewed sibling software sections HTML",
        "24515-security-advisory-0147": "Arista CVE-grouped software HTML",
    }
    slug = document["advisory_id"]
    if (
        slug not in routes
        or document.get("source_format") != routes[slug]
        or url != "https://www.arista.com/en/support/advisories-notices/security-advisory/" + slug
    ):
        return None
    parsed = parse(raw, url, "arista")
    if parsed["source_format"] != routes[slug] or parsed["advisory_id"] != slug:
        raise ValueError("Reviewed Arista identity changed")
    tree = HTML(raw).root
    labels = [
        " ".join(" ".join(c for c in n.children if isinstance(c, str)).split())
        for n in tree.find({"h2"})
        if n.text().startswith("Security Advisory ")
    ]
    labels = [label for label in labels if re.fullmatch(r"Security Advisory [0-9]+", label)]
    tables = [
        t
        for t in tree.find({"table"})
        if any(
            [c.text() for c in row.find({"th", "td"})] == ["Revision", "Date", "Changes"]
            for row in t.find({"tr"})
        )
    ]
    if len(labels) != 1 or len(tables) != 1:
        raise ValueError("Reviewed Arista publisher identity/history changed")
    history = [[c.text() for c in row.find({"th", "td"})] for row in tables[0].find({"tr"})][1:]
    if not history or any(len(row) != 3 or not row[0] for row in history):
        raise ValueError("Reviewed Arista revision rows changed")
    history_row = len(history)
    if slug == "15438-security-advisory-0075":
        history = list(reversed(history)) if len(history) > 1 else history
        history_row = 1
    dates = [iso_date(row[1]) for row in history]
    if dates != sorted(dates) or dates[0] != parsed["published_at"]:
        raise ValueError("Reviewed Arista revision chronology changed")
    software_cves = {
        "23115-security-advisory-0128": "CVE-2025-8872",
        "24847-security-advisory-0201": "CVE-2026-111943",
    }
    if slug in software_cves:
        cid = software_cves[slug]
        headings = [n.text() for n in tree.find({"h2", "h3"})]
        expected_label = "Security Advisory " + slug.rsplit("-", 1)[-1]
        products = ["EOS (source platform scope applies)"]
        if slug == "24847-security-advisory-0201":
            products.append(
                "Streaming Telemetry Agent (TerminAttr) (source platform scope applies)"
            )
        owned = [a for a in parsed["assessments"] if a["product"] in products]
        if (
            labels != [expected_label]
            or parsed["cves"] != [cid]
            or any(headings.count(h) != 1 for h in ("Affected Software", "Affected Platforms"))
            or headings.index("Affected Software") >= headings.index("Affected Platforms")
            or [a["product"] for a in owned] != products
            or (slug == "23115-security-advisory-0128" and len(owned) != len(parsed["assessments"]))
            or any(
                a["cve_id"] != cid or a["scope"] != "cve_specific" or a["status"] != "affected"
                for a in parsed["assessments"]
            )
        ):
            raise ValueError("Reviewed Arista software ownership changed")
        # Only the reviewed software branches participate in this narrow bridge.
        parsed["assessments"] = owned
    if slug == "15438-security-advisory-0075":
        if labels != ["Security Advisory 0075"]:
            raise ValueError("Reviewed Arista publisher identity changed")
        _arista_legacy_eos(tree, parsed)
    if slug in ARISTA_FIX_RULES:
        parsed["assessments"].extend(_arista_fixes(tree, slug, parsed))
    reviewed_fixed, reviewed_issues = arista_assessments(tree, parsed, slug)
    parsed["assessments"].extend(reviewed_fixed)
    publisher = dict(
        id=labels[0],
        sequence=history[-1][0],
        status=None,
        source=_source(
            url,
            digest,
            "h2 direct text; table[Revision, Date, Changes]/tr[" + str(history_row) + "]",
        ),
    )
    claims = []
    for assessment in parsed["assessments"]:
        source = _source(url, digest, assessment["evidence_locator"])
        claim = _claim(
            "arista",
            parsed,
            source,
            publisher.copy(),
            parsed["published_at"],
            dates[-1] if len(dates) > 1 else None,
        )
        claim.update(
            cve_id=assessment["cve_id"],
            product_id=assessment.get("product_id"),
            product=assessment["product"],
            status=assessment["status"],
            scope=assessment["scope"],
        )
        if slug in {
            "24005-security-advisory-0137",
            "25048-security-advisory-0226",
            "23115-security-advisory-0128",
            "24847-security-advisory-0201",
            "15438-security-advisory-0075",
            "19862-security-advisory-0099",
            "19917-security-advisory-0103",
            "24853-security-advisory-0202",
            "25023-security-advisory-0203",
            "12135-security-advisory-61",
            "12166-security-advisory-62",
            "19221-security-advisory-0094",
            "24074-security-advisory-0140",
            "24515-security-advisory-0147",
        }:
            # These HTML adapters use local branch keys, not publisher product IDs.
            claim["product_id"] = None
        if assessment["product"] in {"Arista EOS", "EOS release (source platform scope applies)"}:
            claim["family"] = "arista-eos"
        if (
            slug == "24005-security-advisory-0137"
            and assessment["status"] == "affected"
            and assessment.get("product_context") == [["product_family", "Arista EOS"]]
        ):
            # The reviewed parser validates the EOS parent of these six local
            # platform groups. Literal model bindings remain unresolved below.
            claim["family"] = "arista-eos"
        if slug in software_cves and assessment["product"] == "EOS (source platform scope applies)":
            claim["family"] = "arista-eos"
        claim["version_expressions"] = [
            v["expression"] for v in assessment["versions"] if v.get("expression")
        ]
        claim["conditions"] = [
            text
            for e in assessment.get("exposure", [])
            if (text := _bounded(e.get("details"), claim["issues"]))
        ]
        if (
            slug in {"19905-security-advisory-0101", "24005-security-advisory-0137"}
            and claim["status"] == "affected"
        ):
            claim["conditional_affected"] = True
        claim["named_platforms"] = assessment.get("platforms", [])
        claim["platform_bindings"] = [
            dict(platform=p, model=None, basis="unresolved", source=source.copy())
            for p in claim["named_platforms"]
        ]
        for rem in assessment["remediations"]:
            statement = (
                (assessment["cve_id"] + " has been fixed in the following product releases:")
                if slug == "19904-security-advisory-0100"
                else rem.get("details")
            )
            if statement not in HTML(raw).root.text():
                raise ValueError("Reviewed Arista fixed-release statement changed")
            claim["remediations"].append(
                dict(
                    publisher_id=None,
                    category=rem["category"],
                    details=rem.get("details"),
                    product_ids=[claim["product_id"]] if claim["product_id"] else [],
                    version_expressions=(
                        claim["version_expressions"][:] if assessment in reviewed_fixed else []
                    ),
                    published_availability=statement,
                    availability=rem.get("availability", "unknown"),
                    availability_date=None,
                    source=_source(
                        url, digest, rem.get("source_locator", assessment["evidence_locator"])
                    ),
                )
            )
        claims.append(claim)
    if slug == "19904-security-advisory-0100" or slug in ARISTA_FIX_RULES:
        # Core SA0100 and the bounded resolution parser above verify owned
        # sections. Link only the finite EOS/CVE tuples; no family/model join.
        for claim in claims:
            cid = claim["cve_id"]
            rule = arista_reviewed_rule(claim)
            if (
                rule is None
                or claim["status"] != "affected"
                or claim["scope"] != "cve_specific"
                or claim["product"] != rule[1]
                or claim["source"]["source_locator"] != rule[2]
            ):
                continue
            fixed = [
                c
                for c in claims
                if c["cve_id"] == cid
                and c["status"] == "fixed"
                and c["scope"] == "cve_specific"
                and c["product"] == "Arista EOS"
                and c["source"]["source_locator"] == rule[3]
            ]
            if len(fixed) != 1:
                continue
            for remediation in fixed[0]["remediations"]:
                if remediation["source"] != fixed[0]["source"]:
                    continue
                bound = copy.deepcopy(remediation)
                bound["product_ids"] = []  # No synthetic publisher product ID.
                bound["version_expressions"] = fixed[0]["version_expressions"][:]
                bound["scope_binding"] = dict(
                    basis="reviewed_source_sections",
                    cve_id=cid,
                    source=claim["source"].copy(),
                    fixed_product="Arista EOS",
                    fixed_source=fixed[0]["source"].copy(),
                )
                claim["remediations"].append(bound)
    attach_links(claims)
    return dict(schema_version=1, claims=claims, bundles=[], issues=reviewed_issues)


def extract(raw: bytes, url: str, vendor: str, document: dict) -> dict:
    """Return version-1 claim templates with exact source hash and locators."""
    digest = hashlib.sha256(raw).hexdigest()
    if vendor not in FAMILIES:
        return dict(schema_version=1, claims=[], bundles=[], issues=["vendor_scope_unsupported"])
    matches = [
        r
        for r in bindings_resource()["entries"]
        if r["vendor"] == vendor and r["source_url"] == url
    ]
    entry = next((r for r in matches if r["source_sha256"] == digest), None)
    if matches and entry is None:
        return dict(schema_version=1, claims=[], bundles=[], issues=["source_binding_stale"])
    if raw.lstrip().startswith(b"{"):
        data = json.loads(raw)
        if "document" in data:
            return _csaf(raw, url, vendor, document, digest)
    if entry is None and vendor == "aruba":
        from .aruba_text import FORMAT, research_evidence

        if document.get("source_format") == FORMAT:
            return research_evidence(raw, url, vendor, document)
    if entry is None and vendor == "arista":
        bridged = _arista_reviewed(raw, url, document, digest)
        if bridged is not None:
            return bridged
    if entry is None:
        return dict(
            schema_version=1,
            claims=[],
            bundles=[],
            issues=["source_binding_stale" if matches else "source_layout_unsupported"],
        )
    if "bundle" in entry:
        bundle = copy.deepcopy(entry["bundle"])
        bundle["member_advisory_ids"] = list(dict.fromkeys(bundle["member_advisory_ids"]))
        bundle["source"] = _source(url, digest, bundle.pop("source_locator"))
        return dict(schema_version=1, claims=[], bundles=[bundle], issues=[])
    claims = []
    for row in entry["claims"]:
        row = copy.deepcopy(row)
        claim = _claim(
            vendor,
            document,
            _source(url, digest, row.pop("source_locator")),
            entry["publisher"],
            entry["initial_published_at"],
            entry["updated_at"],
        )
        claim.update(row)
        for rem in claim["remediations"]:
            rem["source"] = _source(url, digest, rem.pop("source_locator"))
            if "scope_binding" in rem:
                binding = rem["scope_binding"]
                binding["source"] = _source(url, digest, binding.pop("source_locator"))
        claims.append(claim)
    return dict(schema_version=1, claims=claims, bundles=[], issues=[])
