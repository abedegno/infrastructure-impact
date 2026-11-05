"""Pure switching evidence extraction. No version comparison or model inference.

CSAF structural product names are matched literally. Reviewed HTML claims and
bundle membership require the exact registered bytes, URL and evidence locator.
The caller adds retained retrieval time and normalized revision, never this hook.
"""

import copy
import hashlib
import json
import re
from importlib.resources import files

from .common import HTML, availability, iso_date
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
        # Resolve each publisher scope once. Membership is checked before any
        # claim-local projection; an unresolved group still cannot authorize a fix.
        remediations = []
        for ri, rem in enumerate(vuln.get("remediations", [])):
            ids = set(rem.get("product_ids", []))
            for group in rem.get("group_ids", []):
                ids.update(groups.get(group, []))
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
            if claim["platform_bindings"]:
                claim["scope_level"] = "model_qualified"
            # Notes remain literal CVE context; no prose conditions are used for
            # model assignment. Scoped threats retain only their own product set.
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
                claim["issues"].extend(issues)
                claim["remediations"].append(
                    {
                        **prepared,
                        "product_ids": [pid] if ids and pid is not None else sorted(ids),
                        "version_expressions": [],
                        "source": dict(prepared["source"]),
                    }
                )
            claims.append(claim)
    return dict(
        schema_version=1,
        claims=claims,
        bundles=[],
        issues=[] if claims else ["product_scope_unresolved"],
    )


def _arista_reviewed(raw, url, document, digest):
    """Bridge only reviewed routes, re-reading bytes through the core adapters.

    Shared platform prose is never attached to another assessment. Slash labels
    remain literal unresolved platforms, even when they contain a target token.
    """
    from ..plugins.arista import parse

    routes = {
        "19905-security-advisory-0101": "Arista reviewed applicability boundaries HTML",
        "19222-security-advisory-0095": "Arista reviewed applicability boundaries HTML",
        "19904-security-advisory-0100": "Arista affected software HTML",
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
    dates = [iso_date(row[1]) for row in history]
    if dates != sorted(dates) or dates[0] != parsed["published_at"]:
        raise ValueError("Reviewed Arista revision chronology changed")
    publisher = dict(
        id=labels[0],
        sequence=history[-1][0],
        status=None,
        source=_source(
            url,
            digest,
            "h2 direct text; table[Revision, Date, Changes]/tr[" + str(len(history)) + "]",
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
        claim["version_expressions"] = [
            v["expression"] for v in assessment["versions"] if v.get("expression")
        ]
        claim["conditions"] = [
            text
            for e in assessment.get("exposure", [])
            if (text := _bounded(e.get("details"), claim["issues"]))
        ]
        if slug == "19905-security-advisory-0101" and claim["status"] == "affected":
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
                    version_expressions=[],
                    published_availability=statement,
                    availability=rem.get("availability", "unknown"),
                    availability_date=None,
                    source=_source(
                        url, digest, rem.get("source_locator", assessment["evidence_locator"])
                    ),
                )
            )
        claims.append(claim)
    if slug == "19904-security-advisory-0100":
        # The core openssh_scope parser has verified its exact reviewed section
        # hashes. Link only these literal EOS/CVE branches; no family/model join.
        for claim in claims:
            cid = claim["cve_id"]
            if (
                cid not in {"CVE-2024-6387", "CVE-2024-6409"}
                or claim["status"] != "affected"
                or claim["scope"] != "cve_specific"
                or claim["product"] != "EOS release (source platform scope applies)"
                or claim["source"]["source_locator"]
                != "Affected Software / EOS release (source platform scope applies)"
            ):
                continue
            fixed = [
                c
                for c in claims
                if c["cve_id"] == cid
                and c["status"] == "fixed"
                and c["scope"] == "cve_specific"
                and c["product"] == "Arista EOS"
                and c["source"]["source_locator"]
                == "Resolution / " + cid + " / Arista EOS-based products"
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
    return dict(schema_version=1, claims=claims, bundles=[], issues=[])


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
