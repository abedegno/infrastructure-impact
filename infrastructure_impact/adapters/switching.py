"""Pure switching evidence extraction. No version comparison or model inference.

CSAF structural product names are matched literally. Reviewed HTML claims and
bundle membership require the exact registered bytes, URL and evidence locator.
The caller adds retained retrieval time and normalized revision, never this hook.
"""

import copy
import hashlib
import json
from importlib.resources import files

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
                ids = threat.get("product_ids", []) + [
                    p for g in threat.get("group_ids", []) for p in groups.get(g, [])
                ]
                if (not ids or pid in ids) and threat.get("details"):
                    claim["conditions"].append(_bounded(threat["details"], claim["issues"]))
            for ri, rem in enumerate(vuln.get("remediations", [])):
                ids = rem.get("product_ids", []) + [
                    p for g in rem.get("group_ids", []) for p in groups.get(g, [])
                ]
                if ids and pid not in ids:
                    continue
                if rem.get("group_ids") and any(g not in groups for g in rem["group_ids"]):
                    claim["issues"].append("remediation_product_scope_unresolved")
                    continue
                details = _bounded(rem.get("details"), claim["issues"])
                claim["remediations"].append(
                    dict(
                        publisher_id=None,
                        category=rem.get("category", "unknown"),
                        details=details,
                        product_ids=sorted(set(ids)),
                        version_expressions=[],
                        published_availability=details,
                        availability_date=rem.get("date"),
                        source=_source(url, digest, f"/vulnerabilities/{vi}/remediations/{ri}"),
                    )
                )
            claims.append(claim)
    return dict(
        schema_version=1,
        claims=claims,
        bundles=[],
        issues=[] if claims else ["product_scope_unresolved"],
    )


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
