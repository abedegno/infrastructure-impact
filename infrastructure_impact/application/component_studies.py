"""Frozen component reference studies with explicit unknown vendor cells.

Enrollment is independent of retained vendor outcomes. A component registry
mapping is a reference candidate, never evidence of a shipped dependency.
"""

import json
import re
from collections import Counter
from hashlib import sha256

from ..references.registry import source
from ..settings import PACKAGE
from .families import definition as family_definition
from .families import statements

HASH = re.compile(r"[a-f0-9]{64}")
BLOCKERS = [
    "Independent human review of role enrollment and vendor assertions is pending.",
    "Comparable product, platform, enabled-service and release-build inventories are not established.",
    "Vendor archive coverage and the completeness of upstream registry mappings are not established.",
    "Backports and downstream patch variants require product-build evidence.",
    "Current retained statements do not reconstruct historical exposure or first disclosure.",
]
METHOD = (
    "Whole-publication study, independent of the dashboard CVE selection. "
    "A frozen retrospective registry product-mapped cohort is joined to the latest retained "
    "non-draft vendor family statements. Missing evidence remains unknown. Client-only exclusions "
    "are not unaffectedness. Fixed-only statements do not establish prior exposure. "
    "No affectedness rates, vendor ranking or concealment finding is supported."
)


def definitions():
    result = []
    known_families = {f["id"] for f in family_definition()["families"]}
    for path in sorted((PACKAGE / "resources/studies").glob("*.json")):
        value = json.loads(path.read_text())
        source(value["source_id"])
        if not set(value["families"]) <= known_families:
            raise ValueError("Unknown study family")
        fields = {
            k: value[k] for k in ("period", "families", "candidate_reviews", "selection_rule")
        }
        digest = sha256(
            json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if digest != value["cohort_sha256"]:
            raise ValueError("Frozen study cohort fingerprint mismatch")
        ids = [r["cve_id"] for r in value["candidate_reviews"]]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate study candidate")
        result.append(value)
    return result


def public_inputs(values):
    """Project only trusted reference metadata; raw descriptions and extensions stay private."""
    result = []
    for value in values:
        try:
            spec = source(value.get("source_id"))
        except ValueError:
            continue
        if value.get("source_url") != spec.url or not HASH.fullmatch(
            value.get("source_sha256", "")
        ):
            continue
        collection = value.get("collection")
        result.append(
            {
                "source_id": spec.id,
                "source_url": spec.url,
                **{
                    k: value.get(k)
                    for k in ("source_sha256", "source_observed_at", "parsed_at", "parser_version")
                },
                "collection": {
                    k: collection.get(k) for k in ("checked_at", "outcome", "error_code")
                }
                if collection
                else None,
                "records": [
                    {
                        k: row[k]
                        for k in (
                            "cve_id",
                            "publisher_published_at",
                            "record_semantic_sha256",
                            "rejected",
                            "has_positive_product_mapping",
                        )
                    }
                    for row in value.get("records", [])
                ],
            }
        )
    return result


def reference_status(study, inputs):
    ref = next((r for r in inputs if r["source_id"] == study["source_id"]), None)
    baseline = {r["cve_id"]: r for r in study["candidate_reviews"]}
    if not ref:
        return {
            "state": "not_collected",
            "source": None,
            "added_candidates": [],
            "removed_candidates": [],
            "changed_candidates": [],
        }
    current = {
        r["cve_id"]: r
        for r in ref["records"]
        if study["period"]["start"] <= r["publisher_published_at"][:10] <= study["period"]["end"]
    }
    added = sorted(current.keys() - baseline.keys())
    removed = sorted(baseline.keys() - current.keys())
    changed = sorted(
        cid
        for cid in baseline.keys() & current.keys()
        if baseline[cid]["record_semantic_sha256"] != current[cid]["record_semantic_sha256"]
    )
    return {
        "state": "review_required"
        if added or removed or changed
        else "matches_frozen_candidate_semantics",
        "source": {k: v for k, v in ref.items() if k != "records"},
        "added_candidates": added,
        "removed_candidates": removed,
        "changed_candidates": changed,
    }


def cell(data, family, cid):
    found = [(r, a) for r, a in statements(data, family) if a["cve_id"] == cid]
    explicit = [(r, a) for r, a in found if a["scope"] == "cve_specific"]
    statuses = sorted({a["status"] for _, a in explicit})
    if not found:
        referenced = any(
            r["vendor"] == family["vendor"]
            and r.get("document_status") != "draft"
            and cid in r["cves"]
            for r in data["records"]
        )
        state = (
            "vendor_reference_without_family_assessment"
            if referenced
            else "unknown_no_retained_family_assessment"
        )
    elif not explicit:
        state = "shared_bulletin_only"
    elif "conflicting" in statuses or "affected" in statuses and "unaffected" in statuses:
        state = "scope_requires_review"
    elif "affected" in statuses:
        state = "explicit_affected_statement"
    elif "partially_mitigated" in statuses:
        state = "explicit_partial_mitigation_statement"
    elif "unaffected" in statuses:
        state = "explicit_unaffected_statement"
    elif "fixed" in statuses:
        state = "fixed_statement_without_prior_exposure_inference"
    else:
        state = "assessment_unresolved"
    evidence = []
    for record, claim in found[:12]:
        evidence.append(
            {
                "source_url": record["source_url"],
                "source_sha256": record["sha256"],
                "source_observed_at": record.get("source_observed_at") or record.get("observed_at"),
                "publisher_published_at": record.get("published_at"),
                "advisory_id": record["advisory_id"],
                "product": claim["product"],
                "status": claim["status"],
                "scope": claim["scope"],
                "platforms": claim.get("platforms", []),
                "versions": [
                    {
                        k: v
                        for k, v in version.items()
                        if k
                        in {
                            "version",
                            "expression",
                            "status",
                            "lessThan",
                            "lessThanOrEqual",
                            "versionType",
                        }
                    }
                    for version in claim.get("versions", [])
                ],
                "product_context": claim.get("product_context", []),
                "exposure_context_present": bool(claim.get("exposure")),
                "evidence_locator": claim.get("evidence_locator"),
            }
        )
    return {
        "family_id": family["id"],
        "vendor": family["vendor"],
        "cve_id": cid,
        "state": state,
        "explicit_statuses": statuses,
        "statements": len(found),
        "evidence": evidence,
        "evidence_truncated": len(found) > 12,
        "product_build_equivalence": "not_verified",
        "deployment_exposure": "not_verified",
    }


def component_studies(data):
    inputs = public_inputs(data.get("research", {}).get("study_inputs", []))
    families = {f["id"]: f for f in family_definition()["families"]}
    studies = []
    for study in definitions():
        enrolled = [
            r["cve_id"] for r in study["candidate_reviews"] if r["enrollment"] == "included"
        ]
        cells = [
            cell(data, families[fid], cid)
            for cid in enrolled
            for fid in study["families"]
            if families[fid]["vendor"] in data["vendors"]
        ]
        studies.append(
            {
                **study,
                "scope": "whole_publication_fixed_reference_cohort",
                "reference_status": reference_status(study, inputs),
                "included_cves": enrolled,
                "members": [
                    {k: families[fid][k] for k in ("id", "vendor", "name")}
                    for fid in study["families"]
                ],
                "cells": cells,
                "cell_states": dict(Counter(c["state"] for c in cells)),
                "rate_comparison": None,
                "ranking_supported": False,
                "blockers": BLOCKERS,
            }
        )
    return {"schema_version": 1, "studies": studies, "method": METHOD}
