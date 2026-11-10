"""Apply only bundled, finite reviewed source-section fix derivations."""

import copy

from .. import remediation_bindings as registry
from .common import availability


def _pointer(data, locator):
    for key in locator.strip("/").split("/"):
        data = data[int(key)] if isinstance(data, list) else data[key]
    return data


def attach_links(claims):
    """Copy an owned original fix onto each exact reviewed affected tuple."""
    for claim in claims:
        rule = registry.rule_for(claim)
        if rule is None or "evidence_text_truncated" in claim.get("issues", []):
            continue
        siblings = registry.fixed_siblings(claim, rule, claims)
        if len(siblings) != 1:
            continue
        originals = [
            rem
            for rem in siblings[0]["remediations"]
            if registry.owned_remediation(siblings[0], rem, rule)
        ]
        if len(originals) != 1:
            continue
        bound = copy.deepcopy(originals[0])
        bound["product_ids"] = []
        bound["version_expressions"] = rule["fixed_versions"][:]
        binding = dict(
            basis="reviewed_source_sections",
            cve_id=claim["cve_id"],
            source=claim["source"].copy(),
            fixed_product=rule["fixed_product"],
            fixed_source=siblings[0]["source"].copy(),
        )
        if rule["fixed_product_id"] is not None:
            binding["fixed_product_id"] = rule["fixed_product_id"]
        bound["scope_binding"] = binding
        registry.validate_link(claim, bound, binding, claims)
        if bound not in claim["remediations"]:
            claim["remediations"].append(bound)


def apply_csaf(data, claims, url, digest, as_of):
    """Upgrade original fixed availability only after source, parent and proof checks.

    Return bounded diagnostic codes. A drift never removes existing affected claims
    or directly scoped remediations. No validation result is cached.
    """
    advisory_id = data.get("document", {}).get("tracking", {}).get("id")
    sources = [
        s
        for s in registry.definition()["sources"]
        if s["kind"] == "csaf"
        and s["advisory_id"] == advisory_id
        and any(c["vendor"] == s["vendor"] and c["advisory_id"] == advisory_id for c in claims)
    ]
    if not sources:
        return []
    source = sources[0]
    try:
        parent = _pointer(data, source["product_parent"]["locator"])
        parent_ok = all(parent.get(k) == source["product_parent"][k] for k in ("category", "name"))
    except (KeyError, IndexError, TypeError, ValueError):
        parent_ok = False
    cves = [v.get("cve") for v in data.get("vulnerabilities", [])]
    if (
        url != source["source_url"]
        or digest != source["source_sha256"]
        or not parent_ok
        or sorted(cves) != sorted(source["expected_cve_ids"])
    ):
        return ["reviewed_fix_source_drift"]
    drift = False
    for claim in claims:
        rule = registry.rule_for(claim)
        if rule is None:
            continue
        siblings = registry.fixed_siblings(claim, rule, claims)
        if len(siblings) != 1:
            drift = True
            continue
        originals = [
            rem
            for rem in siblings[0]["remediations"]
            if registry.owned_remediation(siblings[0], rem, rule, released=False, as_of=as_of)
        ]
        if len(originals) != 1:
            drift = True
            continue
        rem = originals[0]
        # Literal owner proves availability; shared category/date/future guards remain.
        state = availability(
            "\n".join(rule["availability_proof_literals"]),
            rem["category"],
            rem["availability_date"],
            as_of=as_of,
        )
        if state == "vendor_reports_fixed":
            rem["availability"] = state
        else:
            drift = True
    attach_links(claims)
    return ["reviewed_fix_source_drift"] if drift else []
