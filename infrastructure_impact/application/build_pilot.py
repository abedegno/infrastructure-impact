"""Exact firmware references with field-level gaps, never inferred inventories."""

import json
from hashlib import sha256

from ..settings import PACKAGE
from ..source_policy import allowed
from .build_inventory import template

UNKNOWN_FIELDS = (
    "component_version",
    "package_patch_id",
    "hardware_model",
    "image_digest",
    "service_configuration",
    "historical_support_window",
    "historical_download_availability",
    "build_component_binding",
)


def matches_target_reference(record, claim, target):
    """Match the pilot's exact source/product/CVE/build identity, retaining qualifications.

    Statement status and scope remain the caller's policy: the pilot requires a
    CVE-specific fixed claim, while a dossier preserves qualified or contradictory
    branches that carry the same exact target build identity.
    """
    if (
        record["vendor"] != target["vendor"]
        or record["source_url"] != target["source_url"]
        or record.get("document_status") == "draft"
        or claim["product"] != target["product_literal"]
        or claim["cve_id"] != target["cve_id"]
    ):
        return False
    return (
        target["selector"] == "version_expression"
        and any(v.get("expression") == target["expression"] for v in claim.get("versions", []))
    ) or (
        target["selector"] == "product_version_context"
        and ["product_version", target["firmware_build"]] in claim.get("product_context", [])
    )


def build_pilot(data):
    spec = json.loads((PACKAGE / "resources/build-pilot.json").read_text())
    if len({t["id"] for t in spec["targets"]}) != len(spec["targets"]):
        raise ValueError("Duplicate build pilot target")
    rows = []
    for target in spec["targets"]:
        if not allowed(target["source_url"], target["vendor"]):
            raise ValueError("Build pilot requires official vendor sources")
        found = [
            (record, claim)
            for record in data.get("records", [])
            for claim in record["assessments"]
            if matches_target_reference(record, claim, target)
            and claim["status"] == "fixed"
            and claim["scope"] == "cve_specific"
        ]
        evidence = [
            dict(
                source_url=r["source_url"],
                source_sha256=r["sha256"],
                observed_at=r.get("source_observed_at"),
                locator=a["evidence_locator"],
            )
            for r, a in found
        ]
        fields = [
            dict(
                field="firmware_reference",
                state="publisher_statement" if found else "unknown",
                value=target["firmware_build"] if found else None,
                evidence=evidence,
            )
        ]
        for name in UNKNOWN_FIELDS:
            fields.append(dict(field=name, state="unknown", value=None, evidence=[]))
        for field, category in (
            ("platform_applicability_context", "publisher_platform_scope"),
            ("backport_statement", "publisher_backport_statement"),
        ):
            contexts = [
                (r, a, e)
                for r, a in found
                for e in a.get("exposure", [])
                if e["category"] == category
            ]
            references = [
                dict(
                    source_url=r["source_url"],
                    source_sha256=r["sha256"],
                    observed_at=r.get("source_observed_at"),
                    locator=e.get("source_locator") or a["evidence_locator"],
                )
                for r, a, e in contexts
            ]
            fields.append(
                dict(
                    field=field,
                    state="publisher_statement" if contexts else "unknown",
                    value=" ".join(dict.fromkeys(e["details"] for _, _, e in contexts))
                    if contexts
                    else None,
                    evidence=references,
                )
            )
        rows.append(
            dict(
                **target,
                fields=fields,
                state="partial_public_evidence",
                verified_inventory=False,
                inventory_proposal_template=template(
                    target["vendor"],
                    target["product_literal"],
                    target["firmware_build"],
                    "OpenSSH",
                    spec["role"],
                ),
                source_check=next(
                    (
                        dict(
                            outcome=c["outcome"],
                            checked_at=c.get("checked_at"),
                            error_code=c.get("error_code"),
                        )
                        for c in data.get("health", [])
                        if c["vendor"] == target["vendor"]
                        and c["source_url"] == target["source_url"]
                    ),
                    dict(outcome="not_checked", checked_at=None, error_code=None),
                ),
            )
        )
    return dict(
        schema_version=1,
        version=spec["version"],
        selection_sha256=sha256(
            json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        role=spec["role"],
        component="OpenSSH",
        cve_id="CVE-2024-6387",
        targets=rows,
        independent_human_review_completed=False,
        build_denominator=None,
        rate_comparison=None,
        method="Retrospective purposive pilot of two exact firmware references for SSH management on switching platforms. Selection follows accessible publisher statements, not representative sampling. A fixed-release statement does not prove prior exposure, hardware compatibility, a shipped package version, a binary digest or installed service state. Unknown fields remain null; backport statements are publisher context, not image verification. This pilot cannot establish comparable exposure denominators, security rankings or first-disclosure timing.",
    )
