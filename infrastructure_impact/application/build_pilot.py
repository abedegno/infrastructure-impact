"""Exact firmware references with field-level gaps, never inferred inventories."""

import json
from hashlib import sha256

from ..settings import PACKAGE
from ..source_policy import allowed

UNKNOWN_FIELDS = (
    "component_version",
    "package_patch_id",
    "hardware_model",
    "image_digest",
    "service_configuration",
    "historical_support_window",
    "historical_download_availability",
)


def build_pilot(data):
    spec = json.loads((PACKAGE / "resources/build-pilot.json").read_text())
    if len({t["id"] for t in spec["targets"]}) != len(spec["targets"]):
        raise ValueError("Duplicate build pilot target")
    rows = []
    for target in spec["targets"]:
        if not allowed(target["source_url"], target["vendor"]):
            raise ValueError("Build pilot requires official vendor sources")
        found = []
        for record in data.get("records", []):
            if (
                record["vendor"] != target["vendor"]
                or record["source_url"] != target["source_url"]
                or record.get("document_status") == "draft"
            ):
                continue
            for claim in record["assessments"]:
                if (
                    claim["product"] != target["product_literal"]
                    or claim["cve_id"] != target["cve_id"]
                    or claim["status"] != "fixed"
                    or claim["scope"] != "cve_specific"
                ):
                    continue
                exact = (
                    target["selector"] == "version_expression"
                    and any(
                        v.get("expression") == target["expression"]
                        for v in claim.get("versions", [])
                    )
                ) or (
                    target["selector"] == "product_version_context"
                    and ["product_version", target["firmware_build"]]
                    in claim.get("product_context", [])
                )
                if exact:
                    found.append((record, claim))
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
            dict(**target, fields=fields, state="partial_public_evidence", verified_inventory=False)
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
