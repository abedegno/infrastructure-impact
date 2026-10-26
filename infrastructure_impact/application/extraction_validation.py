"""Source-led spot checks pinned to reviewed source bytes, with blind review packets.

This is separate from parser regression tests and the mapping benchmark. Bundled
checks are automated reviews; they do not become independent human adjudication.
"""

import json
import re
from hashlib import sha256

from jsonschema import Draft202012Validator, FormatChecker

from ..collection.transport import allowed
from ..settings import PACKAGE


def definition():
    value = json.loads((PACKAGE / "resources/extraction-review.json").read_text())
    schema = json.loads((PACKAGE / "schemas/extraction-review-v1.json").read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)
    if len({c["id"] for c in value["cases"]}) != len(value["cases"]):
        raise ValueError("Validation case IDs must be unique")
    for case in value["cases"]:
        if not allowed(case["source_url"], case["vendor"]):
            raise ValueError("Extraction reviews require official vendor HTTPS sources")
    return value


def validation_report(records, review=None, scopes=()):
    review = definition() if review is None else review
    cases = []
    for case in review["cases"]:
        current = [
            r
            for r in records
            if r["vendor"] == case["vendor"] and r["source_url"] == case["source_url"]
        ]
        pinned = [
            r
            for r in current
            if r["sha256"] == case["source_sha256"] and r.get("document_status") != "draft"
        ]
        scoped = [
            r
            for r in current
            if r.get("document_status") != "draft"
            and case.get("reviewed_scope")
            and any(
                s.get("source_url") == r["source_url"]
                and s.get("source_sha256") == r["sha256"]
                and s.get("scheme") == case["reviewed_scope"]["scheme"]
                and s.get("scope_sha256") == case["reviewed_scope"]["sha256"]
                for s in scopes
            )
        ]
        claims = [
            a
            for r in pinned or scoped
            for a in r["assessments"]
            if a["cve_id"] == case["cve_id"]
            and re.search(case["product_pattern"], a["product"])
            and all(pair in a.get("product_context", []) for pair in case.get("claim_context", []))
        ]
        valid = [
            a
            for a in claims
            if a["status"] == case["expected_status"]
            and (not case.get("expected_scope") or a["scope"] == case["expected_scope"])
            and (
                not case.get("version_contains")
                or case["version_contains"] in json.dumps(a["versions"])
            )
            and (
                not case.get("remediation_availability")
                or any(
                    r.get("availability") == case["remediation_availability"]
                    for r in a["remediations"]
                )
            )
            and (
                not case.get("exposure_contains")
                or any(
                    case["exposure_contains"] in e.get("details", "") for e in a.get("exposure", [])
                )
            )
        ]
        forbidden = any(a["status"] in case.get("forbidden_statuses", []) for a in claims)
        outcome = (
            "source_missing"
            if not current
            else "source_revision_unreviewed"
            if not pinned and not scoped
            else "product_scope_missing"
            if not claims
            else "disagreement"
            if forbidden or not valid
            else "pass"
            if pinned
            else "reviewed_scope_match_source_changed"
        )
        cases.append(
            dict(
                **case,
                outcome=outcome,
                current_source_fingerprints=sorted({r["sha256"] for r in current}),
                observed_statuses=sorted({a["status"] for a in claims}),
                matching_reviewed_scope=bool(scoped),
            )
        )
    return dict(
        schema_version=1,
        reviewed_at=review["reviewed_at"],
        review_method=review["review_method"],
        review_status="automated_source_review_independent_human_pending",
        independent_human_review_completed=False,
        sample_strategy=review["sample_strategy"],
        total=len(cases),
        passed=sum(c["outcome"] == "pass" for c in cases),
        scope_matches=sum(c["outcome"] == "reviewed_scope_match_source_changed" for c in cases),
        source_documents=len({(c["vendor"], c["source_url"]) for c in cases}),
        vendors=sorted({c["vendor"] for c in cases}),
        global_precision=None,
        cases=cases,
        limitations=[
            "Purposive boundary sample, not a random or exhaustive accuracy estimate.",
            "Source-led checks were performed by an automated assistant in the implementation session, not an independent human reviewer.",
            "A raw source change remains visible. An explicitly reviewed structural section digest can corroborate unchanged evidence scope; it is reported separately from a full raw-byte pass. Expected labels never change automatically.",
            "Version and remediation checks preserve publisher statements; they do not verify version arithmetic, exploitability or actual release availability.",
        ],
    )


def review_packet(records):
    review = definition()
    documents = {}
    for case in review["cases"]:
        key = case["vendor"], case["source_url"]
        row = documents.setdefault(
            key,
            dict(
                vendor=key[0],
                source_url=key[1],
                reviewed_source_sha256=case["source_sha256"],
                current_source_fingerprints=sorted(
                    {
                        r["sha256"]
                        for r in records
                        if r["vendor"] == key[0] and r["source_url"] == key[1]
                    }
                ),
                questions=[],
            ),
        )
        # Withhold parser output, expected labels and rationales until adjudication.
        row["questions"].append(
            dict(
                id=case["id"],
                cve_id=case["cve_id"],
                source_locator=case["source_locator"],
                adjudication=dict(
                    product_scope=None,
                    status=None,
                    versions=None,
                    configuration_qualifiers=None,
                    remediation=None,
                    date_basis=None,
                    rationale=None,
                ),
            )
        )
    packet = dict(
        schema_version=1,
        review_status="awaiting_independent_reviewer",
        instructions="Read the official source independently and record its exact SHA-256. Complete each adjudication before consulting extraction-validation.json. Record reviewer identity/type, date, conflicts of interest and disagreements in a reviewed contribution; this packet never changes assessments or marks review complete.",
        documents=list(documents.values()),
    )
    return {**packet, "packet_sha256": packet_sha256(packet)}


def packet_sha256(packet):
    body = {
        k: v for k, v in packet.items() if k not in ("packet_sha256", "publication", "generated_at")
    }
    return sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
