"""Reproduce the round-4 catalogue from the three pinned, unreviewed research packets.

This is an offline, dated import mapping, not a general vendor scraper. Raw captures
remain outside Git. No field is inferred from an index, matching version or date.
"""

import hashlib
import json
from pathlib import Path

from infrastructure_impact.application.release_catalogue import validate_catalogue

ROOT = Path(__file__).resolve().parents[1]
RESEARCH = ROOT / "docs/research"
PREFIX = "2026-11-25-round4-"


def build_catalogue():
    packets = {
        vendor: json.loads((RESEARCH / f"{PREFIX}{vendor}.json").read_text())
        for vendor in ("cisco", "aruba", "arista")
    }
    # Preserve the latest actual receipt; never invent a capture time.
    receipts = []
    for packet in packets.values():

        def visit(item):
            if isinstance(item, dict):
                if isinstance(item.get("retrieved_at"), str):
                    receipts.append(item["retrieved_at"])
                for child in item.values():
                    visit(child)
            elif isinstance(item, list):
                for child in item:
                    visit(child)

        visit(packet)
    generated = max(r for r in receipts if "T" in r)
    dataset = dict(
        schema_version=1,
        generated_at=generated,
        review_status="independent_human_review_pending",
        sources=[],
        releases=[],
        notices=[],
        statements=[],
        coverage=[],
    )
    source_map = {}

    def reference(vendor, evidence):
        original = evidence.get("original_sha256")
        source = dict(
            vendor=vendor,
            source_url=evidence.get("source_url", evidence.get("url")),
            retrieved_at=evidence["retrieved_at"],
            capture_kind="original_document" if original else "tool_excerpt",
            original_sha256=original,
            excerpt_sha256=evidence.get("rendered_capture_sha256")
            or evidence.get("excerpt_sha256"),
        )
        key = (
            vendor
            + "-"
            + hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()[:24]
        )
        if key not in source_map:
            source["source_id"] = key
            dataset["sources"].append(source)
            source_map[key] = source
        return dict(
            source_id=key,
            locator=evidence.get("source_locator", evidence.get("locator")),
            quote=evidence.get("quote")
            or evidence.get("short_quote")
            or " | ".join(evidence["quoted_statements"]),
        )

    cisco = packets["cisco"]
    cisco_facts = {r["id"]: r for r in cisco["facts"]}
    for row in cisco["release_catalogue"]:
        dataset["releases"].append(
            dict(
                vendor="cisco",
                family="IOS XE",
                train="17.12",
                version=row["version"],
                observation_basis="version_table",
                release_date=None,
                date_status="unknown",
                announcement_date=None,
                platforms_stated=[row["model_family"]],
                evidence=[reference("cisco", cisco_facts[k]) for k in row["evidence_ids"]],
            )
        )
    for row in cisco["notices"]:
        # Keep exclusion controls in the research packet, not the cohort notice list.
        if row["notice_id"] not in {"FN74221", "FN74135", "FN72416"}:
            continue
        hardware = row["notice_id"] == "FN72416"
        dataset["notices"].append(
            dict(
                vendor="cisco",
                family="IOS XE",
                train="17.12",
                notice_id=row["notice_id"],
                title=cisco_facts[row["evidence_ids"][0]]["statement"],
                notice_date=None if row.get("date_conflict") else row["notice_date"],
                action_date=None,
                affected_releases=row.get("affected_versions_explicit", []),
                platforms_stated=["Catalyst 9300"]
                if hardware
                else ["Catalyst 9200", "Catalyst 9300"],
                replacement_release=None,
                classification="hardware" if hardware else "configuration_remediation",
                revision_date=row.get("last_published_date"),
                date_note="First Published header 2024-05-24 conflicts with revision 1.0 2024-05-22"
                if row.get("date_conflict")
                else None,
                fixed_releases=(
                    [
                        {
                            "version": "17.12.2",
                            "platforms_stated": ["Catalyst 9200"],
                            "conditions": "Conditional SUDI display defect; affected-unit status and platform subcase require review",
                        },
                        {
                            "version": "17.12.1",
                            "platforms_stated": ["Catalyst 9300"],
                            "conditions": "Not Affected-unit SUDI display defect only; not a remedy for all affected certificates",
                        },
                    ]
                    if row["notice_id"] == "FN74135"
                    else []
                ),
                evidence=[reference("cisco", cisco_facts[k]) for k in row["evidence_ids"]],
            )
        )

    aruba = packets["aruba"]
    scopes = {r["id"]: r["evidence"] for r in aruba["facts"] if r["kind"] == "platform_scope"}
    for row in aruba["releases"]:
        dataset["releases"].append(
            dict(
                vendor="aruba",
                family="AOS-CX",
                train="10.13",
                version=row["version"],
                observation_basis="release_history",
                release_date=row["release_date"],
                date_status="stated",
                announcement_date=None,
                platforms_stated=[row["platform"].split()[0]],
                evidence=[
                    reference("aruba", row["evidence"]),
                    reference("aruba", scopes[row["platform_scope_evidence_id"]]),
                ],
            )
        )
    # The HPE notice is outside the study models; the security bulletin is context,
    # not a release-deferral or nonsecurity field-notice observation.

    arista = packets["arista"]
    for row in arista["releases"]:
        dataset["releases"].append(
            dict(
                vendor="arista",
                family="EOS",
                train="4.33",
                version=row["release"],
                observation_basis=(
                    "availability_announcement"
                    if row["announcement_date"]
                    else "advisory_version_reference"
                    if "sa127" in row["identity_evidence_ids"]
                    else "notice_version_reference"
                    if "fn103" in row["identity_evidence_ids"]
                    else "document_index_reference"
                ),
                release_date=None,
                date_status="unknown",
                announcement_date=row["announcement_date"],
                platforms_stated=[],
                evidence=[
                    reference("arista", arista["evidence"][k]) for k in row["identity_evidence_ids"]
                ],
            )
        )
    fn103 = next(r for r in arista["notices"] if r["id"] == "FN0103")
    evidence = [reference("arista", arista["evidence"][k]) for k in fn103["evidence_ids"]]
    dataset["notices"].append(
        dict(
            vendor="arista",
            family="EOS",
            train="4.33",
            notice_id="FN0103",
            title="EOS 4.33.3F deferred due to software defect Bug ID 1165537",
            notice_date=fn103["notice_date"],
            action_date=None,
            affected_releases=["4.33.3F"],
            platforms_stated=[],
            replacement_release=None,
            classification="release_deferral",
            evidence=evidence,
        )
    )
    dataset["statements"].append(
        dict(
            vendor="arista",
            family="EOS",
            train="4.33",
            version="4.33.3F",
            status="deferred",
            notice_date=fn103["notice_date"],
            action_date=None,
            related_release=None,
            platforms_stated=[],
            evidence=evidence,
        )
    )

    reasons = {
        "cisco": "Eight unique versions in model-specific boot-loader tables, without release dates. Historical download and withdrawal coverage unestablished. Current notice index inspected; six older leads and C9200 index unresolved.",
        "aruba": "Rendered release-history rows only: 6300 has broader history than6200; TOC-only versions excluded; original document routes blocked. Complete release and notice enumeration not established.",
        "arista": "Rolling RSS and two field-notice index pages are incomplete. Announcement dates are not release dates. Model applicability and full release history unavailable; detail routes require login; automation permission unresolved.",
    }
    for vendor, train in [("cisco", "17.12"), ("aruba", "10.13"), ("arista", "4.33")]:
        for year in (2024, 2025, 2026):
            dataset["coverage"].append(
                dict(
                    vendor=vendor,
                    train=train,
                    year=year,
                    status="partial",
                    platforms={
                        "cisco": ["Catalyst 9200", "Catalyst 9300"],
                        "aruba": ["6200", "6300"],
                        "arista": [],
                    }[vendor],
                    enumeration_complete=False,
                    date_coverage_complete=False,
                    reason=reasons[vendor],
                    source_ids=[
                        s["source_id"] for s in dataset["sources"] if s["vendor"] == vendor
                    ],
                )
            )
    return validate_catalogue(dataset)


if __name__ == "__main__":
    value = build_catalogue()
    output = RESEARCH / "2026-11-25-release-catalogue.json"
    output.write_text(json.dumps(value, indent=2) + "\n")
    print(f"Wrote {len(value['releases'])} release observations to {output.name}")
