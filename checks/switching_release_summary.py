"""Summarize a verified public switching publication without private state.

Run after checks.switching_analysis_acceptance:
    python -m checks.switching_release_summary PUBLIC_DIR PROOF_DIR OUTPUT_JSON
The CLI ignores ambient IMPACT/CISCO settings; imported functions have no env effects.
No network, database, profile or default source configuration is consulted.
"""

import collections
import hashlib
import json
import os
import sys
import time
from pathlib import Path


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def counts(rows):
    return {
        "advisories": len({r["advisory_id"] for r in rows}),
        "cves": len({r["cve_id"] for r in rows}),
        "pairs": len(rows),
    }


def main(argv=None):
    started = time.monotonic()
    values = sys.argv[1:] if argv is None else list(argv)
    if len(values) != 3:
        raise SystemExit(__doc__)
    from infrastructure_impact.application import first_fixed
    from infrastructure_impact.application.publication_reader import PublicationReader
    from infrastructure_impact.publication_codec import MAX_SELECTED

    public, proof_dir, output = map(lambda x: Path(x).resolve(), values)
    proof_path = proof_dir / "proof.json"
    with proof_path.open("rb") as stream:
        raw_proof = stream.read(2_000_001)
    if len(raw_proof) > 2_000_000:
        raise ValueError("proof exceeds metadata bound")
    proof = json.loads(raw_proof)
    analysis_path = proof_dir / "selected-analysis.json"
    desc = proof["analysis_json"]
    if desc["path"] != "selected-analysis.json":
        raise ValueError("unexpected analysis path")
    if type(desc["bytes"]) is not int or not 0 < desc["bytes"] <= MAX_SELECTED:
        raise ValueError("selected-analysis exceeds selected bound")
    if analysis_path.stat().st_size != desc["bytes"]:
        raise ValueError("selected-analysis byte count mismatch")
    if digest(analysis_path) != desc["sha256"]:
        raise ValueError("selected-analysis hash mismatch")
    v = json.loads(analysis_path.read_text())
    reader = PublicationReader(public)
    identity = reader.identity
    for obj in [
        proof,
        v,
        *(
            v[k]
            for k in (
                "upgrades",
                "disclosure",
                "model_coverage",
                "kev_reconciliation",
                "release_history",
            )
        ),
    ]:
        if not all(obj[k] == identity[k] for k in identity):
            raise ValueError("mixed publication generation")
    if v["availability"] != "available":
        raise ValueError("selected analysis unavailable")
    print("Verified selected-analysis bytes/hash and public generation", flush=True)
    u, d = v["upgrades"], v["disclosure"]
    compact = u["requirements"]
    methods = collections.defaultdict(
        lambda: {"requirements": 0, "claims": set(), "advisories": set(), "cves": set()}
    )
    scenarios = collections.defaultdict(
        lambda: {"requirements": 0, "claims": set(), "advisories": set(), "cves": set()}
    )
    for vendor in ("cisco", "aruba", "arista"):
        for scenario in ("publisher_first_fixed", "known_fixed_target", "inferred_inclusive"):
            scenarios[(vendor, scenario)]
    api = collections.defaultdict(
        lambda: {
            "claims": set(),
            "advisories": set(),
            "cves": set(),
            "version_cve_pairs": set(),
            "proof_refs": set(),
        }
    )
    for r in compact["requirements"]:
        if r["target"] is None or r.get("issues"):
            continue
        owner = compact["members"][r["claim_id"]]
        facts = compact["facts"][r["proof_ref"]]
        names = (
            {f.get("method", "unknown") for f in facts} if isinstance(facts, list) else {"unknown"}
        )
        for key, table in [
            ((owner["vendor"], r["scenario"]), scenarios),
            *[((owner["vendor"], r["scenario"], m), methods) for m in names],
        ]:
            q = table[key]
            q["requirements"] += 1
            for field, val in [
                ("claims", r["claim_id"]),
                ("advisories", owner["advisory_id"]),
                ("cves", owner["cve_id"]),
            ]:
                q[field].add(val)
        if r["scenario"] == "publisher_first_fixed" and "openvuln_api" in names:
            for literal in r["alternatives"]:
                q = api[literal]
                q["claims"].add(r["claim_id"])
                q["advisories"].add(owner["advisory_id"])
                q["cves"].add(owner["cve_id"])
                q["version_cve_pairs"].add((literal, owner["cve_id"]))
                q["proof_refs"].add(r["proof_ref"])

    def coverage(table, fields):
        return [
            dict(
                zip(fields, key),
                **{k: len(val) if isinstance(val, set) else val for k, val in row.items()},
            )
            for key, row in sorted(table.items())
        ]

    overview = reader.switching_overview(v["generated_at"])
    whole = [{k: r[k] for k in r if k != "affected_cve_ids"} for r in overview["rows"]]
    # Existing reducer computes annual nonaffected/shared/draft/unresolved coverage;
    # no new projection or build is performed.
    annual = []
    years = sorted(d["years"])
    selections = [{"scope_level": "os_family", "window": year} for year in years]
    for selected in reader.switching_selections(selections, evaluated_at=v["generated_at"]):
        if not all(selected[k] == identity[k] for k in identity):
            raise ValueError("mixed annual publication generation")
        annual.extend({k: r[k] for k in r if k != "affected_cve_ids"} for r in selected["rows"])
    print("Computed public annual and whole-window comparison rows", flush=True)
    trains = {
        "cisco": {"17.9", "17.12", "17.15"},
        "aruba": {"10.13", "10.14", "10.16"},
        "arista": {"4.32", "4.33", "4.34"},
    }
    requested = [
        {
            k: r[k]
            for k in (
                "vendor",
                "family",
                "train",
                "year",
                "scenario",
                "policy",
                "event_count",
                "supported_event_count",
                "coverage",
                "baseline",
                "partial_year",
            )
        }
        for r in u["rows"]
        if r["train"] in trains.get(r["vendor"], set())
    ]
    if len(requested) != 9 * 3 * 2 * len(years):
        raise ValueError("requested train matrix incomplete")
    july = []
    for period in ("pre_july", "from_july", "unknown"):
        pairs = [p for p in d["pairs"] if p["vendor"] == "cisco" and p["date_period"] == period]
        july.append(
            {
                "period": period,
                **counts(pairs),
                "umbrella_cves": len({p["cve_id"] for p in pairs if p["umbrella"]}),
                "method_pair_counts": dict(
                    collections.Counter(p["method"]["classification"] or "unknown" for p in pairs)
                ),
            }
        )
    # Complete scans authenticate logical hashes even when only Cisco is retained.
    ranges = reader.ranges("runtime-snapshot")
    records, wrappers, chronology = [], [], []
    scanned = collections.Counter()
    for record in reader.iter_array(ranges[("records",)]):
        scanned[record["vendor"]] += 1
        if record["vendor"] == "cisco":
            records.append(record)
        if record["vendor"] == "arista":
            chronology.append(
                {
                    k: record.get(k)
                    for k in (
                        "advisory_id",
                        "published_at",
                        "updated_at",
                        "document_status",
                        "timeline",
                        "revision_id",
                        "sha256",
                        "source_url",
                        "source_observed_at",
                    )
                }
            )
    for wrapper in reader.iter_array(ranges[("retained_advisories",)]):
        record = wrapper["record"]
        if record["vendor"] == "cisco":
            wrappers.append(wrapper)
    # Include all current retained Cisco records, deduplicating identical receipts.
    seen = set()
    calibration_records = []
    for record in [*records, *(w["record"] for w in wrappers)]:
        key = json.dumps(record, sort_keys=True, separators=(",", ":"))
        if key not in seen:
            seen.add(key)
            calibration_records.append(record)
    calibration = first_fixed.build_report(
        calibration_records,
        api_results=[],
        publication=v["publication"],
        generated_at=v["generated_at"],
    )
    first_fixed.validate_report(calibration)
    table_records = [r for r in calibration_records if r.get("first_fixed")]
    print(
        "Validated native calibration of all current retained normalized Cisco tables", flush=True
    )
    api_rows = [
        {
            "literal": literal,
            **{k: sorted(vals) for k, vals in q.items()},
            "availability_date": None,
            "date_basis": "not_supplied_by_api_requirement",
        }
        for literal, q in sorted(api.items())
    ]
    summary = dict(
        helper_source_sha256=digest(Path(__file__)),
        native_first_fixed_source_sha256=digest(Path(first_fixed.__file__)),
        schema_version=1,
        publication=v["publication"],
        generated_at=v["generated_at"],
        observation_end=u["observation_end"],
        availability=v["availability"],
        selection=v["selection"],
        generation_proof={
            "proof_sha256": digest(proof_path),
            "selected_analysis": desc,
            "profile": proof.get("profile"),
            "public_index_sha256": digest(public / "data/index.json"),
            "public_catalog_descriptor": reader.index["publication_v2"],
            "runtime_records_range": ranges[("records",)],
            "runtime_retained_range": ranges[("retained_advisories",)],
            "identity_verified": True,
        },
        whole_window=whole,
        annual=annual,
        scenario_usable_coverage=coverage(scenarios, ["vendor", "scenario"]),
        scenario_method_usable_coverage=coverage(methods, ["vendor", "scenario", "method"]),
        api_literal_alternatives={
            "basis": "all alternatives of issue-free publisher_first_fixed requirements with openvuln_api proof; not only chosen target",
            "literal_count": len(api),
            "version_cve_pairs": len(
                {pair for q in api.values() for pair in q["version_cve_pairs"]}
            ),
            "cves": len({cve for q in api.values() for cve in q["cves"]}),
            "advisories": len({adv for q in api.values() for adv in q["advisories"]}),
            "literals": api_rows,
        },
        requested_train_rows=requested,
        upgrade_rows=len(u["rows"]),
        upgrade_rows_known_totals=sum(r["event_count"] is not None for r in u["rows"]),
        kev_reconciliation=v["kev_reconciliation"],
        model_coverage=v["model_coverage"],
        cisco_july_before_after=july,
        disclosure_coverage=d["coverage"],
        disclosure_periods=d["periods"],
        disclosure_bundles=d["bundles"],
        chronology={
            "basis": "current public normalized Arista initial/update/timeline source ownership",
            "records": chronology,
        },
        release_history={
            "coverage": v["release_history"]["coverage"],
            "releases": v["release_history"]["releases"],
            "sources": v["release_history"]["sources"],
            "diagnostics": v["release_history"]["diagnostics"],
        },
        retained_table_calibration={
            "scope": "ALL CURRENT RETAINED normalized Cisco table evidence in this publication, including retained excluded wrappers; not unretrieved advisories, raw extraction completeness, historical revisions or complete vendor archive",
            "api_results": [],
            "native_validate_report": "passed",
            "scanned_current_records_by_vendor": dict(scanned),
            "current_cisco_records": len(records),
            "retained_cisco_wrappers": [
                {k: w.get(k) for k in ("decision_id", "record_scope", "target_key")}
                for w in wrappers
            ],
            "deduplicated_calibration_records": len(calibration_records),
            "table_record_census": [
                {
                    **{
                        k: r.get(k)
                        for k in (
                            "vendor",
                            "advisory_id",
                            "sha256",
                            "source_url",
                            "source_observed_at",
                            "revision_id",
                        )
                    },
                    "normalized_table_facts": len(r["first_fixed"]),
                }
                for r in table_records
            ],
            **{
                k: calibration[k]
                for k in ("coverage", "units", "validation", "diagnostics", "catalogue")
            },
        },
        boundaries={
            "expected_complete_vendor_inventory": None,
            "unretrieved_advisories": None,
            "raw_table_extraction_completeness": None,
            "historical_revision_completeness": None,
            "actual_customer_upgrade_counts": None,
            "human_extraction_review": "pending",
            "visual_review": "not_performed",
            "json_csv_native_parity": "separate acceptance receipt required",
            "nonadditive": "scenarios, methods, model rows and annual CVE unions overlap; null totals remain unknown",
        },
    )
    summary["helper_elapsed_seconds"] = round(time.monotonic() - started, 3)
    output.write_text(json.dumps(summary, indent=2) + "\n")
    print(
        json.dumps(
            {
                "output": str(output),
                "publication": summary["publication"],
                "elapsed_seconds": summary["helper_elapsed_seconds"],
                "requested_rows": len(requested),
                "api_literals": len(api),
                "calibration_validation": calibration["validation"],
                "calibration_coverage": calibration["coverage"],
            }
        )
    )


if __name__ == "__main__":
    for _key in list(os.environ):
        if _key.startswith(("IMPACT", "CISCO")):
            del os.environ[_key]
    main()
