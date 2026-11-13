"""Offline, explicit-path Arista chronology replay/export; never opens default storage.

Run with --manifest, --output-json, --output-csv. Optional --database must name
an absent public scratch database. HTTP captures are read only and verified in
full before any ingestion. The helper neither fetches nor publishes anything.
"""

import argparse
import csv
import json
from hashlib import sha256
from importlib.resources import files
from pathlib import Path

from ..adapters.arista import arista_aggregate_notice
from ..adapters.arista_chronology import reconcile
from ..plugins.arista import research_evidence
from ..plugins.registry import default_registry
from ..storage.repository import connect, ingest, latest, now
from . import switching_evidence


def _receipt(entry):
    return {key: entry[key] for key in ("url", "sha256", "retrieved_at")}


def validate_cases(rows):
    """Actually check the three source-pinned chronology cases; review stays pending."""
    cases = json.loads(
        files("infrastructure_impact")
        .joinpath("resources/arista-chronology-validation.json")
        .read_text()
    )
    results = []
    by_number = {row["number"]: row for row in rows}
    for case in cases["cases"]:
        row = by_number.get(case["number"])
        if row is None:
            state = "not_replayed"
        elif row.get("source_hashes") != case["source_hashes"]:
            state = "different_capture"
        else:
            checks = (
                row["status"] == "corrected",
                row["effective_initial"] == case["html_initial"],
                row["csaf_initial"] == case["csaf_initial"],
                row["rss_publication"] == case["rss_publication"],
                bool(row["claim_initials"]),
                row["claim_initials"] == [case["html_initial"]],
                row["claim_scope_and_fixes_unchanged"],
                row.get("finalized_claim_initials") == [case["html_initial"]],
            )
            state = "passed" if all(checks) else "failed"
        results.append(
            dict(number=case["number"], automated_validation=state, human_review="pending")
        )
    return results


def replay(manifest_path, *, database=None):
    """Replay a caller-owned public manifest; all receipt checks precede writes."""
    manifest_raw = Path(manifest_path).read_bytes()
    manifest = json.loads(manifest_raw)
    captures = {}
    for entry in manifest:
        raw = Path(entry["path"]).read_bytes()
        key = (entry["number"], entry["kind"])
        if (
            entry.get("status") != 200
            or len(raw) != entry["bytes"]
            or sha256(raw).hexdigest() != entry["sha256"]
            or key in captures
            or entry["kind"] not in {"html", "csaf", "rss"}
        ):
            raise ValueError("source receipt verification failed")
        captures[key] = (entry, raw)
    if database is not None and Path(database).exists():
        raise ValueError("scratch database must not already exist")
    registry = default_registry()
    rows = []
    prepared = []
    rss = captures.get((None, "rss"))
    numbers = sorted({n for n, kind in captures if n is not None})
    for number in numbers:
        h = captures.get((number, "html"))
        c = captures.get((number, "csaf"))
        row = dict(
            number=number,
            status="unsupported",
            effective_initial=None,
            csaf_initial=None,
            csaf_current=None,
            rss_publication=None,
            claim_initials=[],
            claim_scope_and_fixes_unchanged=False,
            source_hashes={
                kind: captures[(number, kind)][0]["sha256"]
                for kind in ("html", "csaf")
                if (number, kind) in captures
            },
            human_review="pending",
            issues=[],
            chronology=None,
        )
        row["source_hashes"]["rss"] = rss[0]["sha256"] if rss else None
        if not h or not c:
            row["issues"] = ["paired_csaf_or_html_missing"]
            if h and not c:
                try:
                    notice = arista_aggregate_notice(h[1], h[0]["url"], "arista")
                    row.update(
                        status="informational_html_only",
                        effective_initial=notice["published_at"],
                        issues=["informational_references_only_no_affected_claims"],
                    )
                except ValueError:
                    pass
            rows.append(row)
            continue
        record = registry.normalize(c[1], c[0]["url"], "arista")
        record["source_observed_at"] = c[0]["retrieved_at"]
        result = reconcile(
            record,
            html_raw=h[1],
            html_source=_receipt(h[0]),
            csaf_raw=c[1],
            rss_raw=rss[1] if rss else None,
            rss_source=_receipt(rss[0]) if rss else None,
        )
        fixed = result["corrected_record"]
        original = research_evidence(c[1], c[0]["url"], "arista", record)
        repaired = research_evidence(c[1], c[0]["url"], "arista", fixed)
        initials = sorted(
            {
                claim["initial_published_at"]
                for claim in repaired["claims"]
                if claim["initial_published_at"]
            }
        )
        before = [
            {
                k: v
                for k, v in claim.items()
                if k not in {"initial_published_at", "initial_date_provenance"}
            }
            for claim in original["claims"]
        ]
        after = [
            {
                k: v
                for k, v in claim.items()
                if k not in {"initial_published_at", "initial_date_provenance"}
            }
            for claim in repaired["claims"]
        ]
        meta = result["chronology"]
        row.update(
            status=result["status"],
            effective_initial=fixed["published_at"],
            csaf_initial=record["published_at"],
            csaf_current=record["updated_at"],
            claim_initials=initials,
            claim_scope_and_fixes_unchanged=before == after,
            issues=result["issues"],
            chronology=meta,
        )
        if meta:
            rss_dates = [
                o["value"] for o in meta["observations"] if o["event"] == "rss_publication"
            ]
            row["rss_publication"] = rss_dates[0] if rss_dates else None
            prepared.append((c[1], c[0]["url"], fixed))
        rows.append(row)
    ingested = 0
    # Exercise the real retained-evidence and claim-ID pipeline for every replay.
    # In-memory storage is explicit; the default user's database is never opened.
    with connect(database if database is not None else ":memory:") as db:
        for raw, url, fixed in prepared:
            ingested += bool(ingest(db, raw, url, lambda *_args, fixed=fixed: fixed, "arista"))
        evidence = switching_evidence.project(
            switching_evidence.inputs(db, latest(db)), publication=None, generated_at=now()
        )
    for row in rows:
        claims = [
            c
            for c in evidence["claims"]
            if c["advisory_id"] == f"Arista Networks Security Advisory {row['number']}"
        ]
        row["finalized_claim_count"] = len(claims)
        row["finalized_claim_initials"] = sorted(
            {c["initial_published_at"] for c in claims if c["initial_published_at"]}
        )
        if row["status"] == "corrected" and (
            not claims or row["finalized_claim_initials"] != [row["effective_initial"]]
        ):
            raise ValueError("finalized study claim dates differ from owned chronology")
    validations = validate_cases(rows)
    if any(case["automated_validation"] == "failed" for case in validations):
        raise ValueError("finalized source-pinned chronology validation failed")
    return dict(
        schema_version=1,
        manifest_sha256=sha256(manifest_raw).hexdigest(),
        verified_captures=len(captures),
        source_coverage={
            kind: sum(k == kind for _, k in captures) for kind in ("html", "csaf", "rss")
        },
        sources=[
            {k: entry[k] for k in ("number", "kind", "url", "sha256", "bytes", "retrieved_at")}
            for entry, _ in captures.values()
        ],
        ingested_revisions=ingested,
        finalized_claim_count=len(evidence["claims"]),
        rows=rows,
        validation_cases=validations,
        limitations=[
            "Dates are distinct source events; RSS is not initial advisory publication.",
            "No product scope, fix facts, historical exposure, or human review acceptance is inferred.",
            "Capture receipts retain original times; scratch ingestion creates new local revision times.",
        ],
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-csv", type=Path, required=True)
    parser.add_argument("--database", type=Path)
    args = parser.parse_args(argv)
    result = replay(args.manifest, database=args.database)
    args.output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    columns = [
        "number",
        "status",
        "effective_initial",
        "csaf_initial",
        "csaf_current",
        "rss_publication",
        "claim_initials",
        "finalized_claim_count",
        "finalized_claim_initials",
        "human_review",
        "issues",
    ]
    with args.output_csv.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for row in result["rows"]:
            writer.writerow(
                {k: json.dumps(row[k]) if isinstance(row[k], list) else row[k] for k in columns}
            )
    print(
        json.dumps(
            dict(
                verified_captures=result["verified_captures"],
                rows=len(result["rows"]),
                validation_cases=result["validation_cases"],
            )
        )
    )


if __name__ == "__main__":
    main()
