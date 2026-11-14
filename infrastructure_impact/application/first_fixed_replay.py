"""Explicit-path offline research replay; no database, fetching or publication.

Run: python -m infrastructure_impact.application.first_fixed_replay
     --records PUBLIC.json[.gz] --manifest MANIFEST.json --output REPORT.json
     --generated-at ISO_TIMESTAMP
"""

import argparse
import gzip
import json
from hashlib import sha256
from pathlib import Path

from ..adapters.standards import csaf
from .first_fixed import MAX_GRAPH, build_report, validate_report


def replay(records, manifest_path, generated_at):
    manifest_path = Path(manifest_path)
    manifest_raw = manifest_path.read_bytes()
    manifest = json.loads(manifest_raw)
    entries = manifest["entries"]
    if not isinstance(entries, list) or len(entries) > MAX_GRAPH:
        raise ValueError("Manifest exceeds retained graph bounds")
    refreshed, unavailable, receipts = {}, [], []
    total = 0
    for entry in entries:
        url = entry["source_url"]
        if entry.get("outcome") not in {"captured", "reused_exact_hash"} or not entry.get(
            "raw_path"
        ):
            unavailable.append({"source_url": url, "state": "unavailable"})
            continue
        path = Path(entry["raw_path"])
        if path.stat().st_size > 8000000:
            raise ValueError("Raw source exceeds corpus document bound")
        raw = path.read_bytes()
        total += len(raw)
        if total > 250000000:
            raise ValueError("Raw source exceeds corpus total bound")
        digest = sha256(raw).hexdigest()
        if digest != entry["response_sha256"]:
            raise ValueError("Raw source hash mismatch: " + url)
        capture_url = entry.get("capture_source_url", url)
        record = csaf(raw, capture_url, "cisco")
        record.update(
            sha256=digest,
            source_observed_at=entry["retrieved_at"],
            revision=json.loads(raw)["document"]["tracking"].get("version"),
        )
        # The new raw receipt owns this normalization, never old revision/hash metadata.
        identity = (record["vendor"], record["advisory_id"], url)
        if identity in refreshed:
            raise ValueError("Duplicate raw source identity")
        refreshed[identity] = record
        inventory = entry.get("inventory", {})
        notes = inventory.get("candidate_notes", [])
        receipts.append(
            dict(
                table_header_lead=any(n.get("first_fixed_header_present") for n in notes),
                source_url=capture_url,
                retained_source_url=url,
                sha256=digest,
                source_observed_at=entry["retrieved_at"],
                first_fixed_units=len(record.get("first_fixed", [])),
                parser_issues=[w for w in record.get("warnings", []) if "first-fixed" in w],
            )
        )
    merged = []
    for record in records:
        key = (record["vendor"], record["advisory_id"], record.get("source_url"))
        merged.append(refreshed.pop(key, record))
    merged.extend(refreshed.values())
    report = build_report(
        merged,
        api_results=[],
        publication={"raw_source_manifest": sha256(manifest_raw).hexdigest()},
        generated_at=generated_at,
    )
    validate_report(report)
    receipt = dict(
        manifest_sha256=sha256(manifest_raw).hexdigest(),
        raw_sources_verified=len(receipts),
        unavailable=unavailable,
        source_receipts=receipts,
        received_bytes_replayed=total,
        network_requests=0,
        input_records=len(records),
        output_records=len(merged),
    )
    return report, receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--generated-at", required=True)
    args = parser.parse_args(argv)
    opener = gzip.open if args.records.suffix == ".gz" else open
    with opener(args.records, "rt") as stream:
        records = json.load(stream)
    report, receipt = replay(records, args.manifest, args.generated_at)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    args.output.with_suffix(".receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(
        json.dumps(
            {
                "validation": report["validation"],
                "raw_sources_verified": receipt["raw_sources_verified"],
                "unavailable": len(receipt["unavailable"]),
            }
        )
    )


if __name__ == "__main__":
    main()
