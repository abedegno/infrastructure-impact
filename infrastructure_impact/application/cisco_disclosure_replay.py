"""Explicit cached-source replay; no HTTP, default database, or publication writes."""

import argparse
import json
from hashlib import sha256
from pathlib import Path

from ..adapters.standards import csaf
from ..settings import PACKAGE
from ..storage.repository import connect, ingest, latest
from . import kev, switching_comparison, switching_disclosure, switching_evidence

CASES = json.loads((PACKAGE / "resources/cisco-disclosure-validation.json").read_text())["cases"]


def validate_cases(records):
    """Check source-pinned source facts on materialized records, without accepting review."""
    results = []
    for case in CASES:
        matches = [r for r in records if r["advisory_id"] == case["advisory_id"]]
        state = "not_replayed"
        if matches:
            r = matches[0]
            if r["sha256"] != case["sha256"]:
                state = "different_capture"
            else:
                m = r.get("disclosure_metadata", {})
                bundle = m.get("bundle") or {}
                state = (
                    "passed"
                    if all(
                        (
                            r["published_at"] == case["initial_published_at"],
                            {u["cve_id"]: u["cwe_id"] for u in m.get("umbrella_cves", [])}
                            == case["cwe_by_cve"],
                            m.get("highest_cvss_wording") == case["highest_cvss_wording"],
                            m.get("bug_count") is None,
                            m.get("bug_count_status") == "not_disclosed",
                            bundle.get("advisory_ids") == [case["advisory_id"]],
                            bundle.get("cve_ids") == sorted(case["cwe_by_cve"]),
                            bundle.get("initial_published_at") == case["initial_published_at"],
                        )
                    )
                    else "failed"
                )
        results.append(
            dict(
                advisory_id=case["advisory_id"], automated_validation=state, human_review="pending"
            )
        )
    return results


def replay(
    manifest_path,
    policy_receipt_path,
    *,
    generated_at,
    bundle_history_path=None,
    checkpoint_path=None,
):
    """Read verified caller-owned public captures and use isolated in-memory storage."""
    manifest_raw = Path(manifest_path).read_bytes()
    manifest = json.loads(manifest_raw)
    captures = []
    total = 0
    for entry in manifest["entries"]:
        path = entry.get("durable_raw_path") or entry.get("raw_path")
        if not path or entry.get("outcome") not in ("captured", "reused_exact_hash"):
            raise ValueError("Cisco cached capture unavailable")
        raw = Path(path).read_bytes()
        total += len(raw)
        if (
            len(raw) > 8000000
            or total > 250000000
            or sha256(raw).hexdigest() != entry["response_sha256"]
        ):
            raise ValueError("Cisco capture size or hash mismatch")
        captures.append((entry, raw))
    receipt = json.loads(Path(policy_receipt_path).read_text())
    policy_raw = Path(receipt["path"]).read_bytes()
    if sha256(policy_raw).hexdigest() != receipt["sha256"] or len(policy_raw) != receipt["bytes"]:
        raise ValueError("Cisco policy capture mismatch")
    policy = dict(
        url=receipt["source_url"], sha256=receipt["sha256"], retrieved_at=receipt["retrieved_at"]
    )
    history = json.loads(Path(bundle_history_path).read_text()) if bundle_history_path else None
    with connect(":memory:") as db:
        for entry, raw in captures:
            url = entry.get("capture_source_url", entry["source_url"])
            ingest(db, raw, url, csaf, "cisco")
            # In this explicit scratch replay, preserve each actual capture time;
            # normalization/ingestion timestamps remain new local observations.
            db.execute(
                "UPDATE evidence SET observed_at=? WHERE source_url=? AND sha256=?",
                (entry["retrieved_at"], url, entry["response_sha256"]),
            )
        records = latest(db)
        e = switching_evidence.project(
            switching_evidence.inputs(db, records), publication=None, generated_at=generated_at
        )
    selected = switching_comparison.select_report(
        switching_comparison.build_report(
            e,
            kev.build_report({}, [], publication=None, generated_at=generated_at),
            definition=switching_evidence.definition(),
            publication=None,
            generated_at=generated_at,
            observation_end=generated_at[:10],
        ),
        vendor="cisco",
        evaluated_at=generated_at,
    )
    if checkpoint_path is not None:
        Path(checkpoint_path).write_text(
            json.dumps(dict(records=records, evidence=e, selection=selected))
        )
    report = switching_disclosure.build_report(
        records,
        selected,
        evidence=e,
        publication=None,
        generated_at=generated_at,
        policy_source=policy,
        bundle_history=history,
    )
    validations = validate_cases(records)
    if any(c["automated_validation"] == "failed" for c in validations):
        raise ValueError("Source-pinned Cisco disclosure validation failed")
    return dict(
        manifest_sha256=sha256(manifest_raw).hexdigest(),
        verified_raw_sources=len(captures),
        verified_bytes=total,
        normalized_records=len(records),
        finalized_claims=len(e["claims"]),
        validation_cases=validations,
        report=report,
        corpus_basis=manifest.get("corpus_basis"),
        limitations=[
            "Cached old-identity corpus is not a complete Cisco archive.",
            "New local analysis generation; no immutable upstream publication is relabelled.",
        ],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--policy-receipt", type=Path, required=True)
    parser.add_argument("--bundle-history", type=Path)
    parser.add_argument("--generated-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path)
    args = parser.parse_args()
    result = replay(
        args.manifest,
        args.policy_receipt,
        generated_at=args.generated_at,
        bundle_history_path=args.bundle_history,
        checkpoint_path=args.checkpoint,
    )
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "verified_raw_sources",
                    "normalized_records",
                    "finalized_claims",
                    "validation_cases",
                )
            }
        )
    )


if __name__ == "__main__":
    main()
