"""Regenerate comparable counts and coverage from the evidence store."""

import csv
import json
from collections import Counter
from contextlib import closing

from ..settings import Paths
from ..storage.repository import connect, latest, now
from .cohort import COHORT, coverage
from .comparison import compare


def report():
    root = Paths.from_env().home
    (root / "benchmark").mkdir(parents=True, exist_ok=True)
    with closing(connect(read_only=True)) as db:
        records = latest(db)
        pairs = coverage(db, records)
        comparison = compare(records, COHORT)
    result = {"generated_at": now(), "cohort": COHORT, "pairs": pairs}
    (root / "benchmark/cohort-coverage.json").write_text(json.dumps(result, indent=2) + "\n")
    with (root / "benchmark/cohort-coverage.csv").open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "vendor",
                "cve_id",
                "component",
                "state",
                "advisory_sources",
                "checked_scopes",
            ],
        )
        writer.writeheader()
        for p in pairs:
            writer.writerow(
                {
                    **{k: p[k] for k in ("vendor", "cve_id", "component", "state")},
                    "advisory_sources": " | ".join(p["advisory_sources"]),
                    "checked_scopes": " | ".join(c["scope"] for c in p["checks"]),
                }
            )
    lines = [
        "Infrastructure Impact benchmark — " + result["generated_at"],
        "",
        f"Purposive sample: {len(COHORT)} CVEs / {len(set(COHORT.values()))} component families / {len(comparison['vendors'])} vendors / {len(pairs)} vendor-CVE pairs.",
        "Not a representative vendor security ranking. Counts overlap across products.",
        f"Collected {len(records)} advisory/release-note records and {len({c for r in records for c in r['cves']})} distinct CVEs.",
        "Coverage: " + json.dumps(dict(Counter(p["state"] for p in pairs))),
        "",
        "Vendor\tAssessed/11\tAny affected\tAny unaffected\tFixed release reported",
    ]
    lines += [
        "\t".join(
            map(
                str,
                [
                    r["name"],
                    r["assessed_cves"],
                    r["affected_cves"],
                    r["unaffected_cves"],
                    r["fixed_cves"],
                ],
            )
        )
        for r in comparison["vendors"]
    ]
    lines += [
        "",
        *comparison["limitations"],
        "",
        "Scope: current feed windows, full current Aruba CSAF index within cap 200,",
        "Check Point active product index, upstream CVE reference sets, curated historical documents.",
        "No-match refers to the exact searched source and is never an unaffected assessment.",
        "Public Check Point SK embedded JSON supplements abbreviated index rows.",
        "Vendor product exceptions, dependency presence and configuration qualifications remain visible.",
        "Cisco curl bulletin explicitly excludes the second CVE mentioned in its background.",
        "Fixed-release statements do not infer affected ranges for earlier firmware.",
        "",
        "HPE timing research: see benchmark/hpe-timing-investigation.txt.",
        "No verified silent-fix or intentional-concealment finding.",
        "Existing aggregator comparison: benchmark/report.txt and benchmark/results.csv.",
        "Validation receipt: data/validation.json.",
    ]
    (root / "benchmark/cohort-report.txt").write_text("\n".join(lines) + "\n")
    return result
