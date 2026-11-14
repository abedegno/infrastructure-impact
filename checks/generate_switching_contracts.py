"""Refresh the offline browser schema bundle; no runtime dependencies or network."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "infrastructure_impact"
NAMES = (
    "switching-study-v1.json",
    "switching-evidence-v1.json",
    "switching-comparison-v1.json",
    "switching-summary-v1.json",
    "switching-inputs-v1.json",
    "kev-v1.json",
    "static-index-v1.json",
    "static-index-v2.json",
    "publication-v2.json",
    "switching-overview-v2.json",
    "switching-row-sources-v1.json",
    "current-evidence-v1.json",
    "switching-release-history-v1.json",
    "switching-analysis-v1.json",
    "customer-comparison-v1.json",
)


def payload():
    definition = json.loads((ROOT / "resources/switching-study.json").read_text())
    canonical = json.dumps(
        definition, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    from infrastructure_impact.application import customer_comparison, switching_releases
    from infrastructure_impact.references.registry import SOURCES
    from infrastructure_impact.remediation_bindings import definition as reviewed_definition

    return dict(
        reviewed_remediation_bindings=reviewed_definition(),
        customer_limitations=customer_comparison.LIMITATIONS,
        customer_fields=customer_comparison.CUSTOMER_FIELDS,
        release_method=switching_releases.METHOD,
        release_sources={key: SOURCES[key].url for key in switching_releases.SOURCE_IDS},
        study_definition=definition,
        schemas={name: json.loads((ROOT / "schemas" / name).read_text()) for name in NAMES},
        definition_sha256=hashlib.sha256(canonical).hexdigest(),
    )


if __name__ == "__main__":
    target = ROOT / "web/switching-contracts.js"
    before, rest = target.read_text().split("/* BEGIN GENERATED CONTRACTS */", 1)
    _, after = rest.split("/* END GENERATED CONTRACTS */", 1)
    target.write_text(
        before
        + "/* BEGIN GENERATED CONTRACTS */ "
        + json.dumps(payload(), ensure_ascii=False, separators=(",", ":"))
        + "; /* END GENERATED CONTRACTS */"
        + after
    )
