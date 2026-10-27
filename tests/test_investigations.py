"""Assistant dispositions are dated, exact-source-bound and never human review."""

import json
from copy import deepcopy

from infrastructure_impact.application.investigations import investigation
from infrastructure_impact.settings import PACKAGE


def lead(item):
    return dict(
        vendor=item["vendor"],
        kind=item["kind"],
        cve_ids=item["cve_ids"],
        details=item["required_detail_token"] or "Synthetic chronology context",
        evidence=deepcopy(item["source_bindings"]),
    )


def test_three_research_dispositions_require_exact_current_source_sets():
    spec = json.loads((PACKAGE / "resources/disclosure-investigations.json").read_text())
    assert len(spec["investigations"]) == 3
    for item in spec["investigations"]:
        row = lead(item)
        result = investigation(row)
        assert result["disposition"] == item["disposition"]
        assert result["source_state"] == "matches_reviewed_sources"
        assert result["independent_human_review_completed"] is False
        assert result["concealment"] == "not_established"
        row["evidence"][0]["source_sha256"] = "0" * 64
        changed = investigation(row)
        assert changed["disposition"] == "source_changed_review_required"
        assert changed["summary"] != result["summary"]
        row = lead(item)
        row["evidence"].append(
            {
                "source_url": item["source_bindings"][0]["source_url"] + "/new",
                "source_sha256": "b" * 64,
            }
        )
        assert investigation(row)["source_state"] == "source_changed_review_required"


def test_unlinked_defect_requires_exact_bug_token_and_cve_cohort():
    items = json.loads((PACKAGE / "resources/disclosure-investigations.json").read_text())[
        "investigations"
    ]
    item = next(i for i in items if i["required_detail_token"])
    for text in ["9685140", "1968514", "unrelated overflow"]:
        row = lead(item)
        row["details"] = text
        assert investigation(row) is None
    row = lead(item)
    row["cve_ids"] = ["CVE-2024-6387"]
    assert investigation(row) is None
