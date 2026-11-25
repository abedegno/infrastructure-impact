"""Release checks augment switching validation without rewriting extraction results."""

from copy import deepcopy

import pytest

from infrastructure_impact.application.switching_validation import attach_release_reliability


def test_release_checks_keep_extraction_counts_and_human_status():
    from infrastructure_impact.application.release_reliability import build_report

    evidence = build_report(
        publication={"id": "a" * 32, "advisory_schema_version": 2},
        generated_at="2026-11-26T00:00:00Z",
    )
    original = {
        "summary": {"pass": 3, "source_missing": 2},
        "cases": [{"id": "sample", "outcome": "pass"}],
        "review_status": "independent_review_pending",
    }
    saved = deepcopy(original)
    result = attach_release_reliability(original, evidence)
    assert original == saved
    assert result["summary"] == saved["summary"] and result["cases"] == saved["cases"]
    assert result["review_status"] == saved["review_status"]
    assert result["release_reliability"]["review_status"] == "independent_human_review_pending"
    assert result["release_reliability"]["catalogue_sha256"] == evidence["catalogue_sha256"]
    assert result["release_reliability"]["publication"] == evidence["publication"]


def test_release_validation_rejects_mixed_existing_generation():
    from infrastructure_impact.application.release_reliability import build_report

    evidence = build_report(
        publication={"id": "a" * 32, "advisory_schema_version": 2},
        generated_at="2026-11-26T00:00:00Z",
    )
    with pytest.raises(ValueError):
        attach_release_reliability(
            {"publication": {"id": "b" * 32, "advisory_schema_version": 2}}, evidence
        )
