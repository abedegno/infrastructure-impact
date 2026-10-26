"""Declared negative boundaries and lossless revision comparison."""

from infrastructure_impact.application.evaluation import evaluate
from infrastructure_impact.storage.repository import semantic_diff


def test_correct_claim_cannot_mask_forbidden_extra_claim():
    case = dict(
        id="test",
        vendor="example",
        source_url="https://example.test/a",
        cve_id="CVE-2025-12345",
        product_pattern="^Router$",
        expected_status="unaffected",
        forbidden_statuses=["affected"],
    )
    definition = dict(cases=[case], limitations=[])
    claim = dict(
        cve_id=case["cve_id"],
        product="Router",
        status="unaffected",
        scope="cve_specific",
        versions=[],
    )
    record = dict(
        vendor="example",
        source_url=case["source_url"],
        sha256="abc",
        assessments=[claim, {**claim, "status": "affected"}],
    )
    result = evaluate([record], definition=definition)
    assert result["passed"] == 0
    assert result["cases"][0]["outcome"] == "forbidden_claim"
    assert result["forbidden_claim_count"] == 1
    assert result["global_precision"] is None
    record["assessments"][1]["product"] = "Other router"
    assert evaluate([record], definition=definition)["passed"] == 1


def test_disappearing_version_branch_is_visible_and_order_is_irrelevant():
    affected = dict(
        cve_id="CVE-2025-12345", product_id="router", status="affected", versions=["1.x"]
    )
    fixed = {**affected, "status": "fixed", "versions": ["2.x"]}
    before = dict(assessments=[affected, fixed])
    assert not semantic_diff(before, dict(assessments=[fixed, affected]))
    delta = semantic_diff(before, dict(assessments=[fixed]))
    assert len(delta) == 1
    assert affected in delta[0]["before"]
    assert affected not in delta[0]["after"]
    assert fixed in delta[0]["after"]
