"""Comparison work should scale with assessments, not assessments times CVEs."""

from infrastructure_impact.application.comparison import compare
from infrastructure_impact.application.scorecards import scorecards


def test_comparison_groups_a_large_cohort_without_repeated_assessment_scans():
    reads = []

    class Assessment(dict):
        def __getitem__(self, key):
            if key == "cve_id":
                reads.append(None)
            return super().__getitem__(key)

    cohort = [f"CVE-2026-{i:05d}" for i in range(100)]
    assessments = [
        Assessment(cve_id=cohort[i % 100], status="affected", scope="cve_specific", product="p")
        for i in range(500)
    ]
    result = compare(
        [dict(vendor="acme", cves=cohort, assessments=assessments)],
        cohort,
        vendors={"acme": "Acme"},
    )
    assert result["vendors"][0]["affected_cves"] == 100
    assert result["vendors"][0]["product_labels"] == 1
    assert len(reads) < 6 * len(assessments) + 10 * len(cohort)


def test_comparison_keeps_overlapping_states_and_draft_cohort_membership():
    a, b, c = [f"CVE-2026-{i:05d}" for i in range(3)]
    records = [
        dict(
            vendor="acme",
            cves=[a, b],
            assessments=[
                dict(cve_id=a, product="p", status="affected", scope="bulletin_shared"),
                dict(cve_id=a, product="q", status="unaffected", scope="cve_specific"),
                dict(cve_id=b, product="p", status="recommended", scope="cve_specific"),
            ],
        ),
        dict(
            vendor="acme",
            cves=[c],
            document_status="draft",
            assessments=[
                dict(cve_id=c, product="r", status="affected", scope="cve_specific"),
            ],
        ),
    ]
    result = compare(records, vendors={"acme": "Acme", "other": "Other"})
    row = result["vendors"][0]
    assert result["cohort"] == [a, b, c]
    assert result["draft_advisories_excluded"] == 1
    assert (row["assessed_cves"], row["affected_cves"], row["unaffected_cves"]) == (1, 1, 1)
    assert (row["explicit_affected_cves"], row["shared_bulletin_affected_cves"]) == (0, 1)
    assert row["no_assessment_in_dataset"] == 2
    assert not result["vendors"][1]["has_imported_advisories"]


def test_scorecards_group_claims_once_and_preserve_declared_source_membership():
    reads = []

    class Assessment(dict):
        def __getitem__(self, key):
            if key == "cve_id":
                reads.append(None)
            return super().__getitem__(key)

    cohort = [f"CVE-2026-{i:05d}" for i in range(100)]
    assessments = [
        Assessment(cve_id=cohort[i % 100], status="affected", scope="cve_specific", product="p")
        for i in range(500)
    ]
    document = scorecards(
        [
            dict(
                vendor="acme",
                cves=cohort[:50],
                assessments=assessments,
                source_url="https://example.com/advisory",
            )
        ],
        [],
        {},
        [],
        cohort,
        {"acme": "Acme"},
        "2026-11-07T00:00:00Z",
    )
    card = document["vendors"][0]
    assert card["with_statement"] == 100
    assert sum(case["statement_count"] for case in card["cases"]) == 500
    assert card["cases"][0]["source_urls"] == ["https://example.com/advisory"]
    assert card["cases"][99]["source_urls"] == []
    assert len(reads) < 6 * len(assessments) + 10 * len(cohort)
