"""Public phase-one findings stay reproducible, scoped and unreviewed."""

from infrastructure_impact.application import release_reliability as reliability


def test_packaged_unique_records_preserve_every_pinned_observation_and_replay_preview():
    import json
    from collections import Counter
    from pathlib import Path

    from checks.build_release_catalogue import build_catalogue
    from checks.release import LEAKS

    root = Path(__file__).resolve().parents[1]
    old = build_catalogue()
    packaged = json.loads(
        (root / "infrastructure_impact/resources/release-catalogue.json").read_text()
    )
    original = [r for row in packaged["releases"] for r in row.get("observations", [row])]

    def canonical(rows):
        return Counter(json.dumps(r, sort_keys=True) for r in rows)

    assert canonical(original) == canonical(old["releases"])
    assert len(packaged["releases"]) == 40
    assert Counter(r["vendor"] for r in packaged["releases"]) == {
        "cisco": 8,
        "aruba": 24,
        "arista": 8,
    }
    for field in ("sources", "notices", "statements", "coverage"):
        assert packaged[field] == old[field]
    preview = json.loads(
        (root / "docs/research/2026-11-27-reliability-corrections-preview.json").read_text()
    )
    assert (
        reliability.build_report(publication=None, generated_at=preview["generated_at"]) == preview
    )
    aruba = next(r for r in preview["annual"] if r["vendor"] == "aruba" and r["year"] == 2024)
    assert aruba["metrics"]["possible_respin_90"]["observed_count"] == 2
    assert aruba["metrics"]["possible_respin_30"]["observed_count"] is None
    assert all(m["rate"] is None for r in preview["annual"] for m in r["metrics"].values())
    assert preview["upgrade_selection"] is None and preview["upgrade_annotations"] == []
    review = json.loads(
        (root / "docs/research/2026-11-27-reliability-corrections-review.json").read_text()
    )
    assert review["items"] == preview["review_packet"] and len(review["items"]) == 11
    for path in (root / "docs/research").glob("2026-11-27-reliability-*"):
        assert not LEAKS.search(path.read_text()), path.name


def test_version_gap_findings_keep_fix_literals_and_unknown_dates_separate():
    import json
    from pathlib import Path

    from infrastructure_impact.source_policy import allowed

    root = Path(__file__).resolve().parents[1]
    packet = json.loads(
        (root / "docs/research/2026-11-27-reliability-version-gaps.json").read_text()
    )
    assert packet["review_status"] == "independent_human_review_pending"
    for source in packet["sources"]:
        assert allowed(source["source_url"], source["vendor"])
        assert (source["capture_kind"] == "original_document") == bool(source["original_sha256"])
        assert source["original_sha256"] or source["excerpt_sha256"]
    assert {version for f in packet["findings"] for version in f["versions"]} == {
        "17.12.7",
        "17.12.7a",
        "10.13.1031",
        "10.13.1161",
    }
    for finding in packet["findings"]:
        assert finding["release_date"] is None and finding["action_date"] is None
        assert finding["analysis_extraction_defect_found"] is False
    for finding in packet["findings"][1:]:
        assert finding["platforms_stated"] == []
        assert finding["versions"][0] in finding["evidence"][0]["quote"]
