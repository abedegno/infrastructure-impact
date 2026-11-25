"""The production browser adapter must match native selected evidence and CSV."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from infrastructure_impact.application import release_reliability as rr

ROOT = Path(__file__).resolve().parents[1]


def test_browser_release_reliability_parity(tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is unavailable")
    publication = {"id": "release-ui", "advisory_schema_version": 2}
    report = rr.build_report(publication=publication, generated_at="2026-11-25T18:00:00Z")
    upgrades = dict(
        publication=publication,
        generated_at=report["generated_at"],
        selection={"window": "all"},
        rows=[
            dict(
                vendor="cisco",
                train="17.12",
                scenario=scenario,
                policy="all_affected",
                events=[dict(date="2024-03-27", target="17.12.3")],
            )
            for scenario in ["publisher_first_fixed", "known_fixed_target"]
        ],
    )
    selected = rr.with_upgrades(report, upgrades)
    path = tmp_path / "vectors.json"
    path.write_text(
        json.dumps(
            dict(report=report, upgrades=upgrades, selected=selected, csv=rr.csv_export(selected))
        )
    )
    subprocess.run([node, "tests/test_release_reliability_ui.js", str(path)], cwd=ROOT, check=True)


@pytest.mark.parametrize(
    "models", [None, ["Catalyst 9200"], ["Catalyst 9500"], ["Catalyst 9200", "Catalyst 9300"]]
)
def test_browser_notice_chronology_and_model_scope(tmp_path, models):
    from test_release_catalogue import config, release, specimen
    from test_release_reliability import action, selected

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is unavailable")
    catalogue = specimen()
    catalogue["releases"] = [release("17.12.7", "2024-12-25"), release("17.12.7a", "2025-01-10")]
    catalogue["statements"] = [action()]
    upgrades = selected(models)
    report = rr.build_report(
        catalogue,
        config(),
        publication=upgrades["publication"],
        generated_at=upgrades["generated_at"],
    )
    enriched = rr.with_upgrades(report, upgrades)
    path = tmp_path / "vectors.json"
    path.write_text(
        json.dumps(
            dict(report=report, upgrades=upgrades, selected=enriched, csv=rr.csv_export(enriched))
        )
    )
    subprocess.run([node, "tests/test_release_reliability_ui.js", str(path)], cwd=ROOT, check=True)


def test_browser_complete_signal_rate_parity(tmp_path):
    from test_release_catalogue import config, release, specimen
    from test_release_reliability import action, complete_coverage, selected

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is unavailable")
    catalogue = specimen()
    catalogue["releases"] = [release("17.12.7", "2024-12-25"), release("17.12.7a", "2025-01-10")]
    catalogue["statements"] = [action(action_date="2025-01-15")]
    catalogue["coverage"] = [complete_coverage()]
    upgrades = selected()
    report = rr.build_report(
        catalogue,
        config(),
        publication=upgrades["publication"],
        generated_at=upgrades["generated_at"],
    )
    enriched = rr.with_upgrades(report, upgrades)
    path = tmp_path / "vectors.json"
    path.write_text(
        json.dumps(
            dict(report=report, upgrades=upgrades, selected=enriched, csv=rr.csv_export(enriched))
        )
    )
    subprocess.run([node, "tests/test_release_reliability_ui.js", str(path)], cwd=ROOT, check=True)


@pytest.mark.parametrize(
    "variant", ["undated", "empty_scope", "disjoint", "partial_models", "future_period"]
)
def test_browser_notice_signal_completeness(tmp_path, variant):
    from test_release_catalogue import config, evidence, specimen
    from test_release_reliability import complete_coverage, selected

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is unavailable")
    catalogue, configuration = specimen(), config()
    judgement = complete_coverage()
    judgement.update(status="partial", enumeration_complete=False, date_coverage_complete=False)
    catalogue["coverage"] = [judgement]
    catalogue["notices"] = [
        dict(
            vendor="cisco",
            family="IOS XE",
            train="17.12",
            notice_id="FN1",
            title="Notice",
            notice_date=None,
            action_date=None,
            affected_releases=["17.12.7"],
            platforms_stated=["Catalyst 9200"],
            replacement_release=None,
            classification="software_defect",
            evidence=evidence(),
        )
    ]
    if variant == "empty_scope":
        catalogue["notices"][0]["platforms_stated"] = []
    elif variant == "disjoint":
        catalogue["notices"][0]["platforms_stated"] = ["Catalyst 9500"]
    elif variant == "partial_models":
        catalogue["notices"] = []
        judgement["platforms"] = ["Catalyst 9200"]
    elif variant == "future_period":
        catalogue["notices"] = []
        configuration["end"] = "2027-12-31"
        judgement["year"] = 2027
    upgrades = selected()
    report = rr.build_report(
        catalogue,
        configuration,
        publication=upgrades["publication"],
        generated_at=upgrades["generated_at"],
    )
    enriched = rr.with_upgrades(report, upgrades)
    path = tmp_path / "vectors.json"
    path.write_text(
        json.dumps(
            dict(report=report, upgrades=upgrades, selected=enriched, csv=rr.csv_export(enriched))
        )
    )
    subprocess.run([node, "tests/test_release_reliability_ui.js", str(path)], cwd=ROOT, check=True)


def test_browser_multi_model_respin_order(tmp_path):
    from test_release_catalogue import config, release, specimen
    from test_release_reliability import selected

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is unavailable")
    catalogue = specimen()
    models = ["Catalyst 9300", "Catalyst 9200"]
    catalogue["releases"] = [
        release("17.12.7", "2024-12-25", platforms=models),
        release("17.12.7a", "2025-01-10", platforms=models),
    ]
    upgrades = selected(models)
    report = rr.build_report(
        catalogue,
        config(),
        publication=upgrades["publication"],
        generated_at=upgrades["generated_at"],
    )
    enriched = rr.with_upgrades(report, upgrades)
    path = tmp_path / "vectors.json"
    path.write_text(
        json.dumps(
            dict(report=report, upgrades=upgrades, selected=enriched, csv=rr.csv_export(enriched))
        )
    )
    subprocess.run([node, "tests/test_release_reliability_ui.js", str(path)], cwd=ROOT, check=True)


def test_browser_unknown_action_scope_blocks_complete_zero(tmp_path):
    from test_release_catalogue import config, release, specimen
    from test_release_reliability import action, complete_coverage, selected

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is unavailable")
    catalogue = specimen()
    catalogue["releases"] = [release("17.12.7", "2025-01-01")]
    catalogue["statements"] = [action()]
    catalogue["statements"][0]["platforms_stated"] = []
    catalogue["coverage"] = [complete_coverage()]
    upgrades = selected()
    report = rr.build_report(
        catalogue,
        config(),
        publication=upgrades["publication"],
        generated_at=upgrades["generated_at"],
    )
    enriched = rr.with_upgrades(report, upgrades)
    path = tmp_path / "vectors.json"
    path.write_text(
        json.dumps(
            dict(report=report, upgrades=upgrades, selected=enriched, csv=rr.csv_export(enriched))
        )
    )
    subprocess.run([node, "tests/test_release_reliability_ui.js", str(path)], cwd=ROOT, check=True)
