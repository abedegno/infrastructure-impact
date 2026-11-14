"""Reproduce authored compact vectors against the offline native oracle; no sources.

Run with packaged IMPACT_SOURCES and PYTHONPATH=$PWD:$PWD/tests, --check in CI.
"""

import argparse
import copy
import json
from pathlib import Path

from test_switching_upgrades import AT, inputs

from infrastructure_impact.adapters.cvss import public_metrics
from infrastructure_impact.application import first_fixed
from infrastructure_impact.application import switching_analysis as analysis
from infrastructure_impact.application import switching_comparison as comparison
from infrastructure_impact.application import switching_evidence as evidence
from infrastructure_impact.application import switching_upgrades as upgrades


def produce():
    raw, _, kev = inputs([("2024-12-31", ["17.15.3"]), ("2025-02-01", ["17.15.2"]), (None, [])])
    raw["claims"][1]["cve_id"] = "CVE-2025-99999"
    raw["claims"][1]["remediations"][0]["scope_binding"]["cve_id"] = "CVE-2025-99999"
    for claim, value in zip(raw["claims"], [10.0, 7.5], strict=False):
        claim["scores"] = public_metrics(
            [
                dict(
                    system="CVSS",
                    version="3.1",
                    value=value,
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                    if value == 10.0
                    else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cve_id=claim["cve_id"],
                    product_ids=[],
                    scope="cve_specific",
                    source=claim["source"],
                    origin="vendor_advisory",
                    validation="valid",
                    provider="Cisco",
                )
            ]
        )
    ev = evidence.project(raw, publication=None, generated_at=AT)
    study = comparison.build_report(
        ev,
        kev,
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end=AT[:10],
    )
    compiled = analysis.build_report([], [], study)
    ff = first_fixed.build_report([], api_results=[], publication=None, generated_at=AT)
    native = upgrades.build_report(ev, ff, None, kev, publication=None, generated_at=AT)
    assert {
        f["value"]
        for m in compiled["requirements"]["members"].values()
        for f in compiled["requirements"]["facts"][m["severity_facets_ref"]]
    } == {10.0, 7.5}
    cases = []
    for name, options in [
        ("all_vendors", {}),
        ("pre_window_state", dict(vendor="cisco", window="2025")),
        ("previously_redundant", dict(vendor="cisco", window="2025", cve_ids=["CVE-2025-99999"])),
        ("model_qualified", dict(vendor="cisco", window="2025", scope_level="model_qualified")),
        ("unknown_dates", dict(vendor="cisco", window="undated")),
        ("empty_cves", dict(cve_ids=[])),
    ]:
        selected = comparison.select_report(study, **options, evaluated_at=AT)
        context = analysis.selection_context(compiled, options)
        result = analysis.select_report(compiled, context)
        assert result["upgrades"] == analysis.project_native(native, selected), name
        assert (
            list(analysis.detailed_rows(result["upgrades"]))
            == upgrades.select_report(native, selected)["rows"]
        ), name
        cases.append(
            dict(
                name=name,
                options=options,
                context=context,
                expected=result,
                detailed_rows=list(analysis.detailed_rows(result["upgrades"])),
                upgrades_csv=analysis.csv_export(result["upgrades"]),
                analysis_csv=analysis.analysis_csv_export(result),
            )
        )
    # Serialization-only boundary fixtures: typed selected disclosure cell numbers.
    numeric = copy.deepcopy(cases[1]["expected"])
    for pair, value in zip(numeric["disclosure"]["pairs"], [10.0, 7.5]):
        pair["umbrella"] = dict(
            cve_id=pair["cve_id"],
            cwe_id="CWE-20",
            highest_cvss=value,
            locator="authored numeric CSV boundary",
        )
    numeric_cases = []
    for value in (10.0, 8.6, 1e-7, 2 / 3, -0.0):
        selected_numeric = copy.deepcopy(numeric)
        selected_numeric["disclosure"]["pairs"][0]["umbrella"]["highest_cvss"] = value
        numeric_cases.append(
            dict(selected=selected_numeric, expected=analysis.analysis_csv_export(selected_numeric))
        )
    return dict(
        schema_version=1,
        compiled=compiled,
        cases=cases,
        numeric_csv=dict(selected=numeric, expected=analysis.analysis_csv_export(numeric)),
        numeric_cases=numeric_cases,
        numeric_fingerprints=[
            dict(value=value, sha256=evidence.definition_sha256(value))
            for value in [
                {"cvss": 10.0},
                {"cvss": 7.5},
                {"calibration_rate": 2 / 3},
                {"zero": -0.0},
            ]
        ],
    )


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = Path(__file__).resolve().parents[1] / "tests/fixtures/switching-analysis-vectors.json"
    encoded = json.dumps(produce(), ensure_ascii=False, separators=(",", ":")) + "\n"
    if args.check:
        assert path.read_text() == encoded, "Compact vectors differ; regenerate and review"
    else:
        path.write_text(encoded)


if __name__ == "__main__":
    main()
