"""Authored typed-source cases; exact public bytes are checked in the audit replay."""

import copy

import pytest
from test_reviewed_remediation_bindings import SAMPLES, extracted, projected
from test_switching_aruba_fix_links import browser, native_stream

from infrastructure_impact.application import switching_evidence as evidence
from infrastructure_impact.application import switching_releases as releases
from infrastructure_impact.application import switching_upgrades as upgrades

SAMPLE = next(s for s in SAMPLES if s["advisory_id"] == "ARUBA-PSA-2022-004")
PAIRS = [
    (">=10.09.0000|<=10.09.0002", "10.09.0010", "10.9"),
    (">=10.08.0000|<=10.08.0130", "10.08.1040", "10.8"),
    (">=10.07.0000|<=10.07.0050", "10.07.0061", "10.7"),
]


def affected(result):
    return [
        c for c in result["claims"] if c["cve_id"] == "CVE-2021-41002" and c["status"] == "affected"
    ]


def test_direct_owned_upgrade_literals_supply_same_train_targets_without_rewriting_evidence():
    claims = affected(extracted(SAMPLE))
    original = SAMPLE["data"]["vulnerabilities"][15]["remediations"][0]
    for pid, literal, train in PAIRS:
        claim = next(c for c in claims if c["product_id"] == pid)
        rem = claim["remediations"][0]
        assert rem["version_expressions"] == [literal]
        assert rem["details"] == original["details"]
        assert rem["product_ids"] == [pid]
        assert rem["availability_date"] == original["date"]
        assert rem["source"]["source_locator"] == "/vulnerabilities/15/remediations/0"
        assert "scope_binding" not in rem
        candidates, issues = releases._claim_candidates(claim, "2026-11-14")
        assert not issues
        assert [(c[0], c[1], c[2]) for c in candidates] == [
            ("affected_scope_fix", literal, "explicit_product_id")
        ]
        assert upgrades._affected_trains(claim)[0] == {train}
    cross_train = next(c for c in claims if c["product_id"] == ">=10.00.0000|<=10.06.0170")
    assert cross_train["remediations"][0]["version_expressions"] == []
    assert releases._claim_candidates(cross_train, "2026-11-14") == ([], [])
    assert upgrades._affected_trains(cross_train)[1]["partial"] is True


@pytest.mark.parametrize(
    "mutation",
    ["hash", "url", "details", "date", "cve", "scope", "duplicate", "expression", "product"],
)
def test_source_or_tuple_drift_never_authorizes_direct_targets(mutation):
    data = copy.deepcopy(SAMPLE["data"])
    vuln = data["vulnerabilities"][15]
    kwargs = {}
    if mutation == "hash":
        kwargs["digest"] = "0" * 64
    elif mutation == "url":
        kwargs["url"] = SAMPLE["source_url"] + "?changed"
    elif mutation == "details":
        vuln["remediations"][0]["details"] += "\nAdditional scope qualification."
    elif mutation == "date":
        vuln["remediations"][0]["date"] = "2027-01-01T00:00:00Z"
    elif mutation == "cve":
        vuln["cve"] = "CVE-2021-41003"
    elif mutation == "scope":
        vuln["remediations"][0]["product_ids"] = []
    elif mutation == "duplicate":
        vuln["remediations"].append(copy.deepcopy(vuln["remediations"][0]))
    elif mutation == "expression":
        data["product_tree"]["branches"][0]["branches"][0]["branches"][4]["name"] = (
            "vers:semver/>=10.09.0000|<=10.09.0003"
        )
    elif mutation == "product":
        data["product_tree"]["branches"][0]["branches"][0]["branches"][4]["product"]["name"] = (
            "Other product"
        )
    result = extracted(SAMPLE, data, **kwargs)
    claims = [
        c
        for c in result["claims"]
        if c["source"]["source_locator"].startswith("/vulnerabilities/15/")
    ]
    if mutation in {"expression", "product"}:
        claims = [c for c in claims if c["product_id"] == PAIRS[0][0]]
    assert not any(r["version_expressions"] for c in claims for r in c["remediations"])


def test_direct_targets_use_existing_public_native_and_browser_ownership_contract(monkeypatch):
    report = projected(SAMPLE)
    assert (
        sum(bool(r["version_expressions"]) for c in affected(report) for r in c["remediations"])
        == 3
    )
    evidence.validate_evidence(report)
    assert native_stream(report, monkeypatch) == report["claims"]
    assert browser(report) == browser(report, stream=True) == "accepted"
