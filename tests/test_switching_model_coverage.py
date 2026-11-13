"""Coverage follows accepted row claim membership, with overlapping models."""

import copy

import pytest
from test_switching_disclosure import AT, inputs
from test_switching_disclosure import claim as base_claim


def claim(*args, **kwargs):
    c = base_claim(*args, **kwargs)
    c.update(vendor="cisco", family="cisco-iosxe", product="Cisco IOS XE Software")
    c["source"]["source_url"] = "https://sec.cloudapps.cisco.com/security/test.json"
    for binding in c["platform_bindings"]:
        binding["source"]["source_url"] = c["source"]["source_url"]
    if c["platform_bindings"]:
        c["platform_bindings"][0].update(platform="Cisco Catalyst 9300", model="9300")
        c["named_platforms"] = ["Cisco Catalyst 9300"]
    return c


def report(claims, **selection):
    from infrastructure_impact.application import switching_model_coverage as coverage

    e, s = inputs(claims, **selection)
    return coverage.build_report(e, s, publication=None, generated_at=AT)


def test_overlapping_models_are_not_added_and_ownership_is_retained():
    c = claim()
    b = copy.deepcopy(c["platform_bindings"][0])
    b.update(platform="Cisco Catalyst 9200", model="9200")
    c["named_platforms"].append(b["platform"])
    c["platform_bindings"].append(b)
    r = report([c, claim(product_id="second")])
    assert r["totals"]["claims"] == 2
    assert r["totals"]["advisories"] == 1
    assert r["totals"]["cves"] == 1
    assert r["nonadditive"] is True
    rows = {x["model"]: x for x in r["models"]}
    assert rows["9200"]["counts"]["claims"] == 1
    assert rows["9300"]["counts"]["claims"] == 2
    assert rows["9200"]["by_status"]["affected"]["advisories"] == 1
    assert rows["9200"]["sources"][0]["source_sha256"] == "a" * 64


def test_selection_window_cohort_and_unresolved_do_not_imply_unaffected():
    a = claim(
        scope_level="os_family",
        platform_bindings=[],
        named_platforms=[],
        issues=["model_binding_unresolved", "cisco_model_family_only_9400_9600_context"],
    )
    b = claim("B", "CVE-2026-99999", "2026-07-01")
    r = report([a, b], cve_ids=["CVE-2026-12345"])
    assert r["totals"]["claims"] == 1
    assert r["totals"]["bound_claims"] == 0
    assert r["unresolved"][0]["reason"] == "cisco_model_family_only_9400_9600_context"
    assert all(row["counts"]["claims"] == 0 for row in r["models"])
    assert report([a, b], scope_level="model_qualified")["totals"]["claims"] == 1
    assert report([a, b], window="pre")["totals"]["claims"] == 0


def test_input_ownership_and_generation_are_validated_without_mutation():
    from infrastructure_impact.application import switching_model_coverage as coverage

    e, s = inputs([claim()])
    before = copy.deepcopy((e, s))
    coverage.build_report(e, s, publication=None, generated_at=AT)
    assert (e, s) == before
    s["inputs"]["evidence"]["claims"][0]["product_id"] = "tampered"
    with pytest.raises(ValueError):
        coverage.build_report(e, s, publication=None, generated_at=AT)
    with pytest.raises(ValueError):
        coverage.build_report(e, before[1], publication=None, generated_at="2026-11-12T12:00:00Z")


def test_source_owned_counts_keep_status_and_distinct_model_binding_proofs():
    c = claim()
    d = claim("B", status="unaffected")
    d["platform_bindings"][0]["source"]["source_locator"] = "/product_tree/branches/1"
    r = report([c, d])
    row = next(x for x in r["models"] if x["vendor"] == "cisco" and x["model"] == "9300")
    assert row["by_status"]["affected"]["claims"] == 1
    assert row["by_status"]["unaffected"]["claims"] == 1
    assert len(row["by_source"]) == 2
    assert sorted(x["counts"]["claims"] for x in row["by_source"]) == [1, 1]
