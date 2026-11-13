"""Disclosure counts require selected affected ownership pairs, never set products."""

import copy
import json
from pathlib import Path

import pytest

from infrastructure_impact.application import kev
from infrastructure_impact.application import switching_comparison as comparison
from infrastructure_impact.application import switching_disclosure as disclosure
from infrastructure_impact.application import switching_evidence as evidence

AT = "2026-11-13T12:00:00Z"
BASE = json.loads((Path(__file__).parent / "fixtures/switching-cases.json").read_text())[
    "evidence"
]["claims"][0]


def claim(a="A", cid="CVE-2026-12345", day="2026-06-30", **changes):
    c = copy.deepcopy(BASE)
    c.update(
        advisory_id=a, cve_id=cid, initial_published_at=day, bundle=None, scores=[], remediations=[]
    )
    c.update(changes)
    return c


def inputs(claims, **selection):
    e = evidence.project(
        dict(claims=claims, coverage=[], issues=[]), publication=None, generated_at=AT
    )
    k = kev.build_report({}, [], publication=None, generated_at=AT)
    r = comparison.build_report(
        e,
        k,
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end="2026-11-13",
    )
    return e, comparison.select_report(r, evaluated_at=AT, **selection)


def run(claims, records=(), **selection):
    e, s = inputs(claims, **selection)
    return disclosure.build_report(list(records), s, evidence=e, publication=None, generated_at=AT)


def test_july_era_is_separate_from_april_window_and_distinct_fanout():
    r = run([claim(), claim(product_id="another-product"), claim("B", day="2026-07-01")])
    assert r["periods"]["pre_july"]["counts"] == dict(
        advisories=1, cves=1, owned_pairs=1, umbrella_cves=0
    )
    assert r["periods"]["from_july"]["counts"] == dict(
        advisories=1, cves=1, owned_pairs=1, umbrella_cves=0
    )
    assert r["years"]["2026"]["counts"]["cves"] == 1
    assert r["years"]["2026"]["counts"]["owned_pairs"] == 2
    assert len(r["pairs"][0]["claim_ids"]) == 2
    assert r["pairs"][0]["source"]["source_sha256"] == "a" * 64
    assert r["periods"]["pre_july"]["method_counts"]["unknown"] == 1


def test_cross_advisory_year_unaffected_cve_cannot_be_joined_from_separate_sets():
    r = run(
        [
            claim("A", "CVE-2025-12345", "2025-01-01"),
            claim("A", "CVE-2026-12345", "2025-01-01", status="unaffected"),
            claim("B", "CVE-2026-12345", "2026-08-01"),
        ]
    )
    assert [(p["advisory_id"], p["cve_id"]) for p in r["pairs"]] == [
        ("A", "CVE-2025-12345"),
        ("B", "CVE-2026-12345"),
    ]
    assert r["years"]["2025"]["cve_ids"] == ["CVE-2025-12345"]


def test_native_cohort_window_model_scope_and_undated():
    claims = [
        claim(),
        claim("B", "CVE-2026-99999", "2026-07-01", scope_level="os_family", platform_bindings=[]),
        claim("C", day=None),
    ]
    assert len(run(claims, scope_level="model_qualified")["pairs"]) == 2
    assert len(run(claims, cve_ids=["CVE-2026-99999"])["pairs"]) == 1
    assert len(run(claims, window="undated")["pairs"]) == 1
    assert run(claims)["periods"]["unknown"]["counts"]["advisories"] == 1
    assert run(claims, window="pre")["pairs"] == []  # Existing April definition unchanged.
    assert len(run(claims, window="post")["pairs"]) == 2


def test_envelopes_generation_and_inputs_must_match():
    e, s = inputs([claim()])
    for bad in ("time", "evidence"):
        altered = copy.deepcopy(e)
        if bad == "time":
            altered["generated_at"] = "2026-11-12T12:00:00Z"
        else:
            altered["issues"].append("different_current_evidence")
        with pytest.raises(ValueError):
            disclosure.build_report([], s, evidence=altered, publication=None, generated_at=AT)


def test_inputs_and_legacy_events_unchanged():
    e, s = inputs([claim()])
    before = copy.deepcopy((e, s))
    disclosure.build_report([], s, evidence=e, publication=None, generated_at=AT)
    assert (e, s) == before


def cisco_owned():
    from infrastructure_impact.adapters.standards import csaf

    raw = (Path(__file__).parent / "fixtures/cisco-disclosure-hardening.json").read_text()
    url = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-hardening-iosxe-V8NMuMZJ/csaf/cisco-sa-hardening-iosxe-V8NMuMZJ.json"
    r = csaf(raw, url, "cisco")
    r.update(sha256="a" * 64, source_observed_at=AT)
    c = claim(
        r["advisory_id"],
        "CVE-2026-20272",
        r["published_at"],
        vendor="cisco",
        family="cisco-iosxe",
        product="Cisco IOS XE Software",
        scope_level="os_family",
        platform_bindings=[],
        named_platforms=[],
    )
    c["source"]["source_url"] = url
    return c, r


def test_owned_umbrella_single_advisory_bundle_and_missing_date_proof():
    c, r = cisco_owned()
    result = run([c], [r])
    assert result["periods"]["from_july"]["counts"]["umbrella_cves"] == 1
    assert result["pairs"][0]["umbrella"]["cwe_id"] == "CWE-74"
    assert result["periods"]["from_july"]["method_counts"] == {"risk_based": 1}
    assert len(result["advisory_facts"]) == 1
    assert result["bundles"][0]["member_advisory_ids"] == [r["advisory_id"]]
    assert len(result["bundles"][0]["member_cve_ids"]) == 7
    assert result["bundles"][0]["selected_cve_ids"] == ["CVE-2026-20272"]
    r["sha256"] = "b" * 64
    assert run([c], [r])["pairs"][0]["umbrella"] is None
    c, r = cisco_owned()
    c["initial_published_at"] = None
    r["published_at"] = None
    r["disclosure_metadata"]["initial_published_at"] = None
    r["disclosure_metadata"]["bundle"]["initial_published_at"] = None
    r["disclosure_metadata"]["date_precision"] = "unknown"
    r["disclosure_metadata"]["method"] = dict(classification=None, basis="unknown", locator=None)
    result = run([c], [r])
    assert result["bundles"][0]["date_period"] == "unknown"
    assert result["periods"]["unknown"]["counts"]["cves"] == 1


def test_third_party_exception_is_method_not_date_period():
    c, r = cisco_owned()
    r["disclosure_metadata"]["method"] = dict(
        classification="outside_policy",
        basis="third_party_exception",
        locator="/document/notes/0/text",
    )
    result = run([c], [r])
    assert result["pairs"][0]["date_period"] == "from_july"
    assert result["periods"]["from_july"]["method_counts"] == {"outside_policy": 1}


def test_wrong_advisory_date_or_cve_in_exact_capture_rejected():
    c, r = cisco_owned()
    r["published_at"] = "2025-01-01"
    r.pop("disclosure_metadata")
    with pytest.raises(ValueError, match="ownership"):
        run([c], [r])


def test_score_facets_retain_native_source_and_deduplicate_fanout():
    c = claim(cid="CVE-2025-12345", scores=copy.deepcopy(BASE["scores"]))
    c["scores"][0].update(provider="Cisco", origin="vendor_advisory", preferred=True)
    r = run([c, {**copy.deepcopy(c), "product": "EOS named product"}])
    facet = r["periods"]["pre_july"]["severity"][0]
    assert facet["band"] == "High"
    assert facet["count"] == 1
    assert (facet["provider"], facet["origin"], facet["preferred"]) == (
        "Cisco",
        "vendor_advisory",
        True,
    )


def test_retained_explicit_bundle_keeps_upstream_lineage_and_missing_date():
    from infrastructure_impact.application import switching_releases

    c, r = cisco_owned()
    historical = copy.deepcopy(c)
    historical["bundle"] = dict(
        publisher_id="ERP-synthetic",
        title="Owned EventResponse bundle",
        member_advisory_ids=[r["advisory_id"], "unobserved-member"],
        published_at=None,
        source=copy.deepcopy(c["source"]),
    )
    old_at = "2026-11-12T12:00:00Z"
    old_evidence = evidence.project(
        dict(claims=[historical], coverage=[], issues=[]), publication=None, generated_at=old_at
    )
    history = switching_releases.build(
        old_evidence, [], publication=None, generated_at=old_at, observation_end="2026-11-12"
    )
    e, s = inputs([c])
    result = disclosure.build_report(
        [r], s, evidence=e, publication=None, generated_at=AT, bundle_history=history
    )
    b = next(b for b in result["bundles"] if b["kind"] == "explicit_publisher_bundle")
    assert b["initial_published_at"] is None
    assert b["date_period"] == "unknown"
    assert b["member_advisory_ids"] == [r["advisory_id"], "unobserved-member"]
    assert b["selected_advisory_ids"] == [r["advisory_id"]]
    assert b["upstream"]["generated_at"] == old_at
    assert b["source"] == historical["bundle"]["source"]
    assert result["generated_at"] == AT


def test_output_validator_rejects_counts_and_umbrella_source_substitution():
    c, r = cisco_owned()
    result = run([c], [r])
    broken = copy.deepcopy(result)
    broken["years"]["2026"]["counts"]["cves"] += 1
    with pytest.raises(ValueError, match="counts"):
        disclosure.validate_report(broken)
    broken = copy.deepcopy(result)
    broken["pairs"][0]["source"]["source_sha256"] = "b" * 64
    with pytest.raises(ValueError, match="ownership"):
        disclosure.validate_report(broken)


def test_bundle_cannot_add_unselected_cve_or_inherit_member_date():
    c, r = cisco_owned()
    result = run([c], [r])
    result["bundles"][0]["selected_cve_ids"].append("CVE-2026-99999")
    with pytest.raises(ValueError, match="bundle"):
        disclosure.validate_report(result)


def test_year_period_table_uses_same_distinct_selected_pairs():
    result = run([claim("A", day="2025-12-01"), claim("B"), claim("C", day="2026-07-01")])
    assert result["year_periods"]["2025"]["pre_july"]["counts"]["advisories"] == 1
    assert result["year_periods"]["2025"]["from_july"]["counts"]["advisories"] == 0
    assert result["year_periods"]["2026"]["pre_july"]["counts"]["advisories"] == 1
    assert result["year_periods"]["2026"]["from_july"]["counts"]["advisories"] == 1


def test_retained_bundle_proof_resolves_bundle_coverage_without_document_metadata():
    from infrastructure_impact.application import switching_releases

    c, r = cisco_owned()
    c["bundle"] = dict(
        publisher_id="ERP-synthetic",
        title="Owned EventResponse bundle",
        member_advisory_ids=[r["advisory_id"]],
        published_at=None,
        source=copy.deepcopy(c["source"]),
    )
    e, s = inputs([c])
    history = switching_releases.build(
        e, [], publication=None, generated_at=AT, observation_end="2026-11-13"
    )
    r.pop("disclosure_metadata")
    result = disclosure.build_report(
        [r], s, evidence=e, publication=None, generated_at=AT, bundle_history=history
    )
    assert "explicit_bundle_unavailable" not in result["pairs"][0]["missing"]
    assert "disclosure_metadata_unavailable" in result["pairs"][0]["missing"]


def test_native_current_bundle_is_proof_without_optional_retained_history():
    c, r = cisco_owned()
    c["bundle"] = dict(
        publisher_id="ERP-current",
        title="Owned EventResponse bundle",
        member_advisory_ids=[r["advisory_id"]],
        published_at=None,
        source=copy.deepcopy(c["source"]),
    )
    r.pop("disclosure_metadata")
    result = run([c], [r])
    assert result["bundles"][0]["publisher_id"] == "ERP-current"
    assert result["bundles"][0]["initial_published_at"] is None
    assert "explicit_bundle_unavailable" not in result["pairs"][0]["missing"]
