"""Authored release observations exercise the pure report contract."""

import copy

import pytest

from infrastructure_impact.application.first_fixed import (
    build_catalogue,
    build_report,
    validate_report,
)


def record(aid, versions=(), fixed=None):
    return dict(
        vendor="cisco",
        advisory_id=aid,
        source_url="https://example.org/" + aid,
        sha256="a" * 64,
        source_observed_at="2026-11-10T00:00:00Z",
        revision_id=1,
        assessments=[
            dict(
                status="affected",
                cve_id="CVE-2099-12345",
                product_family="Cisco IOS XE Software",
                product_context=[["service_pack", v]],
                versions=[],
                evidence_locator="affected / " + v,
            )
            for v in versions
        ],
        first_fixed=[]
        if fixed is None
        else [
            dict(
                method="stated_table",
                evidence_state="publisher_stated",
                family="cisco-iosxe",
                product=None,
                product_ids=None,
                scope="bulletin_shared",
                cve_ids=["CVE-2099-12345", "CVE-2099-12346"],
                train="17.9",
                train_expression="17.9",
                fixed_versions=fixed,
                disposition="fixed",
                source_locator="table / row 17.9",
            )
        ],
    )


def report(records, **kwargs):
    return build_report(
        records, api_results=[], publication=None, generated_at="2026-11-13T00:00:00Z", **kwargs
    )


def test_affected_only_catalogue_with_provenance_and_stable_fingerprint():
    a = record("a", ["17.9.8"])
    a["assessments"].append(
        dict(a["assessments"][0], status="fixed", product_context=[["service_pack", "17.9.9"]])
    )
    cat = build_catalogue([a])
    assert [x["version"] for x in cat["versions"]] == ["17.9.8"]
    assert cat["versions"][0]["provenance"][0]["sha256"] == "a" * 64
    assert cat == build_catalogue([copy.deepcopy(a)])


def test_holdout_next_same_train_and_alternative_agreement():
    target = record("target", ["17.9.8", "17.9.9"], ["17.9.10", "17.9.10a"])
    out = report([target, record("other", ["17.9.10", "17.9.11", "17.12.1"])])
    unit = out["units"][0]
    assert unit["candidate"]["fixed_versions"] == ["17.9.10"]
    assert unit["candidate"]["maximum_affected"] == "17.9.9"
    assert unit["candidate"]["method"] == "inferred_next_release"
    assert all(p["advisory_id"] != "target" for p in unit["candidate"]["provenance"])
    assert out["validation"]["eligible"] == 1
    assert out["validation"]["correct"] == 1
    assert out["validation"]["exact_set_correct"] == 0
    assert len(out["units"]) == 1  # shared CVEs do not multiply observations
    validate_report(out)


def test_no_target_leakage_and_no_cross_train_guess():
    out = report(
        [record("target", ["17.9.9", "17.9.10"], ["17.9.11"]), record("other", ["17.12.11"])]
    )
    assert out["validation"]["abstain"] == 1
    assert out["units"][0]["candidate"] is None


def test_every_row_is_accounted_for_including_migration_unknown_and_conflict():
    a = record("a", ["17.9.9"], ["17.9.10"])
    base = a["first_fixed"][0]
    a["first_fixed"] += [
        dict(
            base, disposition="migrate", train=None, fixed_versions=[], source_locator="migration"
        ),
        dict(base, disposition="unknown", source_locator="unknown"),
        dict(base, fixed_versions=["17.9.11"], source_locator="conflict"),
    ]
    out = report([a, record("no-facts")])
    assert out["validation"]["eligible"] == 0
    assert out["validation"]["conflict"] == 2
    assert out["validation"]["migration"] == 1
    assert out["validation"]["unknown"] == 1
    assert out["coverage"]["cisco"]["records"] == 2
    assert out["coverage"]["cisco"]["without_stated_table"] == 1


def test_missing_receipt_and_unsupported_ordering_abstain_explicitly():
    a = record("a", ["17.9.9"], ["17.9.10w"])
    del a["sha256"]
    out = report([a])
    assert out["validation"]["unsupported"] == 1
    assert "missing_source_receipt" in out["diagnostics"]
    assert "raw_source_manifest_not_supplied" in out["diagnostics"]


def test_future_evidence_is_labelled_and_never_called_historical_prediction():
    a = record("target", ["17.9.9"], ["17.9.10"])
    b = record("other", ["17.9.10"])
    b["source_observed_at"] = "2026-11-14T00:00:00Z"
    out = report([a, b])
    assert out["units"][0]["candidate"]["evidence_timing"] == "future_to_report"
    assert out["catalogue"]["completeness"] == "observed_only"


def test_api_unresolved_does_not_become_a_conflicting_source_fact():
    out = build_report(
        [record("a")],
        api_results=[
            {
                "advisory_context": {
                    "ownership_state": "ownership_unresolved",
                    "source_first_fixed": ["17.9.10"],
                }
            }
        ],
        publication=None,
        generated_at="2026-11-13T00:00:00Z",
    )
    assert out["validation"]["conflict"] == 0
    assert out["api_coverage"]["ownership_unresolved"] == 1
    assert out["units"] == []


def test_validation_rejects_inconsistent_denominators_and_unknown_fields():
    out = report([record("a", ["17.9.9"], ["17.9.10"])])
    out["validation"]["issued"] = 99
    with pytest.raises(ValueError):
        validate_report(out)


def test_replay_requires_matching_raw_manifest_hash(tmp_path):
    import json

    from infrastructure_impact.application.first_fixed_replay import replay

    raw = tmp_path / "source.json"
    raw.write_text("{}")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "outcome": "captured",
                        "raw_path": str(raw),
                        "response_sha256": "a" * 64,
                        "source_url": "https://example.org/a",
                        "retrieved_at": "2026-11-13T00:00:00Z",
                    }
                ]
            }
        )
    )
    with pytest.raises(ValueError, match="hash mismatch"):
        replay([record("a")], manifest, "2026-11-13T00:00:00Z")


def test_api_real_list_shape_retains_unresolved_coverage():
    out = build_report(
        [],
        api_results=[
            {
                "advisory_context": [
                    {"ownership_state": "ownership_unresolved"},
                    {"ownership_state": "ownership_unresolved"},
                ]
            }
        ],
        publication=None,
        generated_at="2026-11-13T00:00:00Z",
    )
    assert out["api_coverage"] == {"ownership_unresolved": 2}


def test_replay_accepts_verified_reused_source_and_owns_new_receipt(tmp_path):
    import hashlib
    import json

    from test_cisco_first_fixed import source

    from infrastructure_impact.application.first_fixed_replay import replay

    data = source()
    raw = tmp_path / "source.json"
    raw.write_text(json.dumps(data))
    digest = hashlib.sha256(raw.read_bytes()).hexdigest()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "outcome": "reused_exact_hash",
                        "raw_path": str(raw),
                        "response_sha256": digest,
                        "source_url": "https://example.org/old",
                        "capture_source_url": "https://example.org/actual",
                        "retrieved_at": "2026-11-13T00:00:00Z",
                    }
                ]
            }
        )
    )
    out, receipt = replay([], manifest, "2026-11-13T00:00:00Z")
    assert receipt["raw_sources_verified"] == 1
    assert len(out["units"]) == 6
    assert out["units"][0]["source"]["sha256"] == digest
    assert out["units"][0]["source"]["source_url"] == "https://example.org/actual"
    assert "revision_id" not in out["units"][0]["source"]


def test_normalizer_tuple_contexts_and_serialized_lists_are_equivalent():
    a = record("a", ["17.9.9"])
    b = copy.deepcopy(a)
    b["assessments"][0]["product_context"] = [("service_pack", "17.9.9")]
    assert build_catalogue([a]) == build_catalogue([b])


def test_report_drops_unrelated_private_fields_and_validates_accuracy_values():
    a = record("a", ["17.9.9"], ["17.9.10"])
    a["extensions"] = {"secret": "DO-NOT-PUBLISH"}
    a["first_fixed"][0]["private_payload"] = "DO-NOT-PUBLISH"
    out = report([a, record("b", ["17.9.10"])])
    import json

    assert "DO-NOT-PUBLISH" not in json.dumps(out)
    out["units"][0]["exact_set_agreement"] = False
    out["validation"]["exact_set_correct"] = 0
    with pytest.raises(ValueError):
        validate_report(out)


def test_explicit_conflicting_disposition_remains_conflict():
    a = record("a", ["17.9.9"], ["17.9.10"])
    a["first_fixed"][0]["disposition"] = "conflicting"
    assert report([a])["validation"]["conflict"] == 1


def api_frame(aid="target", query="17.9.9", fixed=None, cves=None):
    return {
        "source": {
            "url": "https://apix.cisco.com/security/advisories/v2/OSType/iosxe?version=" + query,
            "sha256": "b" * 64,
            "retrieved_at": "2026-11-13T00:00:00Z",
        },
        "query_release": query,
        "parser_revision": "cisco-first-fixed-api-1",
        "advisory_context": [
            {
                "advisory_id": aid,
                "source_locator": "/advisories/0/firstFixed",
                "source_first_fixed": fixed or ["17.9.10"],
                "first_fixed_state": "present",
                "cve_refs": cves or ["CVE-2099-12345", "CVE-2099-12346"],
                "ownership_state": "ownership_unresolved",
            }
        ],
    }


def test_api_binding_requires_exact_advisory_query_family_cves_and_source_receipt():
    a = record("target", ["17.9.9"], ["17.9.10"])
    a["assessments"][0]["cve_id"] = "CVE-2099-12345"
    a["assessments"].append(dict(a["assessments"][0], cve_id="CVE-2099-12346"))
    frame = api_frame()
    out = build_report(
        [a],
        api_results=[frame],
        publication={"id": "a" * 32, "advisory_schema_version": 2},
        generated_at="2026-11-13T00:00:00Z",
    )
    assert out["api_observations"][0]["binding_state"] == "bound"
    assert out["api_facts"][0]["fact"]["method"] == "openvuln_api"
    assert out["api_facts"][0]["source"]["sha256"] == "b" * 64
    assert out["publication"]["id"] == "a" * 32
    for change in (
        dict(query_release="17.12.1"),
        dict(source={}),
        dict(advisory_context=[dict(frame["advisory_context"][0], cve_refs=[])]),
        dict(advisory_context=[dict(frame["advisory_context"][0], advisory_id="other")]),
    ):
        bad = build_report(
            [a],
            api_results=[dict(frame, **change)],
            publication=None,
            generated_at="2026-11-13T00:00:00Z",
        )
        assert bad["api_observations"][0]["binding_state"] == "ownership_unresolved"
        assert bad["api_facts"] == []
        assert bad["api_observations"][0]["context"]["source_first_fixed"]


def test_api_owned_disagreement_is_conflict_without_replacing_stated_truth():
    a = record("target", ["17.9.9"], ["17.9.10"])
    a["assessments"][0]["cve_id"] = "CVE-2099-12345"
    a["assessments"].append(dict(a["assessments"][0], cve_id="CVE-2099-12346"))
    out = build_report(
        [a],
        api_results=[api_frame(fixed=["17.9.11"])],
        publication=None,
        generated_at="2026-11-13T00:00:00Z",
    )
    assert out["api_observations"][0]["binding_state"] == "conflicting"
    assert out["units"][0]["fact"]["fixed_versions"] == ["17.9.10"]
    assert out["validation"]["conflict"] == 1
    validate_report(out)


def test_api_only_fact_binds_without_a_table_but_requires_retained_scope():
    a = record("target", ["17.9.9"])
    a["assessments"][0]["cve_id"] = "CVE-2099-12345"
    a["assessments"].append(dict(a["assessments"][0], cve_id="CVE-2099-12346"))
    out = build_report(
        [a], api_results=[api_frame()], publication=None, generated_at="2026-11-13T00:00:00Z"
    )
    assert len(out["api_facts"]) == 1
    assert out["api_facts"][0]["table_source"] == {}
    assert out["api_facts"][0]["fact"]["fixed_versions"] == ["17.9.10"]
    assert out["validation"]["eligible"] == 0
    validate_report(out)
    for field, value in [
        ("product_family", "Cisco NX-OS Software"),
        ("product_context", []),
        ("cve_id", "CVE-2099-99999"),
    ]:
        bad = copy.deepcopy(a)
        for assessment in bad["assessments"]:
            assessment[field] = value
        rejected = build_report(
            [bad], api_results=[api_frame()], publication=None, generated_at="2026-11-13T00:00:00Z"
        )
        assert rejected["api_facts"] == []


def test_peer_affected_observations_cannot_create_inferred_candidates():
    a = record("peer", ["17.9.9"])
    a["vendor"] = "aruba"
    a["assessments"][0]["product_family"] = "HPE Aruba Networking AOS-CX"
    out = report([a])
    assert out["catalogue"]["versions"] == []
    assert out["candidates"] == []


def test_catalogue_collapses_cve_locator_duplicates_deterministically():
    a = record("a", ["17.9.9"])
    a["assessments"] += [
        dict(a["assessments"][0], cve_id="CVE-2099-12346", evidence_locator="earlier locator")
    ]
    cat = build_catalogue([a])
    assert len(cat["versions"][0]["provenance"]) == 1
    b = copy.deepcopy(a)
    b["assessments"].reverse()
    assert cat == build_catalogue([b])
    b["revision_id"] = 2
    assert len(build_catalogue([a, b])["versions"][0]["provenance"]) == 2


def scoped_rows():
    a = record("target", ["17.9.9", "17.9.11"], ["17.9.10"])
    for assessment, cid in zip(a["assessments"], ["CVE-2099-12345", "CVE-2099-12346"]):
        assessment["cve_id"] = cid
    first = a["first_fixed"][0]
    first.update(scope="cve_specific", cve_ids=["CVE-2099-12345"])
    a["first_fixed"].append(dict(first, cve_ids=["CVE-2099-12346"], fixed_versions=["17.9.12"]))
    return a


def test_disjoint_cve_rows_keep_independent_candidates_and_units():
    out = report([scoped_rows(), record("other", ["17.9.10", "17.9.12"])])
    assert out["validation"]["eligible"] == 2
    assert out["validation"]["conflict"] == 0
    assert [u["candidate"]["maximum_affected"] for u in out["units"]] == ["17.9.9", "17.9.11"]
    assert out["validation"]["correct"] == 2
    target_candidates = [
        c["candidate"] for c in out["candidates"] if c["identity"]["advisory_id"] == "target"
    ]
    assert sorted(c["maximum_affected"] for c in target_candidates) == ["17.9.11", "17.9.9"]
    assert all(c["input_scope"]["cve_ids"] for c in target_candidates)
    a = scoped_rows()
    a["first_fixed"][1]["fixed_versions"] = ["17.9.10"]
    assert len(report([a])["units"]) == 2  # same locator/value cannot erase distinct CVEs


@pytest.mark.parametrize(
    "axis, values", [("product_ids", [["p1"], ["p2"]]), ("product", ["model one", "model two"])]
)
def test_disjoint_products_do_not_conflict_or_share_affected_maximum(axis, values):
    a = scoped_rows()
    for index, fact in enumerate(a["first_fixed"]):
        fact["cve_ids"] = ["CVE-2099-12345"]
        fact[axis] = values[index]
        a["assessments"][index]["cve_id"] = "CVE-2099-12345"
        a["assessments"][index]["product_id" if axis == "product_ids" else "product"] = (
            values[index][0] if axis == "product_ids" else values[index]
        )
    out = report([a, record("other", ["17.9.10", "17.9.12"])])
    assert out["validation"]["eligible"] == 2
    assert out["validation"]["correct"] == 2
    assert [u["candidate"]["maximum_affected"] for u in out["units"]] == ["17.9.9", "17.9.11"]


def test_overlapping_owned_scope_conflicts_and_unknown_product_comparison_is_diagnostic():
    a = scoped_rows()
    a["first_fixed"][0].update(
        scope="bulletin_shared", cve_ids=["CVE-2099-12345", "CVE-2099-12346"]
    )
    out = report([a])
    assert out["validation"]["conflict"] == 2
    a["first_fixed"][1]["product_ids"] = ["p2"]
    out = report([a])
    assert out["validation"]["conflict"] == 0
    assert "scope_comparison_unknown" in out["diagnostics"]
    assert out["units"][1]["candidate"] is None  # no matching owned product assessment


@pytest.mark.parametrize(
    "target_time, successor_time, expected",
    [
        ("2026-11-14T00:00:00Z", "2026-11-10T00:00:00Z", "future_to_report"),
        ("2026-11-13T01:00:00+01:00", "2026-11-12T23:00:00-01:00", "latest_known_retrospective"),
        ("2026-11-12T23:30:00-01:00", "2026-11-10T00:00:00Z", "future_to_report"),
        (None, "2026-11-10T00:00:00Z", "evidence_time_unknown"),
        ("not a date", "2026-11-10T00:00:00Z", "evidence_time_unknown"),
        ("2026-11-10T00:00:00Z", "2026-11-10", "evidence_time_unknown"),
    ],
)
def test_candidate_timing_covers_target_and_successor_with_parsed_dates(
    target_time, successor_time, expected
):
    a = record("target", ["17.9.9"], ["17.9.10"])
    a["source_observed_at"] = target_time
    b = record("other", ["17.9.10"])
    b["source_observed_at"] = successor_time
    out = report([a, b])
    assert out["units"][0]["candidate"]["evidence_timing"] == expected
    validate_report(out)


def test_api_compares_only_overlapping_product_and_cve_owned_rows():
    a = scoped_rows()
    # Same query is owned by CVE A on product p1; CVE B's table is unrelated.
    a["assessments"][0]["product_id"] = "p1"
    a["first_fixed"][0]["product_ids"] = ["p1"]
    a["first_fixed"][1]["product_ids"] = ["p2"]
    frame = api_frame(cves=["CVE-2099-12345"], fixed=["17.9.10"])
    out = build_report(
        [a], api_results=[frame], publication=None, generated_at="2026-11-13T00:00:00Z"
    )
    assert out["api_facts"][0]["binding_state"] == "bound"
    assert out["validation"]["conflict"] == 0
    assert out["api_facts"][0]["fact"]["product_ids"] == ["p1"]
    frame["advisory_context"][0]["source_first_fixed"] = ["17.9.13"]
    bad = build_report(
        [a], api_results=[frame], publication=None, generated_at="2026-11-13T00:00:00Z"
    )
    assert bad["validation"]["conflict"] == 1
    assert bad["units"][1]["stratum"] == "eligible"


@pytest.mark.parametrize("field", ["sha256", "source_url", "source_observed_at"])
def test_incomplete_target_receipt_and_unknown_report_time_stay_explicit(field):
    a = record("target", ["17.9.9"], ["17.9.10"])
    del a[field]
    out = report([a, record("other", ["17.9.10"])])
    assert out["units"][0]["candidate"]["evidence_timing"] == "evidence_time_unknown"
    validate_report(out)
    known = record("target", ["17.9.9"], ["17.9.10"])
    unknown = build_report(
        [known, record("other", ["17.9.10"])],
        api_results=[],
        publication=None,
        generated_at="2026-11-13",
    )
    assert unknown["units"][0]["candidate"]["evidence_timing"] == "evidence_time_unknown"


def test_api_unknown_product_axes_preserve_observation_without_false_table_conflict():
    a = scoped_rows()
    a["assessments"][0]["product_id"] = "p1"
    a["first_fixed"][0]["product"] = "model one"  # no known mapping from p1 to this name
    frame = api_frame(cves=["CVE-2099-12345"], fixed=["17.9.13"])
    out = build_report(
        [a], api_results=[frame], publication=None, generated_at="2026-11-13T00:00:00Z"
    )
    assert out["api_facts"][0]["table_source"] == {}
    assert out["api_observations"][0]["binding_state"] == "bound"  # only retained-query binding
    assert out["validation"]["conflict"] == 0
    assert "scope_comparison_unknown" in out["diagnostics"]


def test_validator_rejects_stale_evidence_timing_label():
    a = record("target", ["17.9.9"], ["17.9.10"])
    a["source_observed_at"] = "2026-11-14T00:00:00Z"
    out = report([a, record("other", ["17.9.10"])])
    out["units"][0]["candidate"]["evidence_timing"] = "latest_known_retrospective"
    with pytest.raises(ValueError, match="timing"):
        validate_report(out)


@pytest.mark.parametrize(
    "axis, values",
    [("product_ids", [["p1", "p2"], ["p2", "p3"]]), ("product", ["same model", "same model"])],
)
def test_explicit_overlapping_products_remain_genuine_conflicts(axis, values):
    a = scoped_rows()
    for fact, value in zip(a["first_fixed"], values):
        fact["cve_ids"] = ["CVE-2099-12345"]
        fact[axis] = value
    assert report([a])["validation"]["conflict"] == 2


def test_api_subset_cves_compare_shared_table_without_selecting_unrelated_row():
    a = scoped_rows()
    a["first_fixed"][0].update(
        scope="bulletin_shared", cve_ids=["CVE-2099-12345", "CVE-2099-12346"]
    )
    # The other CVE's independent row agrees with the shared source statement.
    a["first_fixed"][1]["fixed_versions"] = ["17.9.10"]
    frame = api_frame(cves=["CVE-2099-12345"], fixed=["17.9.13"])
    out = build_report(
        [a], api_results=[frame], publication=None, generated_at="2026-11-13T00:00:00Z"
    )
    assert out["api_facts"][0]["binding_state"] == "conflicting"
    assert out["validation"]["conflict"] == 1
    assert out["units"][1]["stratum"] == "eligible"


@pytest.mark.parametrize("separate", [False, True])
def test_owned_affected_range_prevents_literal_only_candidate(separate):
    a = record("target", ["17.9.1"], ["17.9.10"])
    expression = dict(expression="vers:semver/>=17.9.1|<=17.9.9")
    if separate:
        a["assessments"].append(
            dict(a["assessments"][0], product_context=[], versions=[expression])
        )
    else:
        a["assessments"][0]["versions"] = [expression]
    out = report([a, record("other", ["17.9.2", "17.9.10"])])
    assert out["units"][0]["candidate"] is None
    assert out["units"][0]["stratum"] == "eligible"
    assert all(
        c["candidate"] is None
        for c in out["candidates"]
        if c["identity"]["advisory_id"] == "target"
    )


def test_explicit_special_variant_exclusion_remains_separate_from_range_completeness():
    out = report([record("target", ["17.9.1", "17.9.9w"], ["17.9.2"]), record("other", ["17.9.2"])])
    assert out["units"][0]["candidate"]["fixed_versions"] == ["17.9.2"]
    assert out["units"][0]["candidate"]["affected_inputs"] == ["17.9.1"]
