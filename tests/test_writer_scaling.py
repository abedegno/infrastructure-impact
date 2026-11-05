"""Synthetic shared product scopes; these are not publisher evidence."""

import copy
import json
from hashlib import sha256

import pytest

from infrastructure_impact.adapters import cvss, standards, switching
from infrastructure_impact.application import switching_evidence as evidence
from infrastructure_impact.storage.repository import connect, ingest, latest

AT = "2026-11-05T00:00:00Z"
URL = "https://sec.cloudapps.cisco.com/security/center/content/synthetic.json"
CVE = "CVE-2024-12345"
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def fanout(count):
    pids = [f"synthetic-{i}" for i in range(count)]
    return {
        "document": {
            "title": "Synthetic fanout regression",
            "publisher": {"name": "Synthetic publisher"},
            "tracking": {
                "id": "SYNTHETIC-SCALING",
                "version": "1",
                "status": "final",
                "initial_release_date": AT,
                "current_release_date": AT,
            },
        },
        "product_tree": {
            "full_product_names": [{"product_id": p, "name": "Synthetic " + p} for p in pids]
        },
        "vulnerabilities": [
            {
                "cve": CVE,
                "product_status": {"known_affected": pids},
                "notes": [{"text": "Only when the synthetic feature is enabled."}],
                "remediations": [
                    {
                        "category": "vendor_fix",
                        "product_ids": pids,
                        "details": "The software fix is available.",
                        "date": AT,
                    }
                ],
                "scores": [
                    {
                        "products": pids,
                        "cvss_v3": {"version": "3.1", "baseScore": 9.8, "vectorString": VECTOR},
                    }
                ],
            }
        ],
    }


def retained(data):
    db = connect(":memory:")
    raw = json.dumps(data).encode()
    ingest(db, raw, URL, standards.csaf, "cisco")
    return db, raw


@pytest.mark.parametrize("count", [64, 128, 512, 1529])
def test_shared_scopes_are_claim_local_without_losing_full_ordinary_metrics(count, monkeypatch):
    data = fanout(count)
    original = copy.deepcopy(data)
    db, raw = retained(data)
    records = latest(db)
    source_data = evidence.score_inputs(db, records)
    source_scores = source_data["advisories"][0]["claims"]
    original_source_data = copy.deepcopy(source_data)
    monkeypatch.setattr(evidence, "score_inputs", lambda db, records: source_data)
    ordinary = cvss.public_metrics(source_scores)
    calls = []
    real = cvss.public_metrics

    def measured(candidates):
        calls.append(sum(len(s["product_ids"]) for s in candidates))
        return real(candidates)

    monkeypatch.setattr(cvss, "public_metrics", measured)
    result = evidence.inputs(db, records)
    claims = result["claims"]
    assert len(claims) == count
    assert sum(len(r["product_ids"]) for c in claims for r in c["remediations"]) == count
    assert sum(len(s["product_context"]) for c in claims for s in c["scores"]) == count
    # Identical original candidate groups are reconstructed once per extraction.
    assert calls == [count]
    for claim in claims:
        pid = claim["product_id"]
        assert claim["family"] is None
        assert claim["status"] == "affected"
        assert claim["conditions"] == ["Only when the synthetic feature is enabled."]
        assert claim["remediations"][0]["product_ids"] == [pid]
        assert claim["remediations"][0]["availability"] == "vendor_reports_fixed"
        score = claim["scores"][0]
        assert score["product_ids"] == [pid]
        assert [p["product_id"] for p in score["product_context"]] == [pid]
        assert (score["value"], score["preferred"], score["provider"]) == (
            9.8,
            True,
            "Synthetic publisher",
        )
        assert claim["source"]["source_sha256"] == sha256(raw).hexdigest()
        assert claim["source"]["retrieved_at"]
        assert claim["revision"] == "1"
    pids = data["vulnerabilities"][0]["scores"][0]["products"]
    assert ordinary[0]["product_ids"] == pids
    assert [p["product_id"] for p in ordinary[0]["product_context"]] == pids
    claims[0]["scores"][0]["source"]["source_locator"] = "changed"
    assert claims[1]["scores"][0]["source"]["source_locator"] != "changed"
    assert real(source_scores) == ordinary
    assert source_data == original_source_data
    assert bytes(db.execute("SELECT raw FROM evidence").fetchone()[0]) == raw
    assert data == original
    db.close()


def test_projected_representation_grows_linearly_through_public_product_scale():
    sizes = []
    for count in (128, 512, 1529):
        db, raw = retained(fanout(count))
        result = evidence.project(
            evidence.inputs(db, latest(db)), publication=None, generated_at=AT
        )
        assert len(result["claims"]) == count
        size = len(json.dumps(result, separators=(",", ":")).encode())
        assert size < 4500 * count
        sizes.append(size / count)
        db.close()
    assert max(sizes) / min(sizes) < 1.05


def test_remediation_groups_preserve_unbound_and_unresolved_rules():
    data = fanout(2)
    vuln = data["vulnerabilities"][0]
    data["product_tree"]["product_groups"] = [
        {"group_id": "both", "product_ids": ["synthetic-0", "synthetic-1"]}
    ]
    vuln["remediations"] = [
        {"category": "vendor_fix", "group_ids": ["both"], "details": "Group fix"},
        {"category": "workaround", "product_ids": [], "details": "Unbound advice"},
        {"category": "vendor_fix", "group_ids": ["missing"], "details": "Unknown group"},
        {"category": "vendor_fix", "product_ids": ["other"], "details": "Other fix"},
    ]
    raw = json.dumps(data).encode()
    original = json.loads(raw)
    result = switching.extract(raw, URL, "cisco", {"advisory_id": "SYNTHETIC-SCALING"})
    for claim in result["claims"]:
        assert [r["product_ids"] for r in claim["remediations"]] == [[claim["product_id"]], []]
        assert "remediation_product_scope_unresolved" in claim["issues"]
    assert data == original


@pytest.mark.parametrize("scope", [["unrelated", {}], [{}], [[]]])
@pytest.mark.parametrize("grouped", [False, True])
@pytest.mark.parametrize("resolved_product", [False, True])
def test_unrelated_malformed_remediation_scope_keeps_retained_claims(
    scope, grouped, resolved_product
):
    data = fanout(1)
    if not resolved_product:
        data["product_tree"]["full_product_names"] = []
    rem = {"category": "vendor_fix", "details": "The fix is available."}
    if grouped:
        data["product_tree"]["product_groups"] = [{"group_id": "bad", "product_ids": scope}]
        rem["group_ids"] = ["bad"]
    else:
        rem["product_ids"] = scope
    data["vulnerabilities"][0]["remediations"].append(rem)
    db, raw = retained(data)
    try:
        records = latest(db)
        assert len(records) == 1
        result = evidence.inputs(db, records)
        assert "source_extraction_failed" not in result["issues"]
        assert len(result["claims"]) == 1
        claim = result["claims"][0]
        assert claim["product_id"] == "synthetic-0"
        assert claim["family"] is None
        assert claim["status"] == "affected"
        # The malformed nonempty scope must not become unbound fix evidence.
        assert [r["product_ids"] for r in claim["remediations"]] == [["synthetic-0"]]
        assert claim["remediations"][0]["details"] == "The software fix is available."
        assert ("product_id_unresolved" in claim["issues"]) == (not resolved_product)
        assert bytes(db.execute("SELECT raw FROM evidence").fetchone()[0]) == raw
        evidence.project(result, publication=None, generated_at=AT)
    finally:
        db.close()


def test_no_product_claim_does_not_prepare_malformed_remediation_scope():
    data = fanout(0)
    data["vulnerabilities"][0]["remediations"][0]["product_ids"] = [{}]
    db, _ = retained(data)
    try:
        result = evidence.inputs(db, latest(db))
        assert "source_extraction_failed" not in result["issues"]
        assert len(result["claims"]) == 1
        claim = result["claims"][0]
        assert claim["product_id"] is None
        assert claim["remediations"] == []
        assert "product_scope_unresolved" in claim["issues"]
        evidence.project(result, publication=None, generated_at=AT)
    finally:
        db.close()


@pytest.mark.parametrize("unresolved_group", [False, True])
def test_applicable_malformed_remediation_scope_preserves_failure_boundary(unresolved_group):
    data = fanout(1)
    rem = data["vulnerabilities"][0]["remediations"][0]
    rem["product_ids"] = ["synthetic-0", {}]
    if unresolved_group:
        rem["group_ids"] = ["missing"]
    raw = json.dumps(data).encode()
    if unresolved_group:
        result = switching.extract(raw, URL, "cisco", {"advisory_id": "SYNTHETIC-SCALING"})
        assert len(result["claims"]) == 1
        assert result["claims"][0]["remediations"] == []
        assert "remediation_product_scope_unresolved" in result["claims"][0]["issues"]
    else:
        with pytest.raises(TypeError, match="unhashable"):
            switching.extract(raw, URL, "cisco", {"advisory_id": "SYNTHETIC-SCALING"})


def test_overlapping_candidate_groups_keep_preference_and_diagnostics(monkeypatch):
    data = fanout(4)
    scores = data["vulnerabilities"][0]["scores"]
    scores[0]["products"] = ["synthetic-0", "synthetic-1"]
    scores.append(
        {"products": [], "cvss_v3": {"version": "3.1", "baseScore": 4.0, "vectorString": VECTOR}}
    )
    scores.append(
        {
            "products": ["synthetic-1", "synthetic-2"],
            "cvss_v3": {"version": "3.1", "baseScore": 7.5, "vectorString": VECTOR},
        }
    )
    scores.append(
        {
            "products": ["synthetic-0", "synthetic-2"],
            "cvss_v3": {"version": "3.1", "baseScore": 5.0},
        }
    )
    scores.append(
        {
            "products": ["synthetic-2"],
            "cvss_v3": {"version": "3.1", "baseScore": True, "vectorString": VECTOR},
        }
    )
    db, _ = retained(data)
    from test_cvss_enrichment import official

    from infrastructure_impact.collection import score_enrichment

    fallback = cvss.extract(
        json.dumps(official()).encode(), "https://cveawg.mitre.org/api/cve/" + CVE, "cisco", {}
    )
    monkeypatch.setattr(score_enrichment, "inputs", lambda db, cves: fallback)
    claims = evidence.inputs(db, latest(db))["claims"]
    assert [[(s["value"], s["preferred"]) for s in c["scores"]] for c in claims] == [
        [(9.8, True), (4.0, False), (8.1, False), (8.0, False), (5.0, False)],
        [(9.8, True), (4.0, False), (7.5, True), (8.1, False), (8.0, False)],
        [(4.0, False), (7.5, True), (8.1, False), (8.0, False), (5.0, False)],
        [(4.0, False), (8.1, True), (8.0, True)],
    ]
    assert "score_invalid" in claims[2]["issues"]
    assert "vector_missing" in claims[0]["issues"]
    for c in claims:
        for s in c["scores"]:
            assert s["product_ids"] in ([], [c["product_id"]])
    # A new extraction cannot inherit cached state from the same URL.
    data["vulnerabilities"][0]["scores"][0]["cvss_v3"]["baseScore"] = 6.0
    ingest(db, json.dumps(data).encode(), URL, standards.csaf, "cisco")
    assert evidence.inputs(db, latest(db))["claims"][0]["scores"][0]["value"] == 6.0
    db.close()


def source_validator():
    return evidence._validators()["switching-comparison-v1.json"].evolve(
        schema={
            "type": "array",
            "items": {"$ref": "urn:infrastructure-impact:switching-evidence:1#/$defs/source"},
            "uniqueItems": True,
        }
    )


def test_source_uniqueness_does_not_compare_all_pairs(monkeypatch):
    from jsonschema import _utils

    sources = [
        dict(source_url=URL, source_sha256="a" * 64, retrieved_at=AT, source_locator=f"/{i}")
        for i in range(128)
    ]
    comparisons = []
    original = _utils.equal

    def measured(left, right):
        comparisons.append(1)
        return original(left, right)

    monkeypatch.setattr(_utils, "equal", measured)
    source_validator().validate(sources)
    assert len(comparisons) < len(sources)


@pytest.mark.parametrize(
    "fault", ["duplicate", "bool", "integer", "float", "null", "extra", "missing", "list"]
)
def test_source_uniqueness_still_rejects_duplicates_and_invalid_shapes(fault):
    from jsonschema import ValidationError

    source = dict(source_url=URL, source_sha256="a" * 64, retrieved_at=AT, source_locator="/")
    sources = [source]
    if fault == "duplicate":
        sources.append(dict(reversed(list(source.items()))))
    elif fault == "extra":
        source["extra"] = "x"
    elif fault == "missing":
        del source["source_locator"]
    else:
        source["source_locator"] = {
            "bool": True,
            "integer": 1,
            "float": 1.0,
            "null": None,
            "list": [],
        }[fault]
    with pytest.raises(ValidationError):
        source_validator().validate(sources)


@pytest.mark.parametrize(
    "items,valid",
    [
        ([True, 1], True),
        ([1, 1.0], False),
        ([{"a": True}, {"a": 1}], True),
        ([{"a": 1}, {"a": 1.0}], False),
    ],
)
def test_other_unique_arrays_keep_json_equality(items, valid):
    validator = evidence._validators()["switching-comparison-v1.json"].evolve(
        schema={"uniqueItems": True}
    )
    assert validator.is_valid(items) is valid
