"""Reported CVSS evidence never establishes product affectedness."""

import json
import math
from hashlib import sha256

import pytest

from infrastructure_impact.adapters import cvss, standards
from infrastructure_impact.application import switching_evidence
from infrastructure_impact.collection import score_enrichment
from infrastructure_impact.storage.repository import connect, ingest, latest

CVE = "CVE-2024-12345"
URL = "https://support.hpe.com/security/test.json"
V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def csaf(scores):
    return {
        "document": {
            "title": "Synthetic",
            "publisher": {"name": "Publisher"},
            "tracking": {"id": "T-1", "version": "1", "status": "final"},
        },
        "product_tree": {"full_product_names": [{"product_id": "p", "name": "AOS-CX"}]},
        "vulnerabilities": [
            {"cve": CVE, "product_status": {"known_affected": ["p"]}, "scores": scores}
        ],
    }


def extract(data, url=URL):
    return cvss.extract(json.dumps(data).encode(), url, "aruba", {"advisory_id": "T-1"})


@pytest.mark.parametrize(
    "version,vector,key",
    [
        ("2.0", "AV:N/AC:L/Au:N/C:C/I:C/A:C", "cvss_v2"),
        ("3.0", V3.replace("3.1", "3.0"), "cvss_v3"),
        ("3.1", V3, "cvss_v3"),
        ("4.0", V4 + "/U:Red", "cvss_v4"),
    ],
)
def test_csaf_versions_keep_product_provider_and_unverified_consistency(version, vector, key):
    result = extract(
        csaf(
            [
                {
                    "products": ["p"],
                    key: {
                        "version": version,
                        "baseScore": 0,
                        "vectorString": vector,
                        "private": "SENTINEL",
                    },
                }
            ]
        )
    )
    c = result["claims"][0]
    assert (c["version"], c["value"], c["product_ids"], c["provider"]) == (
        version,
        0,
        ["p"],
        "Publisher",
    )
    assert (
        c["source"]["source_sha256"]
        == sha256(
            json.dumps(
                csaf(
                    [
                        {
                            "products": ["p"],
                            key: {
                                "version": version,
                                "baseScore": 0,
                                "vectorString": vector,
                                "private": "SENTINEL",
                            },
                        }
                    ]
                )
            ).encode()
        ).hexdigest()
    )
    assert c["severity"] == ("Low" if version == "2.0" else "None")
    assert c["validation"] == "valid"
    assert "consistency_not_verified" in c["issues"]
    assert "SENTINEL" not in json.dumps(result)
    assert cvss.public_metrics(result["claims"])[0]["value"] == 0


@pytest.mark.parametrize("bad", [True, False, -1, 11, math.inf, math.nan, "9.8"])
def test_bad_base_never_publishes(bad):
    result = extract(
        csaf(
            [
                {
                    "products": ["p"],
                    "cvss_v3": {"version": "3.1", "baseScore": bad, "vectorString": V3},
                }
            ]
        )
    )
    assert result["claims"][0]["validation"] == "invalid"
    assert cvss.public_metrics(result["claims"]) == []
    assert "base_invalid" in result["claims"][0]["issues"]


@pytest.mark.parametrize(
    "vector",
    [
        V3 + "/AV:N",
        V3.replace("/AC:L", ""),
        V3.replace("AV:N", "AV:Z"),
        V3.replace("3.1", "3.0"),
        V4.replace("/AC:L/AT:N", "/AT:N/AC:L"),
        V4 + "/U:red",
    ],
)
def test_malformed_vectors_rejected(vector):
    version = "4.0" if vector.startswith("CVSS:4") else "3.1"
    result = extract(
        csaf(
            [
                {
                    "products": ["p"],
                    "cvss_v4"
                    if version == "4.0"
                    else ("cvss_v4" if version == "4.0" else "cvss_v3"): {
                        "version": version,
                        "baseScore": 9.8,
                        "vectorString": vector,
                    },
                }
            ]
        )
    )
    assert cvss.public_metrics(result["claims"]) == []


def test_structured_metric_disagreement_and_missing_components_are_explicit():
    r = extract(
        csaf(
            [
                {
                    "products": ["p"],
                    "cvss_v3": {
                        "version": "3.1",
                        "baseScore": 9.8,
                        "vectorString": V3,
                        "attackVector": "LOCAL",
                    },
                }
            ]
        )
    )
    assert "structured_metric_disagreement" in r["claims"][0]["issues"]
    for metric, issue in [
        ({"version": "3.1", "baseScore": 9.8}, "vector_missing"),
        ({"version": "3.1", "vectorString": V3}, "base_missing"),
    ]:
        r = extract(csaf([{"products": ["p"], "cvss_v3": metric}]))
        assert issue in r["claims"][0]["issues"]
        assert r["claims"][0]["validation"] == "incomplete"
        assert cvss.public_metrics(r["claims"]) == []


def test_unbound_score_not_copied_to_two_cves_and_sir_not_cvss():
    d = csaf([])
    d["vulnerabilities"].append({"cve": "CVE-2024-54321"})
    d["scores"] = [{"cvss_v3": {"version": "3.1", "baseScore": 9.8, "vectorString": V3}}]
    d["vulnerabilities"][0]["threats"] = [{"category": "impact", "details": "High"}]
    assert extract(d)["claims"] == []


def official(value=8.1):
    return {
        "dataType": "CVE_RECORD",
        "cveMetadata": {"cveId": CVE, "state": "PUBLISHED"},
        "containers": {
            "cna": {
                "providerMetadata": {"shortName": "CNA", "orgId": "org"},
                "metrics": [
                    {
                        "cvssV3_1": {"version": "3.1", "baseScore": value, "vectorString": V3},
                        "scenarios": [{"lang": "en", "value": "scenario"}],
                    }
                ],
            },
            "adp": [
                {
                    "providerMetadata": {"shortName": "ADP"},
                    "metrics": [
                        {"cvssV4_0": {"version": "4.0", "baseScore": 8.0, "vectorString": V4}}
                    ],
                }
            ],
        },
    }


def nvd(value=7.5):
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": CVE,
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": value,
                                    "vectorString": V3,
                                },
                            }
                        ]
                    },
                }
            }
        ]
    }


def test_official_provider_forms_and_priority_keep_conflicts_and_cve_level_scope():
    vendor = extract(
        csaf(
            [
                {
                    "products": ["p"],
                    "cvss_v3": {"version": "3.1", "baseScore": 9.8, "vectorString": V3},
                }
            ]
        )
    )["claims"]
    cna = extract(official(), "https://cveawg.mitre.org/api/cve/" + CVE)["claims"]
    nv = extract(nvd(), "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + CVE)["claims"]
    assert [c["provider"] for c in cna] == ["CNA", "ADP"]
    assert all(c["applicability"] == "cve_level" and c["product_ids"] == [] for c in cna + nv)
    out = cvss.public_metrics(vendor + cna + nv)
    assert len(out) == 4
    assert [c["origin"] for c in out if c["preferred"]] == ["vendor_advisory"]
    assert {c["origin"] for c in cvss.public_metrics(cna + nv) if c["preferred"]} == {"cve_record"}
    assert cvss.public_metrics(nv)[0]["preferred"]
    assert cna[0]["context"] == ["scenario"]


def test_source_evidence_integration_does_not_change_affectedness():
    d = csaf(
        [{"products": ["p"], "cvss_v3": {"version": "3.1", "baseScore": 9.8, "vectorString": V3}}]
    )
    db = connect(":memory:")
    ingest(db, json.dumps(d).encode(), URL, standards.csaf, "aruba")
    records = latest(db)
    inp = switching_evidence.inputs(db, records)
    assert inp["claims"][0]["scores"][0]["value"] == 9.8
    switching_evidence.project(inp, publication=None, generated_at="2026-11-04T12:00:00Z")
    assert records[0]["assessments"][0]["status"] == "affected"


def test_enrichment_bounds_routes_cache_and_durable_rate_state(monkeypatch):
    db = connect(":memory:")
    calls = []

    def fetch(url):
        calls.append(url)
        return json.dumps(official() if "cveawg" in url else nvd()).encode()

    monkeypatch.setattr(score_enrichment, "_fetch", fetch)
    assert score_enrichment.run(db, [CVE], limit=0)["attempted"] == 0
    for bad in [-1, 201, True]:
        with pytest.raises(ValueError):
            score_enrichment.run(db, [CVE], limit=bad)
    with pytest.raises(ValueError):
        score_enrichment.run(db, ["CVE-2024-12345?x=y"], limit=1)
    r = score_enrichment.run(db, [CVE], limit=2)
    assert r["succeeded"] == 2 and len(calls) == 2
    assert score_enrichment.run(db, [CVE], limit=2)["cached"] == 2
    assert len(score_enrichment.inputs(db, [CVE])["claims"]) == 3


def test_429_preserves_last_evidence_and_current_attempt(monkeypatch):
    db = connect(":memory:")
    monkeypatch.setattr(score_enrichment, "_fetch", lambda url: json.dumps(official()).encode())
    score_enrichment.run(db, [CVE], limit=1)
    db.execute("UPDATE score_documents SET checked_at=?", ("2020-01-01T00:00:00Z",))
    db.commit()
    monkeypatch.setattr(score_enrichment, "_clock", lambda: 2000000000.0)

    def denied(url):
        from urllib.error import HTTPError

        raise HTTPError(url, 429, "private detail", {"Retry-After": "120"}, None)

    monkeypatch.setattr(score_enrichment, "_fetch", denied)
    r = score_enrichment.run(db, [CVE], limit=2)
    assert r["failed"] == 1 and r["attempted"] == 1
    retained = score_enrichment.inputs(db, [CVE])
    assert retained["claims"][0]["value"] == 8.1
    assert retained["attempts"][0]["state"] == "rate_limited"
    assert "private detail" not in json.dumps(retained)
    assert score_enrichment.run(db, [CVE], limit=2)["attempted"] == 0


def test_publication_uses_safe_inputs_never_raw_metrics_and_invalid_score_keeps_other_claims():
    from infrastructure_impact.application.publication import public_projection
    from infrastructure_impact.application.query import state

    d = csaf(
        [
            {
                "products": ["p"],
                "cvss_v3": {"version": "3.1", "baseScore": 9.8, "vectorString": V3},
            },
            {
                "products": ["p"],
                "cvss_v3": {
                    "version": "3.1",
                    "baseScore": True,
                    "vectorString": V3,
                    "private": "SENTINEL",
                },
            },
        ]
    )
    db = connect(":memory:")
    ingest(db, json.dumps(d).encode(), URL, standards.csaf, "aruba")
    data = state(db)
    data["records"][0]["metrics"] = [{"private": "SENTINEL"}]
    data["records"][0]["extensions"] = {"private": "SENTINEL"}
    data["research"]["score_input"]["advisories"][0]["claims"][0]["raw"] = {"private": "SENTINEL"}
    public = public_projection(data)
    assert len(public["records"][0]["metrics"]) == 1
    assert public["records"][0]["assessments"][0]["status"] == "affected"
    assert "SENTINEL" not in json.dumps(public)
    assert "score_input" not in public["research"]


def test_csaf_versions_and_conditions_keep_product_attribution():
    from test_switching_evidence import tree

    d = tree()
    d["vulnerabilities"][0]["scores"] = [
        {"products": ["p"], "cvss_v3": {"version": "3.1", "baseScore": 9.8, "vectorString": V3}}
    ]
    c = extract(d)["claims"][0]
    assert c["product_context"][0]["product_id"] == "p"
    assert c["product_context"][0]["version_expressions"] == ["10.13", "10.13.1000"]
    assert c["context"] == ["Only when feature X is enabled."]


def test_persistent_pacing_and_interrupted_request_fail_closed(monkeypatch):
    db = connect(":memory:")
    monkeypatch.setattr(score_enrichment, "_clock", lambda: 2000000000.0)
    monkeypatch.setattr(score_enrichment, "_fetch", lambda url: json.dumps(official()).encode())
    assert score_enrichment.run(db, [CVE], limit=1)["succeeded"] == 1
    assert score_enrichment.run(db, ["CVE-2024-54321"], limit=1)["attempted"] == 0
    db.execute("UPDATE score_service_state SET pending=1,next_at=0")
    db.commit()
    monkeypatch.setattr(score_enrichment, "_clock", lambda: 2000009999.0)
    assert score_enrichment.run(db, ["CVE-2024-54321"], limit=1)["attempted"] == 0


def test_corrected_revision_retains_both_hashes_and_uses_latest_success(monkeypatch):
    db = connect(":memory:")
    tick = [2000000000.0]
    monkeypatch.setattr(score_enrichment, "_clock", lambda: tick[0])
    monkeypatch.setattr(
        score_enrichment,
        "_fetch",
        lambda url: json.dumps(official(8.1 if tick[0] == 2000000000.0 else 5.0)).encode(),
    )
    score_enrichment.run(db, [CVE], limit=1)
    tick[0] += 86401
    score_enrichment.run(db, [CVE], limit=1)
    assert db.execute("SELECT count(*) FROM score_documents").fetchone()[0] == 2
    assert db.execute("SELECT count(DISTINCT sha256) FROM evidence").fetchone()[0] == 2
    assert score_enrichment.inputs(db, [CVE])["claims"][0]["value"] == 5.0


def test_cvss_code_is_an_interpretation_fingerprint_dependency(monkeypatch):
    from pathlib import Path

    from infrastructure_impact.plugins.registry import default_registry
    from infrastructure_impact.settings import PACKAGE

    registry = default_registry()
    before = {p.id: registry.fingerprint(p.id) for p in registry.all()}
    original = Path.read_bytes
    target = (PACKAGE / "adapters/cvss.py").resolve()
    monkeypatch.setattr(
        Path, "read_bytes", lambda p: original(p) + b" " if p.resolve() == target else original(p)
    )
    assert all(before[p.id] != registry.fingerprint(p.id) for p in registry.all())


@pytest.mark.parametrize(
    "bad_vector",
    [V3.replace("AV:N", "AV:NA"), V3.replace("AC:L", "AC:"), V4.replace("UI:N", "UI:NP")],
)
def test_vector_enums_require_complete_exact_tokens(bad_vector):
    version = "4.0" if bad_vector.startswith("CVSS:4") else "3.1"
    assert (
        extract(
            csaf(
                [
                    {
                        "products": ["p"],
                        "cvss_v3": {
                            "version": version,
                            "baseScore": 8.0,
                            "vectorString": bad_vector,
                        },
                    }
                ]
            )
        )["claims"][0]["validation"]
        == "invalid"
    )


def test_one_malformed_score_cannot_discard_other_source_scores():
    d = csaf(
        [
            None,
            {
                "products": ["p"],
                "cvss_v3": {"version": "3.1", "baseScore": 9.8, "vectorString": V3},
            },
        ]
    )
    assert len(cvss.public_metrics(extract(d)["claims"])) == 1


@pytest.mark.parametrize(
    "field,value,vector",
    [
        ("exploitCodeMaturity", "HIGH", V3 + "/E:U"),
        ("modifiedAttackVector", "LOCAL", V3 + "/MAV:N"),
        ("providerUrgency", "RED", V4 + "/U:Green"),
    ],
)
def test_optional_structured_vector_disagreement_is_rejected(field, value, vector):
    version = "4.0" if vector.startswith("CVSS:4") else "3.1"
    r = extract(
        csaf(
            [
                {
                    "products": ["p"],
                    ("cvss_v4" if version == "4.0" else "cvss_v3"): {
                        "version": version,
                        "baseScore": 8.0,
                        "vectorString": vector,
                        field: value,
                    },
                }
            ]
        )
    )
    assert "structured_metric_disagreement" in r["claims"][0]["issues"]


def test_missing_vendor_product_binding_cannot_become_applicable_model_score():
    d = csaf([{"cvss_v3": {"version": "3.1", "baseScore": 9.8, "vectorString": V3}}])
    assert extract(d)["claims"][0]["applicability"] == "cve_level"


def test_missing_or_invalid_vendor_score_availability_in_evidence():
    d = csaf(
        [{"products": ["p"], "cvss_v3": {"version": "3.1", "baseScore": True, "vectorString": V3}}]
    )
    db = connect(":memory:")
    ingest(db, json.dumps(d).encode(), URL, standards.csaf, "aruba")
    inputs = switching_evidence.inputs(db, latest(db))
    assert inputs["claims"][0]["scores"] == []
    assert "score_invalid" in inputs["claims"][0]["issues"]


def test_enrichment_wrong_identity_and_network_failure_leave_explicit_unknown(monkeypatch):
    db = connect(":memory:")
    monkeypatch.setattr(
        score_enrichment,
        "_fetch",
        lambda url: json.dumps(official()).replace(CVE, "CVE-2024-54321").encode(),
    )
    r = score_enrichment.run(db, [CVE], limit=2)
    assert r["failed"] == 2 and score_enrichment.inputs(db, [CVE])["claims"] == []
    assert all(
        a["state"] == "invalid_record" for a in score_enrichment.inputs(db, [CVE])["attempts"]
    )


@pytest.mark.parametrize("key,version,vector", [("cvss_v2", "3.1", V3), ("cvss_v3", "4.0", V4)])
def test_score_form_cannot_contradict_declared_version(key, version, vector):
    r = extract(
        csaf(
            [
                {
                    "products": ["p"],
                    key: {"version": version, "baseScore": 9.8, "vectorString": vector},
                }
            ]
        )
    )
    assert r["claims"][0]["validation"] == "invalid"
    assert "score_form_version_disagreement" in r["claims"][0]["issues"]


def test_v4_vector_group_distinguishes_threat_environmental_and_supplemental():
    for suffix, group in [
        ("/U:Red", "CVSS-B"),
        ("/E:A", "CVSS-BT"),
        ("/CR:H", "CVSS-BE"),
        ("/E:A/CR:H", "CVSS-BTE"),
    ]:
        r = extract(
            csaf(
                [
                    {
                        "products": ["p"],
                        "cvss_v4": {
                            "version": "4.0",
                            "baseScore": 8.0,
                            "vectorString": V4 + suffix,
                        },
                    }
                ]
            )
        )
        assert cvss.public_metrics(r["claims"])[0]["vector_group"] == group


def test_official_transport_rejects_noncanonical_routes_before_network(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("Noncanonical route reached network transport")

    monkeypatch.setattr(score_enrichment, "build_opener", unexpected)
    for url in [
        "https://example.com/" + CVE,
        "https://cveawg.mitre.org/api/cve/" + CVE + "?private=secret",
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + CVE + "&key=secret",
    ]:
        with pytest.raises(ValueError):
            score_enrichment._fetch(url)


def test_nonfinite_retry_after_is_sanitized_and_pending_state_visible(monkeypatch):
    from urllib.error import HTTPError

    db = connect(":memory:")

    def denied(url):
        raise HTTPError(url, 429, "private", {"Retry-After": "NaN"}, None)

    monkeypatch.setattr(score_enrichment, "_fetch", denied)
    r = score_enrichment.run(db, [CVE], limit=1)
    assert r["failed"] == 1 and r["retry_at"]
    db.execute("UPDATE score_service_state SET pending=1 WHERE source=?", ("cve_record",))
    db.commit()
    assert score_enrichment.inputs(db, [CVE])["attempts"][0]["state"] == "request_state_unresolved"


def test_vendor_priority_requires_matching_scoped_product():
    vendor = extract(
        csaf(
            [
                {
                    "products": ["p"],
                    "cvss_v3": {"version": "3.1", "baseScore": 9.8, "vectorString": V3},
                }
            ]
        )
    )["claims"]
    unbound = extract(
        csaf([{"cvss_v3": {"version": "3.1", "baseScore": 9.8, "vectorString": V3}}])
    )["claims"]
    cna = extract(official(), "https://cveawg.mitre.org/api/cve/" + CVE)["claims"]
    assert all(
        c["origin"] == "cve_record" for c in cvss.public_metrics(unbound + cna) if c["preferred"]
    )
    assert any(
        c["origin"] == "vendor_advisory"
        for c in cvss.public_metrics(vendor + cna)
        if c["preferred"]
    )


def test_vendor_aggregate_severity_is_separate_advisory_context():
    d = csaf(
        [{"products": ["p"], "cvss_v3": {"version": "3.1", "baseScore": 9.8, "vectorString": V3}}]
    )
    d["document"]["aggregate_severity"] = {
        "text": "Publisher High",
        "namespace": "https://support.hpe.com/rating",
        "private": "SENTINEL",
    }
    r = extract(d)
    rating = r["vendor_severity"][0]
    assert rating["rating"] == "Publisher High"
    assert rating["namespace"] == "https://support.hpe.com/rating" and rating["scheme"] is None
    assert (
        rating["scope"] == "advisory" and rating["cve_id"] is None and rating["product_ids"] == []
    )
    assert rating["source"]["source_locator"] == "/document/aggregate_severity"
    assert "SENTINEL" not in json.dumps(r)
    db = connect(":memory:")
    ingest(db, json.dumps(d).encode(), URL, standards.csaf, "aruba")
    inp = switching_evidence.inputs(db, latest(db))
    assert inp["claims"][0]["vendor_severity"][0]["rating"] == "Publisher High"
    assert inp["claims"][0]["vendor_severity"][0]["scope"] == "advisory"
    projected = switching_evidence.project(
        inp, publication=None, generated_at="2026-11-04T12:00:00Z"
    )
    assert projected["claims"][0]["vendor_severity"][0]["rating"] == "Publisher High"
    assert cvss.public_metrics(r["claims"])[0]["value"] == 9.8


def test_cisco_api_sir_requires_exact_advisory_identity_and_provenance():
    url = "https://apix.cisco.com/security/advisories/v2/all?pageIndex=1&pageSize=100"
    raw = json.dumps(
        {
            "advisories": [
                {"advisoryId": "T-1", "sir": "Critical", "private": "SENTINEL"},
                {"advisoryId": "OTHER", "sir": "High"},
            ]
        }
    ).encode()
    r = cvss.extract(raw, url, "cisco", {"advisory_id": "T-1"})
    assert len(r["vendor_severity"]) == 1 and r["claims"] == []
    rating = r["vendor_severity"][0]
    assert rating["scheme"] == "Cisco SIR" and rating["rating"] == "Critical"
    assert rating["source"]["source_sha256"] == sha256(raw).hexdigest()
    assert rating["source"]["source_locator"] == "/advisories/0/sir"
    assert rating["advisory_id"] == "T-1" and rating["scope"] == "advisory"
    assert "SENTINEL" not in json.dumps(r)
    assert cvss.extract(raw, url, "cisco", {"advisory_id": "MISSING"})["vendor_severity"] == []


def test_retained_identity_bound_api_sir_joins_selected_advisory_only(monkeypatch):
    from test_switching_backfill import capture, entry, page, run

    from infrastructure_impact.collection import switching_backfill as backfill

    db = connect(":memory:")
    monkeypatch.setattr(
        backfill.CiscoOpenVuln, "get_json", capture({1: page([entry("T-1", sir="High")])}, [])
    )
    monkeypatch.setattr(backfill.archive, "document", lambda *args: None)
    run(db, page_limit=1, document_limit=1)
    inp = switching_evidence.score_inputs(
        db, [{"vendor": "cisco", "advisory_id": "T-1", "cves": [CVE]}]
    )
    assert inp["vendor_severity"][0]["rating"] == "High"
    assert inp["vendor_severity"][0]["revision"] is None
    assert inp["vendor_severity"][0]["source"]["retrieved_at"]
    assert (
        switching_evidence.score_inputs(
            db, [{"vendor": "cisco", "advisory_id": "OTHER", "cves": [CVE]}]
        )["vendor_severity"]
        == []
    )


def test_current_api_page_without_identity_does_not_revive_old_rating(monkeypatch):
    from test_switching_backfill import capture, entry, page, run

    from infrastructure_impact.collection import switching_backfill as backfill
    from infrastructure_impact.storage.repository import evidence

    db = connect(":memory:")
    monkeypatch.setattr(
        backfill.CiscoOpenVuln, "get_json", capture({1: page([entry("T-1", sir="High")])}, [])
    )
    monkeypatch.setattr(backfill.archive, "document", lambda *args: None)
    run(db, page_limit=1, document_limit=1)
    source = db.execute("SELECT * FROM evidence").fetchone()["source_url"]
    with db:
        ev = evidence(db, page([entry("OTHER", sir="Low")]), source)
        db.execute("UPDATE switching_backfill_pages SET evidence_id=?", (ev["id"],))
        db.execute(
            "INSERT INTO score_vendor_observations(source_url,evidence_id,observed_at) VALUES(?,?,?)",
            (source, ev["id"], "2030-01-01T00:00:00Z"),
        )
    assert (
        switching_evidence.score_inputs(
            db, [{"vendor": "cisco", "advisory_id": "T-1", "cves": [CVE]}]
        )["vendor_severity"]
        == []
    )


def test_vendor_rating_projection_strips_unknown_fields_and_rejects_cve_relabel():
    import copy

    d = csaf([])
    d["document"]["aggregate_severity"] = {"text": "High"}
    db = connect(":memory:")
    ingest(db, json.dumps(d).encode(), URL, standards.csaf, "aruba")
    inp = switching_evidence.inputs(db, latest(db))
    rating = inp["claims"][0]["vendor_severity"][0]
    rating["private"] = "SENTINEL"
    public = switching_evidence.project(inp, publication=None, generated_at="2026-11-04T12:00:00Z")
    assert "SENTINEL" not in json.dumps(public)
    broken = copy.deepcopy(inp)
    broken["claims"][0]["vendor_severity"][0]["cve_id"] = CVE
    from jsonschema import ValidationError

    with pytest.raises(ValidationError):
        switching_evidence.project(broken, publication=None, generated_at="2026-11-04T12:00:00Z")


def test_api_rating_latest_success_observation_survives_a_b_a(monkeypatch):
    from test_switching_backfill import capture, entry, page, run

    from infrastructure_impact.collection import switching_backfill as backfill
    from infrastructure_impact.storage.repository import evidence

    db = connect(":memory:")
    monkeypatch.setattr(
        backfill.CiscoOpenVuln, "get_json", capture({1: page([entry("T-1", sir="High")])}, [])
    )
    monkeypatch.setattr(backfill.archive, "document", lambda *args: None)
    run(db, page_limit=1, document_limit=1)
    a = db.execute("SELECT * FROM evidence").fetchone()
    assert db.execute("SELECT count(*) FROM score_vendor_observations").fetchone()[0] == 1
    with db:
        b = evidence(db, page([entry("OTHER", sir="Low")]), a["source_url"])
        db.execute(
            "INSERT INTO score_vendor_observations(source_url,evidence_id,observed_at) VALUES(?,?,?)",
            (a["source_url"], b["id"], "2030-01-01T00:00:00Z"),
        )
    records = [{"vendor": "cisco", "advisory_id": "T-1", "cves": [CVE]}]
    assert switching_evidence.score_inputs(db, records)["vendor_severity"] == []
    with db:
        db.execute(
            "INSERT INTO score_vendor_observations(source_url,evidence_id,observed_at) VALUES(?,?,?)",
            (a["source_url"], a["id"], "2030-01-02T00:00:00Z"),
        )
    rating = switching_evidence.score_inputs(db, records)["vendor_severity"][0]
    assert rating["rating"] == "High" and rating["source"]["source_sha256"] == a["sha256"]
    assert rating["source"]["retrieved_at"] == "2030-01-02T00:00:00Z"


def test_official_inputs_reextract_retained_raw_instead_of_trusting_old_interpretation(monkeypatch):
    db = connect(":memory:")
    monkeypatch.setattr(score_enrichment, "_fetch", lambda url: json.dumps(official()).encode())
    score_enrichment.run(db, [CVE], limit=1)
    previous = json.loads(db.execute("SELECT normalized FROM score_documents").fetchone()[0])
    previous["claims"][0]["value"] = 1.0
    previous["claims"][0]["private"] = "SENTINEL"
    with db:
        db.execute("UPDATE score_documents SET normalized=?", (json.dumps(previous),))
    current = score_enrichment.inputs(db, [CVE])
    assert current["claims"][0]["value"] == 8.1
    assert "SENTINEL" not in json.dumps(current)


def test_incomplete_vendor_yields_valid_official_fallback_in_strict_study_claim(monkeypatch):
    d = csaf([{"products": ["p"], "cvss_v3": {"version": "3.1", "baseScore": 9.8}}])
    db = connect(":memory:")
    ingest(db, json.dumps(d).encode(), URL, standards.csaf, "aruba")
    monkeypatch.setattr(score_enrichment, "_fetch", lambda url: json.dumps(official()).encode())
    score_enrichment.run(db, [CVE], limit=1)
    inp = switching_evidence.inputs(db, latest(db))
    report = switching_evidence.project(inp, publication=None, generated_at="2026-11-04T12:00:00Z")
    scores = report["claims"][0]["scores"]
    assert len(scores) == 3
    assert {s["origin"] for s in scores if s["preferred"]} == {"cve_record"}
    assert [s for s in scores if s["origin"] == "vendor_advisory"][0]["validation"] == "incomplete"
    assert all(
        s["applicability"] == "cve_level" and not s["product_ids"]
        for s in scores
        if s["origin"] == "cve_record"
    )
