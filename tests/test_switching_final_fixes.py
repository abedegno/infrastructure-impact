"""Synthetic final-boundary regressions; no retained publisher bytes."""

import copy
import json
import subprocess

import pytest
from test_kev_delivery import collected as collected
from test_switching_delivery import FIXTURE, delivery, rehash_part
from test_switching_delivery import study as study
from test_switching_evidence import AT, URL, tree

from infrastructure_impact.adapters import standards
from infrastructure_impact.application import switching_comparison as comparison
from infrastructure_impact.application import switching_evidence as evidence
from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.query import state
from infrastructure_impact.application.static_delivery import encode
from infrastructure_impact.storage.repository import connect, ingest, latest


@pytest.mark.parametrize(
    "field,target,code",
    [
        ("initial_release_date", "initial_published_at", "initial_publication_date"),
        ("current_release_date", "updated_at", "update_date"),
    ],
)
@pytest.mark.parametrize("products", [True, False])
def test_local_publisher_dates_survive_publication(tmp_path, field, target, code, products):
    data = tree()
    data["document"]["tracking"][field] = "2024-04-07T01:00:00"
    if not products:
        data["vulnerabilities"][0]["product_status"] = {}
    with connect(":memory:") as db:
        ingest(db, json.dumps(data).encode(), URL, standards.csaf, "aruba")
        retained = latest(db)
        assert (
            retained[0]["published_at" if target == "initial_published_at" else "updated_at"]
            == "2024-04-07T01:00:00"
        )
        projected = evidence.project(
            evidence.inputs(db, latest(db)), publication=None, generated_at=AT
        )
        claim = projected["claims"][0]
        assert claim[target] is None
        assert code + "_unusable" in claim["issues"]
        assert code + "_missing" in claim["issues"]
        generation = publish(state(db), tmp_path)
    full = json.loads((generation / "switching-comparison.json").read_text())
    c = full["inputs"]["evidence"]["claims"][0]
    assert c[target] is None
    assert c["status"] == ("affected" if products else "unknown")
    selected = comparison.select_report(full, vendor="aruba", window="undated")
    assert selected["rows"][0]["counts"]["affected_cves"] == int(
        products and target == "initial_published_at"
    )


def mutate(report, fault):
    c = (
        next(c for c in report["inputs"]["evidence"]["claims"] if c["bundle"])
        if fault == "bundle"
        else report["inputs"]["evidence"]["claims"][0]
    )
    if fault == "model":
        c["platform_bindings"][0]["model"] = "7500"
    elif fault == "family":
        c["family"] = "aruba-aoscx"
    elif fault == "alias":
        c["platform_bindings"][0]["basis"] = "reviewed_alias"
    elif fault == "platform":
        c["named_platforms"] = ["foreign platform"]
    elif fault == "unresolved":
        c["platform_bindings"][0]["basis"] = "unresolved"
    elif fault == "bundle":
        c["bundle"]["member_advisory_ids"] = ["OTHER-ADVISORY"]
    elif fault == "source":
        c["source"]["source_url"] = "https://example.com/advisory"
    elif fault == "publisher_source":
        c["publisher"]["source"] = {**c["source"], "source_sha256": "f" * 64}
    elif fault == "missing":
        c["updated_at"] = None
        c["issues"] = [i for i in c["issues"] if i != "update_date_missing"]
    elif fault == "remediation_product":
        c["remediations"][0]["product_ids"] = ["OTHER"]
    elif fault == "remediation_source":
        c["remediations"][0]["source"]["source_url"] = "https://www.cisco.com/advisory"
    elif fault == "remediation_scope":
        r = c["remediations"][0]
        r["scope_binding"] = dict(
            basis="same_source_row", cve_id="CVE-2099-99999", source=copy.deepcopy(c["source"])
        )
    elif fault == "score_cve":
        c["scores"][0]["cve_id"] = "CVE-2099-99999"
    elif fault == "score_product":
        c["scores"][0]["product_ids"] = ["OTHER"]
    elif fault == "score_source":
        c["scores"][0]["source"]["source_url"] = (
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        )
    elif fault == "score_scope":
        c["scores"][0]["scope"] = "unresolved"
    elif fault == "binding_source":
        c["platform_bindings"][0]["source"]["source_url"] = "https://www.cisco.com/synthetic"
    elif fault == "binding_model_missing":
        c["platform_bindings"][0]["model"] = None
    elif fault == "platform_extra":
        c["named_platforms"].append("Unbound publisher platform")
    elif fault == "model_issue":
        c.update(platform_bindings=[], named_platforms=[], scope_level="os_family")
        c["issues"] = [i for i in c["issues"] if i != "model_binding_unresolved"]
    elif fault in {"remediation_identity", "remediation_locator"}:
        r = c["remediations"][0]
        r["scope_binding"] = dict(
            basis="same_source_row", cve_id=c["cve_id"], source=copy.deepcopy(c["source"])
        )
        if fault == "remediation_identity":
            r["scope_binding"]["source"]["source_sha256"] = "f" * 64
        else:
            r["source"]["source_locator"] = "/unrelated/row"
    elif fault == "remediation_unresolved":
        c["remediations"][0]["product_ids"] = []
        c["issues"] = [i for i in c["issues"] if i != "remediation_product_scope_unresolved"]
    elif fault in {"remediation_statement", "remediation_date", "remediation_id"}:
        key, issue = {
            "remediation_statement": ("published_availability", "availability_statement_missing"),
            "remediation_date": ("availability_date", "availability_date_missing"),
            "remediation_id": ("publisher_id", "remediation_publisher_id_missing"),
        }[fault]
        c["remediations"][0][key] = None
        c["issues"] = [i for i in c["issues"] if i != issue]
    elif fault == "score_value":
        c["scores"][0]["value"] = None
        c["issues"] = [i for i in c["issues"] if i != "score_value_missing"]
    elif fault == "publisher_missing":
        c["publisher"]["id"] = None
        c["issues"] = [i for i in c["issues"] if i != "publisher_id_missing"]
    elif fault == "bundle_date":
        c = next(c for c in report["inputs"]["evidence"]["claims"] if c["bundle"])
        c["bundle"]["published_at"] = None
        c["issues"] = [i for i in c["issues"] if i != "bundle_publication_date_missing"]
    elif fault in {"rating_advisory", "rating_missing"}:
        c["vendor_severity"] = [
            dict(
                vendor=c["vendor"],
                advisory_id=c["advisory_id"],
                rating="High",
                scheme=None,
                namespace=None,
                scope="advisory",
                cve_id=None,
                product_ids=[],
                source=copy.deepcopy(c["source"]),
                revision=c["revision"],
                issues=["vendor_severity_scheme_missing", "vendor_severity_namespace_missing"],
            )
        ]
        if fault == "rating_advisory":
            c["vendor_severity"][0]["advisory_id"] = "OTHER"
        else:
            c["vendor_severity"][0]["issues"] = []
    elif fault == "duplicate":
        report["inputs"]["evidence"]["claims"].append(copy.deepcopy(c))
    for claim in report["inputs"]["evidence"]["claims"]:
        claim["claim_id"] = evidence.definition_sha256(
            {k: v for k, v in claim.items() if k != "claim_id"}
        )
    if fault == "identity":
        c["claim_id"] = "f" * 64
    return comparison._select_report(report, evaluated_at=report["evaluated_at"])


FAULTS = [
    "model",
    "family",
    "alias",
    "platform",
    "unresolved",
    "bundle",
    "source",
    "publisher_source",
    "missing",
    "remediation_product",
    "remediation_source",
    "remediation_scope",
    "score_cve",
    "score_product",
    "score_source",
    "score_scope",
    "duplicate",
    "identity",
    "binding_source",
    "binding_model_missing",
    "platform_extra",
    "model_issue",
    "remediation_identity",
    "remediation_locator",
    "remediation_unresolved",
    "remediation_statement",
    "remediation_date",
    "remediation_id",
    "score_value",
    "publisher_missing",
    "bundle_date",
    "rating_advisory",
    "rating_missing",
]


@pytest.mark.parametrize("fault", FAULTS)
def test_semantic_parity_with_consistent_rows(fault):
    report = mutate(copy.deepcopy(FIXTURE["comparison_base_report"]), fault)
    with pytest.raises(ValueError):
        evidence.validate_comparison(report)
    script = "const fs=require('fs'),vm=require('vm');const c={window:{},URL};vm.createContext(c);for(const f of ['kev','switching-contracts','switching'])vm.runInContext(fs.readFileSync('infrastructure_impact/web/'+f+'.js','utf8'),c);try{c.window.InfrastructureSwitching.selectReport(JSON.parse(fs.readFileSync(0,'utf8')));process.stdout.write('accepted')}catch(e){process.stdout.write('rejected')}"
    assert (
        subprocess.check_output(["node", "-e", script], input=json.dumps(report).encode())
        == b"rejected"
    )


@pytest.mark.parametrize("fault", FAULTS)
def test_rehashed_static_semantic_parity(study, tmp_path, fault):
    generation = publish(study, tmp_path)
    report = mutate(json.loads((generation / "switching-comparison.json").read_text()), fault)
    index = json.loads((generation / "data/index.json").read_text())
    assert len(index["switching"]["claims"]) == 1
    part = index["switching"]["claims"][0]
    claims = report["inputs"]["evidence"]["claims"]
    part["claim_ids"] = [c["claim_id"] for c in claims]
    rehash_part(generation, part["part"], lambda value: value.__setitem__(slice(None), claims))
    summary = comparison.summary(report)
    rehash_part(
        generation,
        index["switching"]["summary"],
        lambda value: (value.clear(), value.update(summary)),
    )
    (generation / "data/index.json").write_bytes(encode(index))
    assert "error" in delivery(generation)


@pytest.mark.parametrize("number", [5, 5.0, 0.1, 1e-6, 1e-7, 5e-324, -0.0])
def test_lossless_claim_numeric_fingerprints_match_browser(number):
    from test_switching_comparison import claim, report

    c = claim()
    c["scores"] = copy.deepcopy(
        FIXTURE["comparison_base_report"]["inputs"]["evidence"]["claims"][0]["scores"]
    )
    c["scores"][0]["value"] = number
    c["scores"][0]["cve_id"] = c["cve_id"]
    for score in c["scores"]:
        score["cve_id"] = c["cve_id"]
    full = report([c])
    script = "const fs=require('fs'),vm=require('vm');const c={window:{}};vm.createContext(c);for(const f of ['kev','switching-contracts','switching'])vm.runInContext(fs.readFileSync('infrastructure_impact/web/'+f+'.js','utf8'),c);const r=JSON.parse(fs.readFileSync(0,'utf8'));c.window.InfrastructureSwitching.selectReport(r);process.stdout.write('accepted');"
    assert (
        subprocess.check_output(["node", "-e", script], input=json.dumps(full).encode())
        == b"accepted"
    )
    if number == 5:
        other = copy.deepcopy(c)
        other["scores"][0]["value"] = 5.0 if type(number) is int else 5
        assert (
            report([other])["inputs"]["evidence"]["claims"][0]["claim_id"]
            == full["inputs"]["evidence"]["claims"][0]["claim_id"]
        )


@pytest.mark.parametrize("sequence", [9007199254740992, 9007199254740993, -9007199254740992])
def test_large_literal_publisher_sequence_survives_ingest_and_publication(tmp_path, sequence):
    data = tree()
    data["document"]["tracking"]["version"] = sequence
    with connect(":memory:") as db:
        ingest(db, json.dumps(data).encode(), URL, standards.csaf, "aruba")
        generation = publish(state(db), tmp_path)
    full = json.loads((generation / "switching-comparison.json").read_text())
    claim = full["inputs"]["evidence"]["claims"][0]
    assert claim["publisher"]["sequence"] == str(sequence)
    assert "publisher_sequence_integer_preserved_as_text" in claim["issues"]
    assert delivery(generation)["value"] == full
