"""Authored finite-binding contracts; typed hash injection never proves source bytes."""

import copy
import json

import pytest
from jsonschema import ValidationError
from test_switching_aruba_fix_links import AT, browser, native_stream, reidentify

from infrastructure_impact.adapters import switching
from infrastructure_impact.application import switching_evidence as evidence
from infrastructure_impact.settings import PACKAGE

SAMPLES = json.loads((PACKAGE.parent / "tests/fixtures/reviewed-aruba-authored.json").read_text())[
    "samples"
]


def extracted(sample, data=None, *, digest=None, url=None):
    return switching._csaf(
        json.dumps(data or sample["data"]).encode(),
        url or sample["source_url"],
        "aruba",
        {"advisory_id": sample["advisory_id"]},
        digest or sample["source_sha256"],
    )


def projected(sample):
    result = extracted(sample)

    def stamp(value):
        if isinstance(value, dict):
            if "retrieved_at" in value:
                value["retrieved_at"] = AT
            for child in value.values():
                stamp(child)
        elif isinstance(value, list):
            for child in value:
                stamp(child)

    stamp(result)
    for claim in result["claims"]:
        claim["revision"] = "authored-revision"
    result.pop("bundles")
    return evidence.project(result, publication=None, generated_at=AT)


def links(report):
    return [
        (c, r)
        for c in report["claims"]
        for r in c["remediations"]
        if r.get("scope_binding", {}).get("basis") == "reviewed_source_sections"
    ]


def test_packaged_registry_is_closed_finite_and_mutation_isolated():
    from jsonschema import Draft202012Validator

    from infrastructure_impact import remediation_bindings as registry

    value = registry.definition()
    schema = json.loads((PACKAGE / "schemas/reviewed-remediation-bindings-v1.json").read_text())
    Draft202012Validator(schema).validate(value)
    assert len(value["sources"]) == 8
    csaf = [s for s in value["sources"] if s["kind"] == "csaf"]
    assert [len(s["bindings"]) for s in csaf] == [65, 20, 16, 15, 170]
    html = [s for s in value["sources"] if s["kind"] == "arista_marker_list"]
    assert sorted(len(s["bindings"]) for s in html) == [1, 1, 2]
    value["sources"][0]["operator_path"] = "/private/not-allowed"
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(value)
    assert "operator_path" not in registry.definition()["sources"][0]


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda s: s["advisory_id"])
def test_exact_pairs_pass_every_boundary(sample, monkeypatch):
    report = projected(sample)
    assert len(links(report)) == sample["links"]
    evidence.validate_evidence(report)
    assert native_stream(report, monkeypatch) == report["claims"]
    assert browser(report) == browser(report, stream=True) == "accepted"
    if sample["advisory_id"] == "HPESBNW05134":
        c, r = next(
            (c, r) for c, r in links(report) if c["product"] != r["scope_binding"]["fixed_product"]
        )
        assert c["product"] == "HPE Aruba Networking AOS-CX"
        assert r["source"]["source_locator"].endswith("/remediations/1")
    if sample["advisory_id"] == "ARUBA-PSA-2022-012":
        assert all(
            c["product_id"] == ">=10.10.0000|<=10.10.0002"
            for c, r in links(report)
            if c["cve_id"] == "CVE-2022-23679"
        )
        assert all(
            r["availability_date"] is None
            for c, r in links(report)
            if c["cve_id"] == "CVE-2022-23683"
        )
        assert all(
            r["availability"] == "unknown"
            for c in report["claims"]
            if c["cve_id"] == "CVE-2022-23679"
            and c["status"] == "fixed"
            and c["product_id"] != "10.10.1000"
            for r in c["remediations"]
        )
    if sample["advisory_id"] == "ARUBA-PSA-2022-004":
        direct = [
            r
            for c in report["claims"]
            if c["cve_id"] == "CVE-2021-41002" and c["status"] == "affected"
            for r in c["remediations"]
            if not r.get("scope_binding")
        ]
        assert len(direct) == 4


@pytest.mark.parametrize(
    "mutation",
    ["hash", "cve", "parent", "date", "future", "planned", "unavailable", "truncated", "proof"],
)
def test_fix_drift_preserves_affected_evidence_and_omits_links(mutation):
    sample = SAMPLES[0]
    data = copy.deepcopy(sample["data"])
    rem = data["vulnerabilities"][0]["remediations"][0]
    digest = sample["source_sha256"]
    if mutation == "hash":
        digest = "f" * 64
    elif mutation == "cve":
        data["vulnerabilities"][0]["cve"] = "CVE-2025-99999"
    elif mutation == "parent":
        data["product_tree"]["branches"][0]["branches"][0]["name"] = "Other product"
    elif mutation == "date":
        rem["date"] = None
    elif mutation == "future":
        data["document"]["tracking"]["current_release_date"] = "2020-01-01T00:00:00Z"
    else:
        rem["details"] += {
            "planned": "\nA fix is planned.",
            "unavailable": "\nNo fix is available.",
            "truncated": "x" * 4001,
            "proof": "\nOther scope.",
        }[mutation]
    result = extracted(sample, data, digest=digest)
    assert not links(result)
    assert sum(c["status"] == "affected" for c in result["claims"]) == 5
    assert "reviewed_fix_source_drift" in result["issues"]


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "duplicate",
        "duplicate_version",
        "cve",
        "revision",
        "publisher",
        "url",
        "hash",
        "product",
        "locator",
        "version",
        "binding",
        "joint_details",
        "joint_date",
        "joint_planned",
        "joint_published",
        "fixed_product_ids",
        "all_hashes",
    ],
)
def test_forged_links_reject_full_compiled_browser_and_native(monkeypatch, mutation):
    report = projected(SAMPLES[-1])
    c, r = links(report)[0]
    f = next(
        f
        for f in report["claims"]
        if f["source"] == r["scope_binding"]["fixed_source"] and f["cve_id"] == c["cve_id"]
    )
    fr = next(fr for fr in f["remediations"] if fr["category"] == "vendor_fix")
    if mutation == "missing":
        report["claims"].remove(f)
    elif mutation.startswith("duplicate"):
        dupe = copy.deepcopy(f)
        dupe["conditions"].append("distinct sibling")
        if mutation == "duplicate_version":
            dupe["version_expressions"] = ["AOS-CX 99.99.9999"]
        report["claims"].append(dupe)
    elif mutation in {"cve", "revision", "publisher", "product", "version"}:
        key = {"cve": "cve_id", "version": "version_expressions"}.get(mutation, mutation)
        f[key] = {
            "cve": "CVE-2026-99999",
            "revision": "other",
            "publisher": dict(f["publisher"], sequence="999"),
            "product": "Other product",
            "version": ["99.99.9999"],
        }[mutation]
    elif mutation in {"url", "hash", "locator"}:
        key = {"url": "source_url", "hash": "source_sha256", "locator": "source_locator"}[mutation]
        f["source"][key] = "e" * 64 if mutation == "hash" else f["source"][key] + "/other"
    elif mutation == "binding":
        r["scope_binding"]["fixed_product_id"] = "other"
    elif mutation.startswith("joint_"):
        key, value = {
            "joint_details": ("details", "Forged fixed release."),
            "joint_date": ("availability_date", "2026-10-01"),
            "joint_planned": ("availability", "planned"),
            "joint_published": ("published_availability", "Forged fixed release."),
        }[mutation]
        r[key] = fr[key] = value
    elif mutation == "fixed_product_ids":
        fr["product_ids"] = []
    else:

        def alter(value):
            if isinstance(value, dict):
                if "source_sha256" in value:
                    value["source_sha256"] = "f" * 64
                for child in value.values():
                    alter(child)
            elif isinstance(value, list):
                for child in value:
                    alter(child)

        alter(report)
    reidentify(report)
    for compiled in (False, True):
        shape = evidence._compiled_validators() if compiled else evidence._validators()
        with pytest.raises((ValueError, ValidationError)):
            shape["switching-evidence-v1.json"].validate(report)
            evidence._validate_evidence_semantics(report)
    with pytest.raises((ValueError, ValidationError)):
        native_stream(report, monkeypatch)
    assert browser(report) == browser(report, stream=True) == "rejected"


def test_existing_004_remediation_event_remains_one():
    from infrastructure_impact.application import kev, switching_comparison

    report = projected(SAMPLES[3])
    full = switching_comparison.build_report(
        report,
        kev.build_report({}, [], publication=None, generated_at=AT),
        definition=evidence.definition(),
        publication=None,
        generated_at=AT,
        observation_end=AT[:10],
    )
    row = next(row for row in full["rows"] if row["vendor"] == "aruba")
    assert row["counts"]["remediation_events"] == 1


def test_rule_results_cannot_poison_cached_metadata():
    from infrastructure_impact import remediation_bindings as registry

    report = projected(SAMPLES[0])
    c, r = links(report)[0]
    rule = registry.rule_for(c)
    rule["availability_proof_literals"].clear()
    rule["fixed_product"] = "Injected"
    assert registry.rule_for(c)["availability_proof_literals"]
    registry.validate_link(c, r, r["scope_binding"], report["claims"])


def test_registered_native_siblings_keep_existing_retention_budget(monkeypatch):
    from infrastructure_impact.application.publication_reader import PublicationReader

    report = projected(SAMPLES[-1])
    raw = [json.dumps(c, ensure_ascii=True).encode() for c in report["claims"]]
    reader = PublicationReader.__new__(PublicationReader)
    reader.identity = dict(publication=None, generated_at=AT)
    reader.limits = dict(selected=max(map(len, raw)) + 1, stream=128000000)
    monkeypatch.setattr(reader, "field", lambda root, key: report[key])
    monkeypatch.setattr(
        reader,
        "_claim_routes",
        lambda: [(c["claim_id"], i, i + 1, len(raw[i])) for i, c in enumerate(report["claims"])],
    )
    monkeypatch.setattr(reader, "_stream", lambda root, first, end, *a, **kw: iter([raw[first]]))
    with pytest.raises(ValueError, match="cross-claim linkage byte budget"):
        list(reader.iter_claims())
