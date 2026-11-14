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


@pytest.mark.parametrize("irrelevant", [0, 120])
def test_complete_validation_visits_only_registered_join_candidates(monkeypatch, irrelevant):
    """A whole-corpus sibling scan must not multiply unrelated CVEs/advisories by links."""
    from infrastructure_impact import remediation_bindings as registry

    report = projected(SAMPLES[0])
    original = copy.deepcopy(report["claims"][-1])
    for index in range(irrelevant):
        claim = copy.deepcopy(original)
        claim["advisory_id"] = f"unrelated-{index}"
        claim["cve_id"] = f"CVE-2026-{10000 + index}"
        claim["remediations"] = []
        if index % 2:
            claim["vendor"] = "arista"
            claim["source"]["source_url"] = (
                "https://www.arista.com/en/support/advisories-notices/security-advisory/"
                f"unrelated-{index}"
            )
        report["claims"].append(claim)
    reidentify(report)
    visits = 0
    searches = 0
    fixed_siblings = registry.fixed_siblings
    build_buckets = evidence._reviewed_candidate_buckets
    index_sizes = []

    def counted_index(claims):
        index_sizes.append(len(claims))
        return build_buckets(claims)

    def counted(claim, rule, candidates):
        nonlocal searches
        searches += 1

        def observed():
            nonlocal visits
            for candidate in candidates:
                visits += 1
                yield candidate

        return fixed_siblings(claim, rule, observed())

    monkeypatch.setattr(registry, "fixed_siblings", counted)
    monkeypatch.setattr(evidence, "_reviewed_candidate_buckets", counted_index)
    evidence.validate_evidence(report)
    assert searches == len(links(report)) == 5
    assert index_sizes == [22 + irrelevant]
    # The authored source contains 5 affected + 5 fixed claims of the same CVE.
    # Unrelated rows may be indexed once, but never enter the exact join predicate.
    assert visits == 50


@pytest.mark.parametrize(
    "field",
    [
        "vendor",
        "advisory_id",
        "revision",
        "publisher",
        "cve_id",
        "family",
        "scope",
        "initial_published_at",
        "updated_at",
        "status",
        "product",
        "product_id",
        "source_locator",
        "source_url",
        "source_sha256",
        "retrieved_at",
        "version_expressions",
        "duplicate",
        "duplicate_version",
    ],
)
def test_indexed_registered_matcher_agrees_with_full_scan_on_forged_siblings(monkeypatch, field):
    """A necessary-prefix bucket must not replace any exact ownership predicate."""
    from infrastructure_impact import remediation_bindings as registry

    report = projected(SAMPLES[0])
    claim, remediation = links(report)[0]
    fixed = registry.fixed_siblings(claim, registry.rule_for(claim), report["claims"])[0]
    # Reach the join before an independently invalid forged fixed row is visited.
    report["claims"].remove(claim)
    report["claims"].insert(0, claim)
    if field.startswith("duplicate"):
        duplicate = copy.deepcopy(fixed)
        duplicate["conditions"].append("distinct duplicate")
        if field == "duplicate_version":
            duplicate["version_expressions"] = ["99.99.9999"]
        report["claims"].insert(0, duplicate)
    elif field == "publisher":
        fixed["publisher"]["sequence"] = "changed"
    elif field in {"source_locator", "source_url", "source_sha256", "retrieved_at"}:
        fixed["source"][field] = {
            "source_locator": "/different",
            "source_url": fixed["source"]["source_url"] + "/different",
            "source_sha256": "e" * 64,
            "retrieved_at": "2026-11-08T12:00:00Z",
        }[field]
    else:
        fixed[field] = {
            "vendor": "arista",
            "advisory_id": "different",
            "revision": "different",
            "cve_id": "CVE-2026-99999",
            "family": "aruba-aos",
            "scope": "advisory",
            "initial_published_at": "2020-01-01T00:00:00Z",
            "updated_at": "2020-01-01T00:00:00Z",
            "status": "affected",
            "product": "Other product",
            "product_id": None,
            "version_expressions": ["99.99.9999"],
        }[field]
    reidentify(report)
    oracle = registry.fixed_siblings
    checked = []

    def compared(claim, rule, candidates):
        result = oracle(claim, rule, candidates)
        expected = oracle(claim, rule, report["claims"])
        assert [id(row) for row in result] == [id(row) for row in expected]
        checked.append(result)
        return result

    monkeypatch.setattr(registry, "fixed_siblings", compared)
    # Semantics directly exercises all predicate fields, even for forged shapes.
    with pytest.raises(ValueError):
        evidence._validate_claim_semantics(report["claims"], evidence.definition())
    assert checked


def test_candidate_buckets_preserve_occurrences_order_and_optional_nulls():
    from infrastructure_impact import remediation_bindings as registry

    report = projected(SAMPLES[0])
    claim, _ = links(report)[0]
    rule = registry.rule_for(claim)
    fixed = registry.fixed_siblings(claim, rule, report["claims"])[0]
    duplicate = copy.deepcopy(fixed)
    duplicate["version_expressions"] = ["conflicting version"]
    rows = [duplicate, claim, fixed, fixed]
    buckets = evidence._reviewed_candidate_buckets(rows)
    candidates = buckets[(claim["vendor"], claim["advisory_id"], claim["cve_id"])]
    assert [id(row) for row in registry.fixed_siblings(claim, rule, candidates)] == [
        id(duplicate),
        id(fixed),
        id(fixed),
    ]
    absent = {"vendor": "aruba", "advisory_id": "unregistered"}
    null = dict(absent, cve_id=None)
    assert evidence._reviewed_candidate_buckets([absent, null]) == {
        ("aruba", "unregistered", None): [absent, null]
    }
    # Non-JSON/non-hashable values retain the old matcher instead of being coerced.
    assert evidence._reviewed_candidate_buckets([dict(claim, cve_id=[])]) is None
    assert evidence._reviewed_candidate_buckets([dict(claim, vendor={})]) is None
    assert evidence._reviewed_candidate_buckets([None]) is None
    stream = iter(rows)
    assert evidence._reviewed_candidate_buckets(stream) is None
    assert list(stream) == rows


@pytest.mark.parametrize("field", ["cve_id", "source_sha256", "details"])
def test_prior_link_success_does_not_authorize_mutated_nested_evidence(field):
    from infrastructure_impact import remediation_bindings as registry

    report = projected(SAMPLES[0])
    evidence.validate_evidence(report)
    claim, remediation = links(report)[0]
    fixed = registry.fixed_siblings(claim, registry.rule_for(claim), report["claims"])[0]
    if field == "cve_id":
        fixed[field] = "CVE-2026-99999"
    elif field == "source_sha256":
        fixed["source"][field] = "f" * 64
    else:
        original = next(r for r in fixed["remediations"] if r["category"] == "vendor_fix")
        original[field] = remediation[field] = "Jointly forged original and copied remediation"
    reidentify(report)
    with pytest.raises((ValueError, ValidationError)):
        evidence.validate_evidence(report)


def test_native_stream_defers_linkage_without_building_complete_candidate_index(monkeypatch):
    report = projected(SAMPLES[0])

    def forbidden(_):
        raise AssertionError("Deferred streaming must not build complete candidate buckets")

    monkeypatch.setattr(evidence, "_reviewed_candidate_buckets", forbidden)
    assert native_stream(report, monkeypatch) == report["claims"]
