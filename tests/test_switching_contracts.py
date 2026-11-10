"""Strict source-bound contracts; synthetic records never establish real applicability."""

import copy
import hashlib
import importlib
import json
from importlib.resources import files
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

FIXTURE = json.loads((Path(__file__).parent / "fixtures/switching-cases.json").read_text())


def contracts():
    return importlib.import_module("infrastructure_impact.application.switching_evidence")


def evidence():
    result = copy.deepcopy(FIXTURE["evidence"])
    result["definition_sha256"] = contracts().definition_sha256(contracts().definition())
    return result


def reidentify(report):
    for claim in report["claims"]:
        claim["claim_id"] = contracts().definition_sha256(
            {key: value for key, value in claim.items() if key != "claim_id"}
        )
    return report


def comparison():
    from infrastructure_impact.application import kev, switching_comparison

    sample = evidence()
    return switching_comparison.build_report(
        sample,
        kev.build_report({}, [], publication=None, generated_at=sample["generated_at"]),
        definition=contracts().definition(),
        publication=None,
        generated_at=sample["generated_at"],
        observation_end="2026-11-04",
    )


def test_registered_definition_exact_targets_and_dates_load_outside_checkout(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    value = contracts().definition()
    assert value["id"] == "campus-branch-switching"
    assert value["version"] == 1
    assert value["start_date"] == "2021-01-01"
    assert value["cutoff_date"] == "2026-04-07"
    assert {(t["vendor"], t["family"], m) for t in value["targets"] for m in t["models"]} == {
        ("cisco", "cisco-iosxe", m)
        for m in ["9200", "9300", "9300L", "C9407R", "C9410R", "9500", "C9606R"]
    } | {("aruba", "aruba-aoscx", m) for m in ["6300M", "6410"]} | {
        ("arista", "arista-eos", m) for m in ["7050X3", "720XP", "750"]
    }
    labels = [a["literal"] for t in value["targets"] for a in t["aliases"]]
    assert not any("7500" in label for label in labels)
    assert all(
        a["source_locator"] and a["source_url"].startswith("https://")
        for t in value["targets"]
        for a in t["aliases"]
    )
    value["targets"].clear()
    assert contracts().definition()["targets"]  # Caller mutation cannot poison later reports.


def test_canonical_hash_is_stable_utf8_and_rejects_non_json_values():
    value = {"z": 1, "a": "é"}
    assert (
        contracts().definition_sha256(value)
        == hashlib.sha256('{"a":"é","z":1}'.encode("utf-8")).hexdigest()
    )
    assert contracts().definition_sha256(value) == contracts().definition_sha256(
        dict(reversed(list(value.items())))
    )
    for invalid in [{"x": float("nan")}, {"x": float("inf")}, {"x": (1, 2)}, {1: "x"}]:
        with pytest.raises((ValueError, TypeError)):
            contracts().definition_sha256(invalid)


def test_positive_evidence_and_closed_comparison_envelope_validate():
    contracts().validate_evidence(evidence())
    contracts().validate_comparison(comparison())


@pytest.mark.parametrize(
    "path,value",
    [
        (["secret"], "private"),
        (["claims", 0, "token"], "secret"),
        (["generated_at"], "2026-02-30T10:00:00Z"),
        (["claims", 0, "initial_published_at"], "2025-02-30"),
        (["claims", 0, "source", "source_url"], "file:///private/capture"),
        (["claims", 0, "source", "source_url"], "https://example.com/advisory"),
        (["claims", 0, "source", "source_sha256"], "broken"),
        (["claims", 0, "source", "retrieved_at"], "2026-11-04T10:00:00"),
        (["claims", 0, "platform_bindings", 0, "source", "source_locator"], ""),
        (["claims", 0, "bundle", "source", "source_locator"], ""),
        (["claims", 0, "remediations", 0, "source", "source_sha256"], "broken"),
        (["claims", 0, "scores", 0, "value"], True),
        (["claims", 0, "scores", 0, "value"], float("nan")),
        (["claims", 0, "scores", 0, "value"], float("inf")),
        (["claims", 0, "scores", 0, "cve_id"], "CVE-2025-99999"),
        (["claims", 0, "scores", 0, "product_ids"], ["unrelated-product"]),
    ],
)
def test_evidence_rejects_invalid_or_private_fields(path, value):
    report = evidence()
    node = report
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    with pytest.raises((ValidationError, ValueError, TypeError)):
        contracts().validate_evidence(reidentify(report))


def test_unresolved_model_scope_retains_literal_product_and_requires_issue():
    report = evidence()
    claim = report["claims"][0]
    claim["platform_bindings"] = [
        dict(platform="7500", model=None, basis="unresolved", source=None)
    ]
    claim["named_platforms"] = ["7500"]
    claim["scope_level"] = "os_family"
    claim["issues"].append("model_binding_unresolved")
    contracts().validate_evidence(reidentify(report))
    assert claim["product_id"] == "publisher-product-1"
    assert claim["product"] == "EOS"
    claim["scope_level"] = "model_qualified"
    with pytest.raises(ValueError):
        contracts().validate_evidence(reidentify(report))
    claim["scope_level"] = "os_family"
    claim["issues"].remove("model_binding_unresolved")
    with pytest.raises(ValueError):
        contracts().validate_evidence(reidentify(report))


def test_missing_source_fields_need_explicit_nulls_and_issue_codes():
    report = evidence()
    claim = report["claims"][0]
    claim["revision"] = None
    claim["initial_published_at"] = None
    claim["issues"] += ["revision_missing", "initial_publication_date_missing"]
    contracts().validate_evidence(reidentify(report))
    claim["issues"].remove("revision_missing")
    with pytest.raises(ValueError):
        contracts().validate_evidence(reidentify(report))
    del claim["revision"]
    with pytest.raises(ValidationError):
        contracts().validate_evidence(reidentify(report))


def test_claim_ids_detect_changes_and_duplicates():
    report = evidence()
    report["claims"][0]["product"] = "Different publisher product"
    with pytest.raises(ValueError):
        contracts().validate_evidence(report)
    report = evidence()
    report["claims"].append(copy.deepcopy(report["claims"][0]))
    with pytest.raises(ValueError):
        contracts().validate_evidence(report)


@pytest.mark.parametrize(
    "field,value",
    [
        ("selection", {"guess": True}),
        ("rows", [{}]),
        ("token", "private"),
        ("evaluated_at", "2026-02-30"),
    ],
)
def test_comparison_rejects_invalid_strict_shapes(field, value):
    report = comparison()
    report[field] = value
    with pytest.raises(ValidationError):
        contracts().validate_comparison(report)


def test_enclosing_publication_identity_must_match_when_supplied():
    identity = dict(id="c" * 32, advisory_schema_version=2)
    for builder, validate in [
        (evidence, contracts().validate_evidence),
        (comparison, contracts().validate_comparison),
    ]:
        report = builder()
        report["publication"] = identity
        if "inputs" in report:
            report["inputs"]["evidence"]["publication"] = identity
            report["inputs"]["kev"]["publication"] = identity
        validate(report, publication=identity, generated_at=report["generated_at"])
        for wrong in [None, dict(id="d" * 32, advisory_schema_version=2)]:
            with pytest.raises(ValueError):
                validate(report, publication=wrong, generated_at=report["generated_at"])
        report["publication"] = None
        with pytest.raises(ValueError):
            validate(report, publication=identity, generated_at=report["generated_at"])


def test_study_schema_checks_dates_unknown_properties_and_alias_locators():
    schema = json.loads(
        files("infrastructure_impact").joinpath("schemas/switching-study-v1.json").read_text()
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    value = contracts().definition()
    validator.validate(value)
    for field, wrong in [("start_date", "2021-02-30"), ("private_path", "/private/vault")]:
        invalid = copy.deepcopy(value)
        invalid[field] = wrong
        with pytest.raises(ValidationError):
            validator.validate(invalid)
    value["targets"][0]["aliases"][0]["source_locator"] = ""
    with pytest.raises(ValidationError):
        validator.validate(value)


def test_old_resource_bytes_are_preserved():
    package = files("infrastructure_impact")
    for name, sha256 in FIXTURE["old_resource_sha256"].items():
        raw = package.joinpath(name.removeprefix("infrastructure_impact/")).read_bytes()
        if name == "infrastructure_impact/resources/sources.json":
            # Task 5 appends exactly these reviewed references; the dedicated
            # collection-config test checks their complete entries and enablement.
            # Preserve the original frozen digest for every pre-existing byte.
            config = json.loads(raw)
            added = {
                "aruba-aos-cx-6300-6400-10-14-history",
                "aruba-aos-cx-6300-6400-10-16-history",
                "aruba-aos-cx-6300-6400-10-14-models",
                "cisco-iosxe-17-12-1-release",
                "arista-eos-advisory-bundle-0148",
            }
            for entry in config["reference_sources"]:
                if entry["source_id"] in added:
                    fragment = (
                        ",\n"
                        + "\n".join(
                            "    " + line for line in json.dumps(entry, indent=2).splitlines()
                        )
                    ).encode()
                    assert raw.count(fragment) == 1
                    raw = raw.replace(fragment, b"", 1)
        assert hashlib.sha256(raw).hexdigest() == sha256


@pytest.mark.parametrize("change", ["unknown_model", "unbound_platform", "family", "alias"])
def test_model_qualification_requires_complete_reviewed_identity(change):
    report = evidence()
    claim = report["claims"][0]
    if change == "unknown_model":
        claim["platform_bindings"][0]["model"] = "7500"
    elif change == "unbound_platform":
        claim["named_platforms"].append("7500")
    elif change == "family":
        claim["family"] = "cisco-iosxe"
    else:
        claim["platform_bindings"][0]["basis"] = "reviewed_alias"
        claim["platform_bindings"][0]["platform"] = "7500"
        claim["named_platforms"] = ["7500"]
    with pytest.raises(ValueError):
        contracts().validate_evidence(reidentify(report))


def test_real_uri_check_rejects_malformed_https_and_wrong_generation_time():
    report = evidence()
    report["claims"][0]["source"]["source_url"] = "https://www.arista.com/a b"
    with pytest.raises((ValueError, ValidationError)):
        contracts().validate_evidence(reidentify(report))
    for builder, validate in [
        (evidence, contracts().validate_evidence),
        (comparison, contracts().validate_comparison),
    ]:
        with pytest.raises(ValueError):
            validate(builder(), generated_at="2026-11-04T11:00:00Z")


def test_advisory_provenance_stays_with_vendor_while_scores_can_cite_nvd():
    report = evidence()
    claim = report["claims"][0]
    claim["source"]["source_url"] = "https://nvd.nist.gov/vuln/detail/CVE-2025-12345"
    with pytest.raises(ValueError):
        contracts().validate_evidence(reidentify(report))
    report = evidence()
    report["claims"][0]["scores"][0]["source"]["source_url"] = (
        "https://nvd.nist.gov/vuln/detail/CVE-2025-12345"
    )
    contracts().validate_evidence(reidentify(report))


@pytest.mark.parametrize(
    "url",
    [
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
    ],
)
def test_kev_exploitation_metadata_is_not_a_score_origin(url):
    report = evidence()
    report["claims"][0]["scores"][0]["source"]["source_url"] = url
    with pytest.raises(ValueError):
        contracts().validate_evidence(reidentify(report))


def test_remediation_cannot_attach_a_different_publisher_products_fix():
    report = evidence()
    report["claims"][0]["remediations"][0]["product_ids"] = ["unrelated-product"]
    with pytest.raises(ValueError):
        contracts().validate_evidence(reidentify(report))


def test_unscoped_remediation_requires_explicit_unresolved_product_scope():
    report = evidence()
    claim = report["claims"][0]
    claim["remediations"][0]["product_ids"] = []
    with pytest.raises(ValueError):
        contracts().validate_evidence(reidentify(report))
    claim["issues"].append("remediation_product_scope_unresolved")
    contracts().validate_evidence(reidentify(report))
    assert claim["remediations"][0]["product_ids"] == []


def test_unknown_claim_product_does_not_qualify_remediation_product_scope():
    report = evidence()
    claim = report["claims"][0]
    claim["product_id"] = None
    claim["scores"][0]["product_ids"] = []
    claim["issues"].append("product_id_missing")
    with pytest.raises(ValueError):
        contracts().validate_evidence(reidentify(report))
    claim["issues"].append("remediation_product_scope_unresolved")
    contracts().validate_evidence(reidentify(report))


def test_missing_availability_statement_is_distinct_from_missing_date():
    report = evidence()
    claim = report["claims"][0]
    remediation = claim["remediations"][0]
    remediation["published_availability"] = None
    assert "availability_date_missing" in claim["issues"]
    with pytest.raises(ValueError):
        contracts().validate_evidence(reidentify(report))
    claim["issues"].append("availability_statement_missing")
    contracts().validate_evidence(reidentify(report))
    assert remediation["published_availability"] is None
    assert remediation["availability_date"] is None


@pytest.mark.parametrize(
    "character", ["<capture>", '"capture"', "{capture}", "|", "^", "`", "[capture]"]
)
def test_source_uri_rejects_characters_outside_rfc_uri_path_syntax(character):
    report = evidence()
    report["claims"][0]["source"]["source_url"] = "https://www.arista.com/" + character
    with pytest.raises(ValidationError):
        contracts().validate_evidence(reidentify(report))


def test_source_uri_accepts_percent_encoded_capture_path():
    report = evidence()
    report["claims"][0]["source"]["source_url"] = "https://www.arista.com/%3Ccapture%3E"
    contracts().validate_evidence(reidentify(report))


def test_fresh_public_evidence_binding_rejects_changed_packaged_definition(monkeypatch):
    c = contracts()
    value = evidence()
    study = c.definition()
    c.validate_evidence(value)
    monkeypatch.setattr(c, "definition", lambda: study)
    c.validate_evidence(value)
    study["targets"].clear()
    with pytest.raises(ValueError, match="fingerprint"):
        c.validate_evidence(value)


@pytest.mark.parametrize("fault", ["integer_to_float", "unused_field", "context"])
def test_prior_evidence_proof_keeps_exact_value_and_context_types(fault):
    c = contracts()
    value = evidence()
    publication, generated_at = value["publication"], value["generated_at"]
    proof = c._ValidatedEvidence(value, publication=publication, generated_at=generated_at)
    proof.require(value, publication=publication, generated_at=generated_at)
    if fault == "integer_to_float":
        value["schema_version"] = 1.0
    elif fault == "unused_field":
        value["issues"].append("authored_context_mutation")
    else:
        publication = {"unused": True}
    with pytest.raises(ValueError, match="complete value/context"):
        proof.require(value, publication=publication, generated_at=generated_at)
