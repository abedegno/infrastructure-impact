"""Compiled shape checks must agree with the existing source validator."""

import copy

import pytest
from jsonschema import ValidationError
from test_switching_comparison import claim, report

from infrastructure_impact.application import switching_comparison as comparison
from infrastructure_impact.application import switching_evidence as evidence


@pytest.fixture(scope="module")
def reports():
    value = report([claim()])
    return {
        "switching-study-v1.json": value["definition"],
        "switching-evidence-v1.json": value["inputs"]["evidence"],
        "switching-comparison-v1.json": value,
        "switching-summary-v1.json": comparison.summary(value),
        "switching-inputs-v1.json": dict(
            representation="switching-inputs",
            evidence={
                k: value["inputs"]["evidence"][k]
                for k in (
                    "schema_version",
                    "publication",
                    "generated_at",
                    "definition_sha256",
                    "issues",
                )
            },
            kev={k: v for k, v in value["inputs"]["kev"].items() if k != "entries"},
        ),
        "kev-v1.json": value["inputs"]["kev"],
    }


def test_valid_shape_avoids_another_python_schema_walk(reports, monkeypatch):
    legacy = evidence._validators()["switching-evidence-v1.json"]
    # Build before replacing only the slow validation operation, not its semantics.
    evidence._compiled_validators()

    def unnecessary_walk(value):
        raise AssertionError("Valid shapes should not repeat the Python schema walk")

    monkeypatch.setattr(type(legacy), "validate", lambda self, value: unnecessary_walk(value))
    evidence._validate(reports["switching-evidence-v1.json"], "switching-evidence-v1.json")


@pytest.mark.parametrize("name", evidence._SCHEMAS)
def test_compiled_and_legacy_agree_on_valid_reports_and_top_level_mutations(reports, name):
    value = reports[name]
    legacy = evidence._validators()[name]
    compiled = evidence._compiled_validators()[name]
    assert legacy.is_valid(value) and compiled.is_valid(value)
    bad_values = [None, True, False, 0, 1, 1.0, {}, [], "", "\x1c", "\u0085", "é😀"]
    for key in value:
        for bad in bad_values:
            changed = {**value, key: bad}
            assert compiled.is_valid(changed) == legacy.is_valid(changed), (name, key, bad)


@pytest.mark.parametrize(
    "text",
    ["\x1c", "\x1d", "\x1e", "\x1f", "\u0085", "\u00a0", "\u2007", "\u202f", "\u200b", "é😀"],
)
def test_python_whitespace_pattern_semantics_are_preserved(reports, text):
    value = copy.deepcopy(reports["switching-evidence-v1.json"])
    value["claims"][0]["publisher"]["id"] = text
    name = "switching-evidence-v1.json"
    assert evidence._compiled_validators()[name].is_valid(value) == evidence._validators()[
        name
    ].is_valid(value)


@pytest.mark.parametrize(
    "bad", ["not a timestamp", "2026-11-08", [], True, None, "2026-02-30T00:00:00Z"]
)
def test_invalid_nested_format_keeps_legacy_exception(reports, bad):
    value = copy.deepcopy(reports["switching-evidence-v1.json"])
    value["claims"][0]["source"]["retrieved_at"] = bad
    with pytest.raises(ValidationError):
        evidence._validate(value, "switching-evidence-v1.json")


def test_unregistered_schema_cannot_read_a_local_file(tmp_path, monkeypatch):
    from jsonschema import Draft202012Validator, FormatChecker

    sentinel = tmp_path / "unregistered-schema.json"
    sentinel.write_text("{}")
    unknown = Draft202012Validator(
        {"$id": "urn:test:offline", "$ref": sentinel.as_uri()}, format_checker=FormatChecker()
    )
    evidence._compiled_validators.cache_clear()
    monkeypatch.setattr(evidence, "_validators", lambda: {"test": unknown})
    try:
        with pytest.raises(
            Exception, match="Schema reference is not installed|Retrieval is disabled"
        ):
            evidence._compiled_validators()
    finally:
        evidence._compiled_validators.cache_clear()


@pytest.mark.parametrize(
    "fault",
    [
        "source_shape",
        "source_property",
        "source_duplicate",
        "claim_hash",
        "claim_identity",
        "generation",
        "publication",
        "definition",
        "counts",
        "source_membership",
        "binding_semantics",
        "nonfinite",
        "python_value",
    ],
)
def test_same_object_is_revalidated_after_mutation(fault):
    from test_switching_scaling import corrupt, sample

    value = sample()
    evidence.validate_comparison(value)
    corrupt(value, fault)
    if fault not in ("nonfinite", "python_value"):
        name = "switching-comparison-v1.json"
        assert evidence._compiled_validators()[name].is_valid(value) == evidence._validators()[
            name
        ].is_valid(value)
    with pytest.raises((ValidationError, ValueError, TypeError)):
        evidence.validate_comparison(value)


@pytest.mark.parametrize(
    "fault", ["missing_source", "extra_source", "duplicate_models", "duplicate_claims"]
)
def test_nested_closed_objects_and_unique_items(reports, fault):
    value = copy.deepcopy(reports["switching-evidence-v1.json"])
    current = value["claims"][0]
    if fault == "missing_source":
        del current["source"]["source_locator"]
    elif fault == "extra_source":
        current["source"]["unexpected"] = "forbidden"
    elif fault == "duplicate_models":
        current["named_platforms"] = ["same model", "same model"]
    else:
        value["claims"].append(copy.deepcopy(current))
    name = "switching-evidence-v1.json"
    if fault == "duplicate_claims":
        # Identity uniqueness belongs to semantic validation, not array shape.
        assert evidence._validators()[name].is_valid(value)
        assert evidence._compiled_validators()[name].is_valid(value)
        with pytest.raises(ValueError, match="unique"):
            evidence.validate_evidence(value)
    else:
        assert not evidence._validators()[name].is_valid(value)
        assert not evidence._compiled_validators()[name].is_valid(value)
        with pytest.raises(ValidationError):
            evidence._validate(value, name)


@pytest.mark.parametrize("number", [True, -1, 1.5, None, {}, 0, 1, 1.0, 2**100])
def test_nested_integer_and_minimum_boundaries(reports, number):
    value = copy.deepcopy(reports["switching-comparison-v1.json"])
    value["rows"][0]["counts"]["claims"] = number
    name = "switching-comparison-v1.json"
    assert evidence._compiled_validators()[name].is_valid(value) == evidence._validators()[
        name
    ].is_valid(value)


@pytest.mark.parametrize(
    "variant,expected",
    [
        ("reviewed_valid", True),
        ("reviewed_missing_fixed", False),
        ("row_with_fixed", False),
        ("row_valid", True),
    ],
)
def test_nested_if_then_else_bindings(reports, variant, expected):
    import json
    from pathlib import Path

    import test_switching_comparison as case_helpers

    fixture = json.loads(
        (
            Path(case_helpers.__file__).parent / "fixtures/publication-v2-reviewed-link.json"
        ).read_text()
    )
    binding = next(
        r["scope_binding"]
        for c in fixture["claims"]
        for r in c["remediations"]
        if r.get("scope_binding")
    )
    if variant == "reviewed_missing_fixed":
        del binding["fixed_product"]
    elif variant in ("row_with_fixed", "row_valid"):
        binding["basis"] = "same_source_row"
        if variant == "row_valid":
            del binding["fixed_product"]
            del binding["fixed_source"]
    value = copy.deepcopy(reports["switching-evidence-v1.json"])
    value["claims"][0]["remediations"][0]["scope_binding"] = binding
    name = "switching-evidence-v1.json"
    assert evidence._validators()[name].is_valid(value) is expected
    assert evidence._compiled_validators()[name].is_valid(value) is expected
