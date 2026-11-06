"""Bounded synthetic work and strict fresh-call contracts for expanded comparisons."""

import copy
import json
from collections import Counter
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from infrastructure_impact.application import switching_comparison as comparison
from infrastructure_impact.application import switching_evidence as evidence

FIXTURE = json.loads((Path(__file__).parent / "fixtures/switching-cases.json").read_text())


def sample(copies=1):
    report = copy.deepcopy(FIXTURE["comparison_base_report"])
    if copies == 1:
        return report
    retained = report["inputs"]["evidence"]
    originals = retained["claims"]
    retained["claims"] = []
    for index in range(copies):
        for original in originals:
            claim = copy.deepcopy(original)
            claim["revision"] = f"synthetic-{index}"
            claim["claim_id"] = evidence.definition_sha256(
                {key: value for key, value in claim.items() if key != "claim_id"}
            )
            retained["claims"].append(claim)
    return comparison.build_report(
        retained,
        report["inputs"]["kev"],
        definition=report["definition"],
        publication=report["publication"],
        generated_at=report["generated_at"],
        observation_end=report["observation_end"],
    )


@pytest.mark.parametrize("copies", [1, 4])
@pytest.mark.parametrize(
    "operation,shape_passes,row_passes", [("validate", 1, 3), ("select", 1, 6)]
)
def test_retained_inputs_are_not_revalidated_for_source_derivation(
    monkeypatch, operation, shape_passes, row_passes, copies
):
    """Catch full-corpus shape/reducer repetition merely to verify selected sources."""
    report = sample(copies)
    calls = Counter()
    validate, row = evidence._validate, comparison._row

    def counted_validate(value, schema):
        if schema == "switching-evidence-v1.json" or (
            schema == "switching-comparison-v1.json" and value["inputs"] is not None
        ):
            calls["shape"] += 1
        return validate(value, schema)

    def counted_row(*args, **kwargs):
        calls["row"] += 1
        return row(*args, **kwargs)

    monkeypatch.setattr(evidence, "_validate", counted_validate)
    monkeypatch.setattr(comparison, "_row", counted_row)
    if operation == "validate":
        evidence.validate_comparison(report)
    else:
        selected = comparison.select_report(report, evaluated_at=report["evaluated_at"])
        assert selected == report
    assert calls == {"shape": shape_passes, "row": row_passes}


def test_build_copies_the_complete_evidence_tree_once(monkeypatch):
    """Catch a redundant retained-corpus allocation before the output isolation copy."""
    report = sample()
    source = report["inputs"]["evidence"]
    copies = []
    deepcopy_dict = copy._deepcopy_dispatch[dict]

    def counted(value, memo):
        if isinstance(value, dict) and "claims" in value and "definition_sha256" in value:
            copies.append(value)
        return deepcopy_dict(value, memo)

    monkeypatch.setitem(copy._deepcopy_dispatch, dict, counted)
    built = comparison.build_report(
        source,
        report["inputs"]["kev"],
        definition=report["definition"],
        publication=report["publication"],
        generated_at=report["generated_at"],
        observation_end=report["observation_end"],
    )
    assert built == report
    assert len(copies) == 1
    assert built["inputs"]["evidence"] is not source


def test_build_and_selection_keep_mutable_trees_isolated():
    original = sample()
    untouched = copy.deepcopy(original)
    built = comparison.build_report(
        original["inputs"]["evidence"],
        original["inputs"]["kev"],
        definition=original["definition"],
        publication=original["publication"],
        generated_at=original["generated_at"],
        observation_end=original["observation_end"],
    )
    selected = comparison.select_report(built, evaluated_at=built["evaluated_at"])
    sibling = comparison.select_report(built, evaluated_at=built["evaluated_at"])
    original["inputs"]["evidence"]["claims"][0]["source"]["source_locator"] = "caller mutation"
    original["definition"]["targets"].clear()
    assert built == untouched
    selected["inputs"]["evidence"]["claims"][0]["issues"].append("output_mutation")
    selected["inputs"]["kev"]["listed_cve_ids"].clear()
    selected["definition"]["targets"].clear()
    selected["sources"][0]["source_locator"] = "output mutation"
    selected["rows"][0]["counts"]["claims"] = -1
    assert built == sibling == untouched


def corrupt(report, fault):
    claim = report["inputs"]["evidence"]["claims"][0]
    if fault == "source_shape":
        claim["source"]["retrieved_at"] = {"bad": True}
    elif fault == "source_property":
        claim["source"]["extra"] = "not allowed"
    elif fault == "source_duplicate":
        report["sources"].append(copy.deepcopy(report["sources"][0]))
    elif fault == "claim_hash":
        claim["claim_id"] = "0" * 64
    elif fault == "claim_identity":
        claim["advisory_id"] = "changed"
    elif fault == "generation":
        report["inputs"]["evidence"]["generated_at"] = "2026-11-03T10:00:00Z"
    elif fault == "publication":
        report["inputs"]["evidence"]["publication"] = {
            "id": "a" * 32,
            "advisory_schema_version": 2,
        }
    elif fault == "definition":
        report["inputs"]["evidence"]["definition_sha256"] = "0" * 64
    elif fault == "counts":
        report["rows"][0]["counts"]["claims"] += 1
    elif fault == "source_membership":
        report["sources"].pop()
    elif fault == "binding_semantics":
        claim["platform_bindings"][0]["model"] = "not-a-study-model"
        claim["claim_id"] = evidence.definition_sha256(
            {key: value for key, value in claim.items() if key != "claim_id"}
        )
    elif fault == "nonfinite":
        claim["publisher"]["sequence"] = float("nan")
    elif fault == "python_value":
        claim["issues"] = tuple(claim["issues"])
    else:
        raise AssertionError(fault)


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
def test_prior_success_does_not_authorize_changed_inputs(fault):
    report = sample()
    evidence.validate_comparison(report)
    comparison.select_report(report, evaluated_at=report["evaluated_at"])
    corrupt(report, fault)
    for operation in (evidence.validate_comparison, comparison.select_report):
        with pytest.raises((ValidationError, ValueError, TypeError)):
            operation(report)


@pytest.mark.parametrize("bad", [{}, [], True, 1, None, "not a timestamp"])
def test_nested_shape_rejection_matches_stock_validator(bad):
    report = sample()
    optimized = evidence._validators()["switching-comparison-v1.json"]
    stock = Draft202012Validator(
        optimized.schema,
        format_checker=optimized.format_checker,
        registry=optimized._registry,
    )
    assert optimized.is_valid(report) and stock.is_valid(report)
    report["inputs"]["evidence"]["claims"][0]["source"]["retrieved_at"] = bad
    assert not stock.is_valid(report)
    with pytest.raises(ValidationError):
        evidence.validate_comparison(report)
    with pytest.raises(ValidationError):
        evidence.validate_evidence(report["inputs"]["evidence"])


@pytest.mark.parametrize("fault", ["claim_hash", "generation", "binding_semantics"])
def test_public_evidence_validation_remains_strict_after_success(fault):
    report = sample()
    retained = report["inputs"]["evidence"]
    evidence.validate_evidence(
        retained, publication=report["publication"], generated_at=report["generated_at"]
    )
    corrupt(report, fault)
    with pytest.raises(ValueError):
        evidence.validate_evidence(
            retained, publication=report["publication"], generated_at=report["generated_at"]
        )


@pytest.mark.parametrize(
    "fault", ["integer_to_boolean", "integer_to_float", "boolean_to_integer", "claim_removal"]
)
def test_selection_rejects_corrupted_isolation_copy(monkeypatch, fault):
    """The same-call shape proof must not use Python's True == 1 equality."""
    report = sample()
    deepcopy_dict = copy._deepcopy_dispatch[dict]

    def corrupted_copy(value, memo):
        result = deepcopy_dict(value, memo)
        if "claims" in value and "definition_sha256" in value:
            if fault == "integer_to_boolean":
                result["schema_version"] = True
            elif fault == "integer_to_float":
                result["schema_version"] = 1.0
            elif fault == "boolean_to_integer":
                claim = next(c for c in result["claims"] if c.get("conditional_affected") is True)
                claim["conditional_affected"] = 1
            else:
                result["claims"].pop()
        return result

    monkeypatch.setitem(copy._deepcopy_dispatch, dict, corrupted_copy)
    with pytest.raises(ValueError, match="Retained comparison inputs changed"):
        comparison.select_report(report, evaluated_at=report["evaluated_at"])


@pytest.mark.parametrize("scope", ["os_family", "model_qualified"])
@pytest.mark.parametrize(
    "window", ["all", "pre", "post", "2021", "2022", "2023", "2024", "2025", "2026"]
)
def test_selected_actual_report_passes_full_stock_shape_and_fresh_semantics(scope, window):
    report = sample()
    selected = comparison.select_report(
        report, scope_level=scope, window=window, evaluated_at=report["evaluated_at"]
    )
    validator = evidence._validators()["switching-comparison-v1.json"]
    stock = Draft202012Validator(
        validator.schema, format_checker=validator.format_checker, registry=validator._registry
    )
    stock.validate(selected)
    evidence.validate_comparison(selected)
    assert selected["inputs"] == report["inputs"]
    assert selected["inputs"] is not report["inputs"]


def test_selection_still_validates_generated_row_shapes(monkeypatch):
    report = sample()
    row = comparison._row

    def malformed_row(*args, **kwargs):
        result = row(*args, **kwargs)
        result["unexpected"] = "not allowed"
        return result

    # Start the injection after fresh input validation, so only output checking
    # can reject this malformed generated field.
    validate = evidence.validate_comparison

    def validate_then_inject(value):
        validate(value)
        monkeypatch.setattr(comparison, "_row", malformed_row)

    monkeypatch.setattr(evidence, "validate_comparison", validate_then_inject)
    with pytest.raises(ValidationError):
        comparison.select_report(report, evaluated_at=report["evaluated_at"])


def build_with_shared_publication():
    report = sample()
    publication = {"id": "a" * 32, "advisory_schema_version": 2}
    retained = report["inputs"]["evidence"]
    kev = report["inputs"]["kev"]
    retained["publication"] = kev["publication"] = publication
    built = comparison.build_report(
        retained,
        kev,
        definition=report["definition"],
        publication=publication,
        generated_at=report["generated_at"],
        observation_end=report["observation_end"],
    )
    return built, publication


def test_build_shared_publication_keeps_independent_generation_snapshots():
    built, caller_publication = build_with_shared_publication()
    evidence.validate_comparison(built)
    snapshots = [
        built["publication"],
        built["inputs"]["evidence"]["publication"],
        built["inputs"]["kev"]["publication"],
    ]
    assert all(value == caller_publication for value in snapshots)
    assert len({id(value) for value in snapshots}) == 3
    assert all(value is not caller_publication for value in snapshots)
    caller_publication["id"] = "b" * 32
    assert all(value["id"] == "a" * 32 for value in snapshots)
    evidence.validate_comparison(built)


@pytest.mark.parametrize("location", ["outer", "evidence", "kev"])
def test_build_shared_publication_rejects_single_snapshot_mutation(location):
    built, caller_publication = build_with_shared_publication()
    sibling = comparison.select_report(built, evaluated_at=built["evaluated_at"])
    untouched = copy.deepcopy(built)
    publication = (
        built["publication"] if location == "outer" else built["inputs"][location]["publication"]
    )
    publication["id"] = "b" * 32
    assert caller_publication["id"] == "a" * 32
    assert sibling == untouched
    for operation in (evidence.validate_comparison, comparison.select_report):
        with pytest.raises(ValueError):
            operation(built)
    evidence.validate_comparison(sibling)
