"""Cached analysis shape validation preserves the existing Python shape contract."""

import copy
import json
from pathlib import Path

import pytest

from infrastructure_impact.application import switching_analysis as analysis


@pytest.fixture(scope="module")
def values():
    vectors = json.loads(
        (Path(__file__).parent / "fixtures/switching-analysis-vectors.json").read_text()
    )
    selected = vectors["cases"][0]["expected"]
    return dict(
        compiled=vectors["compiled"],
        compact=vectors["compiled"]["requirements"],
        selected=selected,
        selected_upgrades=selected["upgrades"],
        model_coverage=selected["model_coverage"],
    )


@pytest.mark.parametrize(
    "definition", ["compiled", "compact", "selected", "selected_upgrades", "model_coverage"]
)
def test_cached_and_python_shapes_agree_on_valid_and_mutated_fields(values, definition):
    shape = {"$ref": "#/$defs/" + definition, "$defs": analysis._SCHEMA["$defs"]}
    legacy = analysis._VALIDATOR.evolve(schema=shape)
    fast = analysis._compiled_shape(definition)
    value = values[definition]
    assert fast.is_valid(value) and legacy.is_valid(value)
    for key in value:
        for invalid in (None, True, 0, 1.0, [], {}, "", "\x1c", "é😀"):
            changed = dict(value, **{key: invalid})
            assert fast.is_valid(changed) == legacy.is_valid(changed), (definition, key, invalid)


def test_patterns_and_disabled_formats_match_legacy(values):
    shape = {"$ref": "#/$defs/compiled", "$defs": analysis._SCHEMA["$defs"]}
    legacy = analysis._VALIDATOR.evolve(schema=shape)
    fast = analysis._compiled_shape("compiled")
    for text in ("\x1c", "\u0085", "\u00a0", "é😀", "x"):
        changed = copy.deepcopy(values["compiled"])
        next(iter(changed["claims"].values()))["advisory_id"] = text
        assert fast.is_valid(changed) == legacy.is_valid(changed)
    changed = dict(values["compiled"], generated_at="not-a-date")
    assert fast.is_valid(changed) == legacy.is_valid(changed)


def test_valid_shape_skips_python_walk_and_invalid_preserves_error(values, monkeypatch):
    analysis._compiled_shape("compiled")
    with monkeypatch.context() as patch:
        patch.setattr(
            type(analysis._VALIDATOR), "validate", lambda *args: pytest.fail("repeated Python walk")
        )
        analysis._validate_shape(values["compiled"], "compiled")
    with pytest.raises(ValueError, match="Invalid analysis DTO"):
        analysis._validate_shape(None, "compiled")
