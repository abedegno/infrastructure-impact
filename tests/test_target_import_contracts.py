"""Closed receipts reject malformed, stale and unbounded operational metadata."""

from copy import deepcopy
from hashlib import sha256

import pytest
from test_target_import_profiles import manifest

from infrastructure_impact.application import target_import_contracts as contracts
from infrastructure_impact.application.evidence_identity import canonical_json
from infrastructure_impact.collection.target_import_profiles import from_manifest
from infrastructure_impact.plugins.registry import default_registry


def preview(selected):
    identities = {
        "baseline_fingerprint": "c" * 64,
        "manifest_fingerprint": selected.fingerprint,
        "source_config_fingerprint": "d" * 64,
        "normalizer_fingerprints": {
            v: default_registry().fingerprint(v) for v in ["aruba", "cisco"]
        },
    }
    return {
        "format": "impact-target-import-preview",
        "schema_version": 1,
        "profile_id": selected.profile_id,
        "profile_version": selected.version,
        **identities,
        "fingerprint": sha256(canonical_json(identities)).hexdigest(),
        "targets": [t.metadata() | {"before_keys": []} for t in selected.targets],
        "observed_at": "2026-11-07T12:00:00Z",
    }


def result(selected):
    value = preview(selected)
    value["format"] = "impact-target-import-result"
    value["staged_database"] = None
    value["public_directory"] = None
    value["outcome"] = "failed"
    value["failure_code"] = "candidate_capacity"
    value["targets"] = [
        {
            "vendor": t.vendor,
            "advisory_id": t.advisory_id,
            "fetch_url": t.fetch_url,
            "source_sha256": t.source_sha256,
            "status": "validated",
            "failure_code": None,
            "before_keys": [],
            "after_keys": [],
        }
        for t in selected.targets
    ]
    value["counters"] = {
        "http_attempts": 2,
        "received_bytes": 200,
        "input_bytes": 200,
        "imported": 0,
        "unchanged": 0,
    }
    value["checks"] = {"audit_passed": True, "candidate_validated": False, "capacity_passed": False}
    return value


def test_serializers_canonical_finite_and_fresh_load(tmp_path):
    selected = from_manifest(manifest())
    value = preview(selected)
    encoded = contracts.preview_bytes(value, selected=selected)
    assert encoded == canonical_json(value) + b"\n"
    path = tmp_path / "preview.json"
    path.write_bytes(encoded)
    loaded = contracts.load_preview(path, selected)
    loaded["targets"][0]["before_keys"].append("d" * 64)
    assert contracts.load_preview(path, selected) == value
    assert contracts.result_bytes(result(selected), selected=selected).endswith(b"\n")


@pytest.mark.parametrize("kind", ["preview", "result"])
@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "extra",
        "format",
        "nan",
        "inf",
        "boolean",
        "targets",
        "identity",
        "fingerprint",
        "normalizer",
        "nested_extra",
    ],
)
def test_strict_receipt_fields(kind, mutation):
    selected = from_manifest(manifest())
    value = preview(selected) if kind == "preview" else result(selected)
    if mutation == "missing":
        del value["observed_at"]
    elif mutation == "extra":
        value["raw_b64"] = "PRIVATE"
    elif mutation == "format":
        value["format"] = "impact-maintenance-preview"
    elif mutation == "nan":
        value["observed_at"] = float("nan")
    elif mutation == "inf":
        value["observed_at"] = float("inf")
    elif mutation == "boolean":
        value["schema_version"] = True
    elif mutation == "targets":
        value["targets"] = []
    elif mutation == "identity":
        value["targets"][0]["advisory_id"] = "forged"
    elif mutation == "fingerprint":
        value["fingerprint"] = "f" * 64
    elif mutation == "normalizer":
        value["normalizer_fingerprints"]["aruba"] = "0" * 16
    elif mutation == "nested_extra":
        value["targets"][0]["raw"] = "PRIVATE"
    with pytest.raises(ValueError):
        getattr(contracts, f"{kind}_bytes")(value, selected=selected)


@pytest.mark.parametrize("kind", ["preview", "result"])
def test_receipt_size_enforced_without_truncation(kind, tmp_path):
    selected = from_manifest(manifest())
    value = preview(selected) if kind == "preview" else result(selected)
    value["targets"][0]["before_keys"] = ["e" * 64] * 30_000
    with pytest.raises(ValueError, match="size"):
        getattr(contracts, f"{kind}_bytes")(value, selected=selected)
    path = tmp_path / "oversize.json"
    path.write_bytes(b" " * 2_000_001)
    with pytest.raises(ValueError):
        contracts.load_preview(path, selected)


@pytest.mark.parametrize("bad", ["duplicate", "deep", "constant", "non_utf8"])
def test_load_preview_rejects_non_strict_json(tmp_path, bad):
    selected = from_manifest(manifest())
    raw = contracts.preview_bytes(preview(selected), selected=selected)
    if bad == "duplicate":
        raw = raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1')
    elif bad == "deep":
        raw = b"[" * 10_000 + b"]" * 10_000
    elif bad == "constant":
        raw = raw.replace(b'"schema_version":1', b'"schema_version":NaN')
    else:
        raw = b"\xff"
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        contracts.load_preview(path, selected)


def test_completed_result_requires_every_target_and_successful_checks():
    selected = from_manifest(manifest())
    value = result(selected)
    value["outcome"] = "completed"
    with pytest.raises(ValueError):
        contracts.result_bytes(value, selected=selected)
    value["failure_code"] = None
    value["staged_database"] = "private/data/intel.sqlite3"
    value["public_directory"] = "public/"
    value["checks"] = dict.fromkeys(value["checks"], True)
    for target in value["targets"]:
        target["status"] = "unchanged"
    value["counters"]["unchanged"] = 2
    contracts.result_bytes(value, selected=selected)
    value["targets"].append(deepcopy(value["targets"][0]))
    with pytest.raises(ValueError):
        contracts.result_bytes(value, selected=selected)


@pytest.mark.parametrize("outcome", ["failed", "skipped_writer_lock"])
def test_failed_result_never_advertises_accepted_paths(outcome):
    selected = from_manifest(manifest())
    value = result(selected)
    value["outcome"] = outcome
    value["staged_database"] = "private/data/intel.sqlite3"
    with pytest.raises(ValueError):
        contracts.result_bytes(value, selected=selected)


def test_installed_profile_serializers_use_closed_lookup():
    from infrastructure_impact.collection.target_import_profiles import PROFILE_ID, profile

    value = preview(profile(PROFILE_ID))
    contracts.preview_bytes(value)
    value["profile_id"] = "uninstalled"
    with pytest.raises(ValueError, match="unknown_target_import_profile"):
        contracts.preview_bytes(value)


@pytest.mark.parametrize(
    "field,bad",
    [
        ("http_attempts", True),
        ("received_bytes", 80_000_001),
        ("input_bytes", 40_000_001),
        ("imported", 1),
        ("unchanged", 1.0),
    ],
)
def test_result_counters_are_typed_bounded_and_match_target_outcomes(field, bad):
    selected = from_manifest(manifest())
    value = result(selected)
    value["counters"][field] = bad
    with pytest.raises(ValueError):
        contracts.result_bytes(value, selected=selected)


def test_not_attempted_targets_are_retained_in_failure_receipts():
    selected = from_manifest(manifest())
    value = result(selected)
    for target in value["targets"]:
        target["status"] = "not_attempted"
    contracts.result_bytes(value, selected=selected)
