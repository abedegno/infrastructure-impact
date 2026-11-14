"""Public release receipts reject corrupt or mixed inputs before aggregation."""

import importlib
import json
from hashlib import sha256
from types import SimpleNamespace

import pytest


def inputs(tmp_path, *, publication="test-publication"):
    identity = {"publication": {"id": publication}, "generated_at": "2026-11-14T00:00:00Z"}
    analysis = {
        **identity,
        "availability": "available",
        **{
            key: identity
            for key in (
                "upgrades",
                "disclosure",
                "model_coverage",
                "kev_reconciliation",
                "release_history",
            )
        },
    }
    proof_dir = tmp_path / "proof"
    proof_dir.mkdir()
    raw = json.dumps(analysis).encode()
    (proof_dir / "selected-analysis.json").write_bytes(raw)
    proof = {
        **identity,
        "analysis_json": {
            "path": "selected-analysis.json",
            "bytes": len(raw),
            "sha256": sha256(raw).hexdigest(),
        },
    }
    (proof_dir / "proof.json").write_text(json.dumps(proof))
    return proof_dir, proof


def test_import_does_not_change_environment(monkeypatch):
    monkeypatch.setenv("IMPACT_TEST_SENTINEL", "synthetic")
    monkeypatch.setenv("CISCO_TEST_SENTINEL", "synthetic")
    importlib.import_module("checks.switching_release_summary")
    import os

    assert os.environ["IMPACT_TEST_SENTINEL"] == "synthetic"
    assert os.environ["CISCO_TEST_SENTINEL"] == "synthetic"


@pytest.mark.parametrize("corruption", ["hash", "oversized"])
def test_bad_proof_stops_before_publication_read(tmp_path, corruption):
    summary = importlib.import_module("checks.switching_release_summary")
    proof_dir, proof = inputs(tmp_path)
    if corruption == "hash":
        proof["analysis_json"]["sha256"] = "0" * 64
    else:
        proof["analysis_json"]["bytes"] = 128_000_001
    (proof_dir / "proof.json").write_text(json.dumps(proof))
    output = tmp_path / "result.json"
    with pytest.raises(ValueError):
        summary.main([str(tmp_path / "absent-publication"), str(proof_dir), str(output)])
    assert not output.exists()


def test_mixed_generation_stops_before_aggregation(tmp_path, monkeypatch):
    summary = importlib.import_module("checks.switching_release_summary")
    from infrastructure_impact.application import publication_reader

    proof_dir, _ = inputs(tmp_path, publication="other-publication")
    monkeypatch.setattr(
        publication_reader,
        "PublicationReader",
        lambda _path: SimpleNamespace(
            identity={
                "publication": {"id": "actual-publication"},
                "generated_at": "2026-11-14T00:00:00Z",
            }
        ),
    )
    output = tmp_path / "result.json"
    with pytest.raises(ValueError, match="mixed publication generation"):
        summary.main([str(tmp_path / "public"), str(proof_dir), str(output)])
    assert not output.exists()
