"""Private inventory proposals cannot auto-certify builds or publish local evidence."""

import json
import os
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from unittest.mock import patch

import pytest

from infrastructure_impact.application import build_inventory as inventory
from infrastructure_impact.application.build_pilot import build_pilot
from infrastructure_impact.application.research_reports import validator
from infrastructure_impact.research_cli import main
from infrastructure_impact.settings import PACKAGE

NOW = datetime(2026, 10, 27, tzinfo=timezone.utc)


def proposal():
    return inventory.template("arista", "Arista EOS", "4.32.2F", "OpenSSH", "SSH management")


def documented(tmp_path):
    value = proposal()
    raw = b"Synthetic manifest: example package 1.0 for an example image; not vendor evidence."
    (tmp_path / "manifest.txt").write_bytes(raw)
    value["artifacts"] = [
        dict(
            id="manifest",
            file_name="manifest.txt",
            sha256=sha256(raw).hexdigest(),
            source_url="https://www.arista.com/en/support/product-documentation/gpl",
            observed_at="2026-10-26T12:00:00Z",
            kind="publisher_manifest",
            redistribution="unknown",
            rights_basis=None,
        )
    ]
    claim = value["claims"][0]
    claim.update(
        state="publisher_statement",
        value="4.32.2F",
        evidence=[dict(artifact_id="manifest", locator="Synthetic row 1")],
    )
    return value


def test_blank_proposal_and_complete_claims_never_certify_semantics(tmp_path):
    blank = inventory.audit(proposal())
    assert blank["undocumented_fields"] == list(inventory.FIELDS)
    assert not blank["all_required_fields_documented"]
    value = documented(tmp_path)
    for claim in value["claims"]:
        claim.update(
            state="artifact_observation",
            value="synthetic",
            evidence=[dict(artifact_id="manifest", locator="Synthetic row 1")],
        )
    value["claims"][0]["value"] = "4.32.2F"
    next(c for c in value["claims"] if c["field"] == "image_digest")["value"] = "sha256:" + "a" * 64
    result = inventory.audit(value, tmp_path, now=NOW)
    assert result["all_required_fields_documented"]
    assert result["status"] == "requires_maintainer_review"
    assert result["artifacts_without_declared_redistribution_permission"] == 1
    assert all(
        result[k] is False
        for k in (
            "inventory_verified",
            "independent_human_review_completed",
            "metric_eligibility_changed",
            "assessments_changed",
            "evidence_published",
        )
    )
    serialized = json.dumps(result)
    assert "Synthetic row" not in serialized and "manifest.txt" not in serialized
    assert str(tmp_path) not in serialized and "Arista EOS" not in serialized


@pytest.mark.parametrize(
    "mutate",
    [
        lambda v: v["claims"].__setitem__(1, deepcopy(v["claims"][0])),
        lambda v: v["claims"][1].update(value="8.7p1"),
        lambda v: v["claims"][1].update(state="publisher_statement", value="8.7p1"),
        lambda v: v["claims"][0].update(value="4.32.3M"),
        lambda v: v["claims"][0]["evidence"][0].update(artifact_id="missing"),
        lambda v: v["artifacts"][0].update(source_url="https://www.cisco.com/inventory"),
        lambda v: v["artifacts"][0].update(
            source_url="https://www.arista.com.attacker.example/manifest"
        ),
        lambda v: v["artifacts"][0].update(
            source_url="https://name:secret@www.arista.com/manifest"
        ),
        lambda v: v["artifacts"][0].update(file_name="../manifest.txt"),
        lambda v: v["artifacts"][0].update(file_name="/tmp/manifest.txt"),
        lambda v: v["artifacts"][0].update(file_name="nested/manifest.txt"),
        lambda v: v["artifacts"][0].update(observed_at="2026-10-26T12:00:00"),
        lambda v: v["artifacts"][0].update(observed_at="2027-10-26T12:00:00Z"),
        lambda v: v["artifacts"][0].update(redistribution="permission_confirmed"),
        lambda v: v["artifacts"][0].update(kind="device_export"),
        lambda v: v["artifacts"].append(deepcopy(v["artifacts"][0])),
        lambda v: v["artifacts"].append(
            dict(v["artifacts"][0], id="unused", file_name="unused.txt")
        ),
        lambda v: v["claims"].append(deepcopy(v["claims"][0])),
        lambda v: v["target"].update(vendor="uninstalled"),
        lambda v: v.update(private_notes="not accepted"),
    ],
)
def test_ambiguous_mismatched_or_unbounded_proposals_are_rejected(tmp_path, mutate):
    value = documented(tmp_path)
    mutate(value)
    with pytest.raises(ValueError):
        inventory.validate(value, now=NOW)


def test_named_byte_checks_reject_hash_changes_symlinks_and_size_overruns(tmp_path):
    value = documented(tmp_path)
    assert inventory.audit(value, tmp_path, now=NOW)["checked_artifacts"] == 1
    with pytest.raises(ValueError, match="explicit"):
        inventory.audit(value, now=NOW)
    artifact = tmp_path / "manifest.txt"
    raw = artifact.read_bytes()
    artifact.write_bytes(raw + b"changed")
    with pytest.raises(ValueError, match="fingerprint"):
        inventory.audit(value, tmp_path, now=NOW)
    artifact.unlink()
    (tmp_path / "other.txt").write_bytes(raw)
    artifact.symlink_to(tmp_path / "other.txt")
    with pytest.raises(ValueError, match="regular"):
        inventory.audit(value, tmp_path, now=NOW)
    artifact.unlink()
    artifact.write_bytes(raw)
    with patch.object(inventory, "MAX_ARTIFACT_BYTES", 1):
        with pytest.raises(ValueError, match="32 MB"):
            inventory.audit(value, tmp_path, now=NOW)
    with patch.object(inventory, "MAX_TOTAL_BYTES", 1):
        with pytest.raises(ValueError, match="budget"):
            inventory.audit(value, tmp_path, now=NOW)


def test_private_device_export_can_be_a_proposal_without_publisher_authenticity(tmp_path):
    value = documented(tmp_path)
    value["artifacts"][0].update(kind="device_export", source_url=None)
    result = inventory.audit(value, tmp_path, now=NOW)
    assert not result["inventory_verified"] and not result["evidence_published"]


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":1,"schema_version":1}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b"not JSON",
        b"\xff",
        b"[" * 5000,
        b" " * (inventory.MAX_PROPOSAL_BYTES + 1),
    ],
)
def test_proposal_loader_rejects_ambiguous_nonfinite_and_oversize_input(raw):
    with pytest.raises(ValueError):
        inventory.loads(raw)


def test_cli_is_offline_vault_free_and_reports_rejection_without_private_values(tmp_path, capsys):
    with patch(
        "infrastructure_impact.research_cli.connect", side_effect=AssertionError("Vault forbidden")
    ):
        main(
            [
                "inventory-template",
                "--vendor",
                "arista",
                "--product",
                "Arista EOS",
                "--build",
                "4.32.2F",
                "--component",
                "OpenSSH",
                "--role",
                "SSH management",
            ]
        )
        value = json.loads(capsys.readouterr().out)
        path = tmp_path / "proposal.json"
        path.write_text(json.dumps(value))
        main(["inventory-audit", str(path)])
        assert json.loads(capsys.readouterr().out)["evidence_published"] is False
        path.write_text('{"PRIVATE_SENTINEL":1}')
        with pytest.raises(SystemExit):
            main(["inventory-audit", str(path)])
        assert "PRIVATE_SENTINEL" not in capsys.readouterr().err


def test_pilot_template_contract_is_embedded_offline_and_checks_do_not_erase_evidence():
    schema = json.loads((PACKAGE / "schemas/product-cohorts-v1.json").read_text())
    embedded = schema["properties"]["build_pilot"]["properties"]["targets"]["items"]["properties"][
        "inventory_proposal_template"
    ]
    contract = json.loads((PACKAGE / "schemas/build-inventory-submission-v1.json").read_text())
    assert embedded == {
        k: v for k, v in contract.items() if k not in {"$schema", "$id", "title", "description"}
    }
    from infrastructure_impact.application.product_cohorts import product_cohorts

    pilot = build_pilot({})
    target = pilot["targets"][0]
    data = dict(
        vendors={},
        records=[],
        health=[
            dict(
                vendor=target["vendor"],
                source_url=target["source_url"],
                outcome="error",
                checked_at="2026-10-26T12:00:00Z",
                error_code="access_denied",
            )
        ],
    )
    report = product_cohorts(data)
    validator("product_cohorts").validate(report)
    assert report["build_pilot"]["targets"][0]["source_check"]["outcome"] == "error"
    for target in report["build_pilot"]["targets"]:
        value = target["inventory_proposal_template"]
        assert value["target"]["firmware_build"] == target["firmware_build"]
        assert all(c["state"] == "unknown" for c in value["claims"])
        assert not inventory.audit(value)["inventory_verified"]


def test_fifo_cannot_block_an_offline_evidence_audit(tmp_path):
    value = documented(tmp_path)
    artifact = tmp_path / "manifest.txt"
    artifact.unlink()
    os.mkfifo(artifact)
    with pytest.raises(ValueError, match="regular"):
        inventory.audit(value, tmp_path, now=NOW)
