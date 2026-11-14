"""Closed hosted analysis configuration; all data/state is authored or packaged public input."""

import pytest
from test_hosted_maintenance import forbidden, invoke
from test_hosted_maintenance import recovery as recovery
from test_hosted_publication_format import target_recovery as target_recovery
from test_hosted_workflow_protocol import legacy_workflow as legacy_workflow
from test_target_import_stage import setup as setup

from infrastructure_impact import worker
from infrastructure_impact.application import switching_analysis_profiles as profiles
from ops import hosted_job as hosted

PROFILE = "campus-switching-openvuln-2026-11-14-v1"


@pytest.mark.parametrize("selector,format", [(PROFILE, "v1"), ("unknown", "v2")])
def test_worker_profile_rejected_before_state(tmp_path, monkeypatch, selector, format):
    monkeypatch.setenv("IMPACT_HOME", str(tmp_path / "absent"))
    monkeypatch.setattr(worker, "execute", forbidden)
    with pytest.raises(ValueError):
        worker.collect_once(publication_format=format, switching_analysis_profile=selector)
    assert not (tmp_path / "absent").exists()


@pytest.mark.parametrize("extra", [("--restore-only", "absent"), ("--validate-encrypted-state",)])
def test_selected_recovery_fails_before_keys(tmp_path, monkeypatch, capsys, extra):
    monkeypatch.delenv("IMPACT_STATE_KEY", raising=False)
    monkeypatch.setattr(hosted, "state_backend", forbidden)
    with pytest.raises(SystemExit):
        invoke(
            monkeypatch,
            tmp_path / "state",
            tmp_path / "public",
            "--publication-format",
            "v2",
            "--switching-analysis-profile",
            PROFILE,
            *extra,
        )
    assert "analysis" in capsys.readouterr().err.lower()


def test_identity_rejects_missing_mixed_and_rehashed():
    identity = profiles.profile(PROFILE).identity()
    from infrastructure_impact.application.import_candidate import _analysis_identity

    assert _analysis_identity(identity) == PROFILE
    for value in (
        {},
        dict(identity, input_sha256="0" * 64),
        dict(identity, extra=1),
        dict(identity, api_frames=True),
        dict(identity, profile_id="unknown"),
    ):
        with pytest.raises(ValueError):
            _analysis_identity(value)


def test_public_reference_rejects_absent_owned_api_proof(tmp_path):
    from test_static_delivery import dataset

    from checks.switching_analysis_acceptance import write_reference
    from infrastructure_impact.application import publication

    out = publication.publish(
        dataset(), tmp_path / "public", publication_format="v2", include_switching_analysis=True
    )
    with pytest.raises(ValueError, match="owned.*API"):
        write_reference(out, PROFILE, tmp_path / "proof")
    assert not (tmp_path / "proof").exists()


def test_selected_native_projection_reloads_profile_and_requires_exact_roots(tmp_path, monkeypatch):
    import copy
    from io import StringIO

    from test_static_delivery import dataset

    from infrastructure_impact.application import publication, publication_v2, query
    from infrastructure_impact.application.publication_reader import PublicationReader
    from infrastructure_impact.storage import repository

    native = dataset()
    options = profiles.profile(PROFILE).build_options()
    built = copy.deepcopy(native)
    built["research"]["switching_analysis_input"] = options["switching_analysis_input"]
    out = publication.publish(
        built, tmp_path / "public", publication_format="v2", include_switching_analysis=True
    )
    monkeypatch.setattr(repository, "connect", lambda *a, **k: StringIO())
    monkeypatch.setattr(query, "state", lambda db: copy.deepcopy(native))
    publication_v2.native_parity(
        "authored", out, tmp_path, PublicationReader(out), switching_analysis_profile=PROFILE
    )
    with pytest.raises(ValueError, match="logical root"):
        publication_v2.native_parity("authored", out, tmp_path, PublicationReader(out))


def test_old_pinned_helper_rejects_selected_profile_before_invocation(legacy_workflow):
    from test_hosted_workflow_protocol import preflight

    source, env, _, _ = legacy_workflow
    env.update(PUBLICATION_FORMAT="v1", SWITCHING_ANALYSIS_PROFILE=PROFILE)
    result = preflight(source, env)
    assert result.returncode != 0
    assert "analysis" in result.stderr.lower()


def test_certification_retained_selected_rejected_before_checkout(tmp_path):
    from test_candidate_certification_workflow import execute

    result = execute(
        "Validate manual inputs",
        tmp_path,
        SOURCE_COMMIT="a" * 40,
        PREVIOUS_RUN_ID="",
        RETAINED_ONLY="true",
        SWITCHING_ANALYSIS_PROFILE=PROFILE,
    )
    assert result.returncode != 0


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "missing",
        "hash",
        "null",
        "request_missing",
        "request_hash",
        "request_null",
        "paired_null",
    ],
)
def test_selected_stage_fresh_worker_binds_context_and_blocks_invalid_candidate(
    setup, monkeypatch, mutation
):
    import json

    from test_target_import_stage import receipt, serve, snapshot

    from infrastructure_impact.application import import_candidate, target_import_stage

    database, selected, raws, output, home = setup
    from contextlib import closing

    from infrastructure_impact.adapters.common import assessment, base
    from infrastructure_impact.storage.repository import connect, ingest

    record = base(
        "juniper",
        "https://www.juniper.net/synthetic/baseline",
        "AUTHORED",
        "Authored baseline",
        "2025-01-01T00:00:00Z",
    )
    record["cves"] = ["CVE-2024-6387"]
    record["assessments"] = [assessment("CVE-2024-6387", "Junos OS", "affected", "Synthetic")]
    with closing(connect(database)) as db:
        ingest(db, b"authored baseline", record["source_url"], lambda *a: record, "juniper")
    serve(monkeypatch, selected, raws)
    accepted = receipt(database, selected)
    before = snapshot(database)
    real_verify = import_candidate.verify

    def verify(database, public, profile, **kwargs):
        assert kwargs["switching_analysis_profile"] == PROFILE
        context_path = database.parent.parent / "home/target-import-context.json"
        context = json.loads(context_path.read_bytes())
        assert context["switching_analysis_profile"] == profiles.profile(PROFILE).identity()
        if mutation == "missing":
            del context["switching_analysis_profile"]
        if mutation == "hash":
            context["switching_analysis_profile"]["input_sha256"] = "0" * 64
        if mutation == "null":
            context["switching_analysis_profile"] = None
        if mutation == "paired_null":
            context["switching_analysis_profile"] = None
        context_path.write_text(json.dumps(context))
        real_run = import_candidate.subprocess.run

        def tampered_run(*args, **options):
            request_path = database.parent.parent / "home/target-import-request.json"
            request = json.loads(request_path.read_bytes())
            if mutation == "request_missing":
                del request["switching_analysis_profile"]
            elif mutation == "request_hash":
                request["switching_analysis_profile"]["input_sha256"] = "0" * 64
            else:
                request["switching_analysis_profile"] = None
            request_path.write_text(json.dumps(request))
            return real_run(*args, **options)

        if mutation in ("request_missing", "request_hash", "request_null", "paired_null"):
            with monkeypatch.context() as patch:
                patch.setattr(import_candidate.subprocess, "run", tampered_run)
                return real_verify(database, public, profile, **kwargs)
        return real_verify(database, public, profile, **kwargs)

    monkeypatch.setattr(target_import_stage, "verify", verify)
    result = target_import_stage.stage(
        database,
        selected,
        accepted["fingerprint"],
        output,
        lock_home=home,
        accepted_preview=accepted,
        publication_format="v2",
        switching_analysis_profile=PROFILE,
    )
    assert snapshot(database) == before
    assert (result["outcome"] == "completed") is (mutation is None), __import__("json").dumps(
        result
    )
    if mutation is None:
        from infrastructure_impact.application.publication_reader import PublicationReader

        assert (
            PublicationReader(output / "public").switching_analysis()["availability"] == "available"
        )
        request = json.loads((output / "private/home/target-import-request.json").read_bytes())
        assert request["switching_analysis_profile"] == profiles.profile(PROFILE).identity()
        assert len(json.dumps(request)) < 30_000
    else:
        assert result["staged_database"] is None
        assert result["checks"]["candidate_validated"] is False, __import__("json").dumps(result)


@pytest.mark.parametrize("mode", ["ordinary", "maintenance", "preview"])
def test_selected_hosted_ordinary_maintenance_and_preview(recovery, tmp_path, monkeypatch, mode):
    from test_hosted_maintenance import PROFILE as MAINTENANCE
    from test_hosted_maintenance import effect_values, inject_sources
    from test_hosted_publication_format import offline_collection

    from infrastructure_impact.application import maintenance
    from infrastructure_impact.application.publication_reader import PublicationReader

    state, database, _, effects = recovery
    offline_collection(monkeypatch)
    if mode != "ordinary":
        inject_sources(monkeypatch)
    output = tmp_path / "selected-public"
    extra = []
    if mode != "ordinary":
        extra += [
            "--maintenance-profile",
            MAINTENANCE,
            "--maintenance-mode",
            "preview" if mode == "preview" else "apply",
        ]
    if mode == "maintenance":
        extra += [
            "--maintenance-preview-fingerprint",
            maintenance.preview(database, MAINTENANCE)["fingerprint"],
        ]
    invoke(
        monkeypatch,
        state,
        output,
        "--publication-format",
        "v2",
        "--switching-analysis-profile",
        PROFILE,
        *extra,
    )
    if mode == "preview":
        assert not (output / "data/index.json").exists()
        assert effect_values(effects) == {"mode": "preview", "preview_ready": "true"}
    else:
        assert PublicationReader(output).switching_analysis()["availability"] == "available"
        assert effect_values(effects)["publish_ready"] == "true"


def test_selected_public_monitor(tmp_path, monkeypatch):
    from test_static_delivery import dataset

    from infrastructure_impact.application import import_candidate, publication, publication_v2

    native = dataset()
    native["research"]["switching_analysis_input"] = profiles.profile(PROFILE).build_options()[
        "switching_analysis_input"
    ]
    out = publication.publish(
        native, tmp_path / "publication", publication_format="v2", include_switching_analysis=True
    )
    facts = import_candidate._empty(publication_format="v2")["candidate"]
    publication_v2.inspect_bundle(out, facts)
    import_candidate._monitors(out, tmp_path, facts)
    assert facts["default_monitor_passed"] is True


def authored_api_publication(tmp_path, *, wrong_source=False):
    """One owned API fix, normalized advisory and current claim with matching identities."""
    import copy
    import json

    from test_first_fixed import record
    from test_static_delivery import dataset
    from test_switching_upgrades import AT, inputs

    from infrastructure_impact.adapters.common import assessment, base
    from infrastructure_impact.application import publication
    from infrastructure_impact.application import switching_evidence as contracts

    frame = profiles.profile(PROFILE).build_options()["switching_analysis_input"]
    api = next(f for f in frame["api_results"] if f["query_release"] == "17.12.1")
    context = next(
        c for c in api["advisory_context"] if c["advisory_id"] == "cisco-sa-ios-xmcp-thbAr34t"
    )
    if wrong_source:
        api["source"]["sha256"] = "b" * 64
    native = dataset()
    ev, _, _ = inputs([("2025-01-01", ["17.12.8"])])
    raw = copy.deepcopy(ev)
    raw["claims"][0] = json.loads(
        json.dumps(raw["claims"][0]).replace("CVE-2024-6387", "CVE-2026-20301")
    )
    raw["claims"][0]["advisory_id"] = context["advisory_id"]
    raw["claims"][0]["publisher"]["id"] = context["advisory_id"]
    raw["claims"][0]["version_expressions"] = ["17.12.1"]
    raw["claims"][0]["product_id"] = raw["claims"][0]["product"]
    c = contracts.project(raw, publication=None, generated_at=AT)["claims"][0]
    r = base(
        "cisco",
        c["source"]["source_url"],
        c["advisory_id"],
        "Authored API proof",
        c["initial_published_at"],
    )
    r.update(record(c["advisory_id"], ["17.12.1"]))
    r.update(
        published_at=c["initial_published_at"],
        source_url=c["source"]["source_url"],
        source_observed_at=c["source"]["retrieved_at"],
        evidence_id=999,
        cves=[c["cve_id"]],
    )
    r["assessments"][0] = {
        **assessment(c["cve_id"], c["product"], "affected", "Authored"),
        **r["assessments"][0],
        "cve_id": c["cve_id"],
        "product": c["product"],
    }
    native["records"].append(r)
    native.pop("current_evidence")
    native["research"]["switching_input"] = contracts.project(
        raw, publication=None, generated_at=AT
    )
    native["research"]["switching_analysis_input"] = frame
    return publication.publish(
        native, tmp_path / "public", publication_format="v2", include_switching_analysis=True
    )


def test_public_reference_full_typed_selection_and_exact_export_hashes(tmp_path):
    import json
    from hashlib import sha256

    from checks.switching_analysis_acceptance import write_reference
    from infrastructure_impact.application import switching_analysis as analysis
    from infrastructure_impact.application.publication_reader import PublicationReader

    out = authored_api_publication(tmp_path)
    proof = write_reference(out, PROFILE, tmp_path / "proof")
    selected = PublicationReader(out).switching_analysis()
    raw = (tmp_path / "proof/selected-analysis.json").read_bytes()
    assert json.loads(raw) == selected
    assert proof["analysis_json"] == {
        "path": "selected-analysis.json",
        "sha256": sha256(raw).hexdigest(),
        "bytes": len(raw),
    }
    for field, csv in [
        ("analysis_csv", analysis.analysis_csv_export(selected)),
        ("upgrades_csv", analysis.csv_export(selected["upgrades"])),
    ]:
        encoded = csv.encode("utf-8")
        assert proof[field] == {"sha256": sha256(encoded).hexdigest(), "bytes": len(encoded)}
    assert proof["profile"] == profiles.profile(PROFILE).identity()
    assert proof["publication"] == selected["publication"]
    assert proof["generated_at"] == selected["generated_at"]


def test_api_proof_count_requires_owned_target_and_referenced_proof():
    from checks.switching_analysis_acceptance import _owned_api_proofs

    source = {
        "url": "https://apix.cisco.com/security/advisories/v2/OSType/iosxe?version=17.12.1",
        "sha256": "a" * 64,
        "retrieved_at": "2026-11-13T00:00:00Z",
    }
    context = {
        "advisory_id": "authored",
        "cve_refs": ["CVE-2099-12345"],
        "source_locator": "/advisories/0/firstFixed",
        "first_fixed_state": "present",
        "source_first_fixed": ["17.12.8"],
    }
    frame = {
        "api_results": [
            {"source": source, "query_release": "17.12.1", "advisory_context": [context]}
        ]
    }
    proof = {
        "method": "openvuln_api",
        "kind": "publisher_api_first_fixed",
        "locator": context["source_locator"],
        "source": {
            "source_url": source["url"],
            "source_sha256": source["sha256"],
            "retrieved_at": source["retrieved_at"],
            "source_locator": context["source_locator"],
        },
    }
    requirement = {
        "claim_id": "owned",
        "target": None,
        "proof_ref": "api",
        "scenario": "publisher_first_fixed",
        "train": "17.12",
        "issues": [],
    }
    compact = {
        "members": {
            "owned": {
                "vendor": "cisco",
                "family": "cisco-iosxe",
                "advisory_id": "authored",
                "cve_id": "CVE-2099-12345",
            }
        },
        "requirements": [requirement],
        "facts": {"api": [proof], "unused": []},
    }
    selected = {"upgrades": {"requirements": compact}}
    assert _owned_api_proofs(selected, frame) == 0
    requirement["target"] = "17.12.8"
    assert _owned_api_proofs(selected, frame) == 1
    requirement["issues"] = ["first_fixed_conflict"]
    assert _owned_api_proofs(selected, frame) == 0
    requirement["issues"] = []
    requirement["proof_ref"] = "unused"
    assert _owned_api_proofs(selected, frame) == 0
    requirement["proof_ref"] = "api"
    proof["source"]["source_sha256"] = "0" * 64
    assert _owned_api_proofs(selected, frame) == 0


@pytest.mark.parametrize("status", ["failed", "mixed", "passed"])
def test_public_artifact_wrapper_requires_completed_receipt_and_generation(tmp_path, status):
    completed = status != "failed"
    import json

    from test_target_import_contracts import passing_candidate, result

    from checks.switching_analysis_acceptance import prepare_artifacts
    from infrastructure_impact.collection.target_import_profiles import PROFILE_ID, profile

    selected = profile(PROFILE_ID)
    receipt = result(selected)
    receipt.update(schema_version=2, publication_format="v2")
    if completed:
        receipt.update(
            outcome="completed",
            failure_code=None,
            staged_database="private/data/intel.sqlite3",
            public_directory="public/",
        )
        receipt["checks"] = dict.fromkeys(receipt["checks"], True)
        for target in receipt["targets"]:
            target["status"] = "unchanged"
        receipt["counters"]["unchanged"] = len(selected.targets)
        receipt["candidate"] = dict(
            passing_candidate(),
            archive_scope="snapshot-v1",
            representation="publication-v2-physical",
        )
    (tmp_path / "stage-result.json").write_text(json.dumps(receipt))
    if completed:
        # A completed but mixed candidate must never create public proof output.
        out = authored_api_publication(tmp_path / "private-stage")
        import shutil

        shutil.copytree(out, tmp_path / "private-stage/copied")
        # publish returns a generation path; wrapper requires the explicit public copy.
        shutil.rmtree(tmp_path / "private-stage/public")
        (tmp_path / "private-stage/copied").rename(tmp_path / "private-stage/public")
    if status == "passed":
        from hashlib import sha256

        from infrastructure_impact.application.publication_reader import PublicationReader

        public = tmp_path / "private-stage/public"
        receipt["candidate"]["generation"] = PublicationReader(public).identity["publication"]["id"]
        receipt["candidate"]["manifest_sha256"] = sha256(
            (public / "manifest.json").read_bytes()
        ).hexdigest()
        (tmp_path / "stage-result.json").write_text(json.dumps(receipt))
        attestation = prepare_artifacts(tmp_path, PROFILE, "a" * 40)
        assert attestation["source_commit"] == "a" * 40
        assert attestation["manifest_sha256"] == receipt["candidate"]["manifest_sha256"]
        assert attestation["profile"] == profiles.profile(PROFILE).identity()
        assert {p.name for p in (tmp_path / "public-analysis-proof").iterdir()} == {
            "proof.json",
            "selected-analysis.json",
            "attestation.json",
        }
    else:
        with pytest.raises((ValueError, FileNotFoundError)):
            prepare_artifacts(tmp_path, PROFILE, "a" * 40)
        assert not (tmp_path / "public-analysis-proof").exists()


@pytest.mark.parametrize("failure", ["build", "parity"])
def test_selected_failed_candidate_cannot_promote_or_publish(
    target_recovery, tmp_path, monkeypatch, failure
):
    from test_hosted_maintenance import effect_values
    from test_hosted_target_import import apply, state_bytes
    from test_target_import_stage import serve

    from infrastructure_impact.application import import_candidate, target_import_stage

    state, _, _, effects, selected, raws = target_recovery
    serve(monkeypatch, selected, raws)
    before = state_bytes(state)

    def rejected(database, public, profile, **kwargs):
        assert kwargs == {"publication_format": "v2", "switching_analysis_profile": PROFILE}
        value = import_candidate._empty("validation_failed", publication_format="v2")
        value["audit_passed"] = True
        if failure == "parity":
            value["candidate"]["parity_passed"] = False
        return value

    monkeypatch.setattr(target_import_stage, "verify", rejected)
    monkeypatch.setattr(hosted, "backup_verified", forbidden)
    output = tmp_path / "public"
    with pytest.raises(RuntimeError):
        apply(
            target_recovery,
            monkeypatch,
            output,
            extra=("--publication-format", "v2", "--switching-analysis-profile", PROFILE),
        )
    assert state_bytes(state) == before
    assert not output.exists()
    assert effect_values(effects) == {"mode": "apply"}


def test_public_reference_rejects_rehashed_api_receipt_from_another_profile(tmp_path):
    from checks.switching_analysis_acceptance import write_reference

    out = authored_api_publication(tmp_path, wrong_source=True)
    with pytest.raises(ValueError, match="owned.*API"):
        write_reference(out, PROFILE, tmp_path / "proof")
    assert not (tmp_path / "proof").exists()


def test_v2_pinned_helper_without_analysis_flag_rejected(legacy_workflow):
    from test_hosted_workflow_protocol import preflight

    source, env, _, _ = legacy_workflow
    (source / "ops/hosted_job.py").write_text(
        "HOSTED_WORKFLOW_PROTOCOL = 'effects-v1'\nHOSTED_PUBLICATION_FORMATS = ('v1', 'v2')\nprint('usage: old helper')\n"
    )
    env.update(PUBLICATION_FORMAT="v2", SWITCHING_ANALYSIS_PROFILE=PROFILE)
    result = preflight(source, env)
    assert result.returncode != 0
    assert "does not support switching analysis" in result.stderr


@pytest.mark.parametrize("selector,format", [("unknown", "v2"), (PROFILE, "v1")])
def test_stage_cli_profile_invalid_before_output_or_database(tmp_path, capsys, selector, format):
    from infrastructure_impact.cli import main
    from infrastructure_impact.collection.target_import_profiles import PROFILE_ID

    with pytest.raises(SystemExit):
        main(
            [
                "target-import",
                "stage",
                "--profile",
                PROFILE_ID,
                "--database",
                str(tmp_path / "absent.sqlite3"),
                "--home",
                str(tmp_path / "home"),
                "--preview",
                str(tmp_path / "absent-preview.json"),
                "--output",
                str(tmp_path / "output"),
                "--publication-format",
                format,
                "--switching-analysis-profile",
                selector,
            ]
        )
    assert "target_import_failed" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []
