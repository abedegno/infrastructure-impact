"""Verify the Pages job dependency, artifact readiness, and health identity."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_pages_redeploy import archive
from test_pages_redeploy import candidate as candidate

ROOT = Path(__file__).resolve().parents[1]


def workflow_job(filename, name):
    workflow = (ROOT / ".github/workflows" / filename).read_text()
    match = re.search(rf"^  {name}:\n(.*?)(?=^  \S|\Z)", workflow, re.M | re.S)
    assert match, f"{filename} has no {name} job"
    return match[1]


def expression(job, field, indent):
    match = re.search(rf"^{' ' * indent}{field}: \$\{{\{{ (.+) \}}\}}$", job, re.M)
    assert match, f"missing {field} expression"
    return match[1]


def evaluate(expr, **context):
    return eval(
        expr.replace("&&", " and ").replace("||", " or "),
        {"__builtins__": {}},
        context,
    )


class ArtifactOutputs(dict):
    def __getattr__(self, name):
        return self.get(name, "")


def deployment_allowed(
    filename,
    producer_name,
    *,
    outcome,
    artifact_outputs,
    producer_result,
    identity_available=True,
    producer_attempt="1",
    deploy_attempt="1",
):
    producer = workflow_job(filename, producer_name)
    deploy = workflow_job(filename, "deploy")
    step = SimpleNamespace(outcome=outcome, outputs=ArtifactOutputs(artifact_outputs))
    accepted_attempt = evaluate(
        expression(producer, "accepted_attempt", 6),
        steps=SimpleNamespace(pages_upload=step),
        github=SimpleNamespace(run_attempt=producer_attempt),
    )
    needs = SimpleNamespace(
        **{
            producer_name: SimpleNamespace(
                result=producer_result,
                outputs=SimpleNamespace(
                    accepted_attempt=accepted_attempt,
                    source_commit="2" * 40 if identity_available else "",
                    generation="1" * 32 if identity_available else "",
                ),
            )
        }
    )
    return bool(
        evaluate(
            expression(deploy, "if", 4),
            needs=needs,
            github=SimpleNamespace(run_attempt=deploy_attempt),
        )
    )


WORKFLOWS = [("collect.yaml", "publish"), ("pages-redeploy.yaml", "redeploy")]


@pytest.mark.parametrize("filename,producer_name", WORKFLOWS)
def test_deploy_runs_only_after_an_accepted_upload(filename, producer_name):
    producer = workflow_job(filename, producer_name)
    deploy = workflow_job(filename, "deploy")
    assert f"    needs: {producer_name}\n" in deploy
    for action in ("configure-pages@", "deploy-pages@"):
        assert action not in producer
        assert action in deploy
    assert "upload-pages-artifact@" in producer
    assert "id: pages_upload" in producer
    assert "upload-pages-artifact@" not in deploy
    assert "      name: github-pages\n" in producer
    assert "      name: github-pages\n" in deploy
    assert "page_url" not in producer
    assert "url: ${{ steps.deployment.outputs.page_url }}" in deploy

    for outcome, outputs, result, expected in (
        ("success", {"artifact_id": "123"}, "success", True),
        ("success", {}, "success", False),
        ("success", {"artifact-id": "123"}, "success", False),
        ("success", {"artifact_id": ""}, "success", False),
        ("skipped", {}, "success", False),
        ("failure", {"artifact_id": "123"}, "success", False),
        ("success", {"artifact_id": "123"}, "failure", False),
        ("success", {"artifact_id": "123"}, "cancelled", False),
    ):
        assert (
            deployment_allowed(
                filename,
                producer_name,
                outcome=outcome,
                artifact_outputs=outputs,
                producer_result=result,
            )
            is expected
        )


@pytest.mark.parametrize("filename,producer_name", WORKFLOWS)
@pytest.mark.parametrize(
    ("producer_attempt", "deploy_attempt", "expected"),
    [("1", "1", True), ("1", "2", False), ("2", "2", True)],
)
def test_deploy_requires_acceptance_in_the_current_attempt(
    filename, producer_name, producer_attempt, deploy_attempt, expected
):
    assert (
        deployment_allowed(
            filename,
            producer_name,
            outcome="success",
            artifact_outputs={"artifact_id": "123"},
            producer_result="success",
            producer_attempt=producer_attempt,
            deploy_attempt=deploy_attempt,
        )
        is expected
    )


@pytest.mark.parametrize("filename,producer_name", WORKFLOWS)
def test_deploy_requires_the_health_identity(filename, producer_name):
    assert not deployment_allowed(
        filename,
        producer_name,
        outcome="success",
        artifact_outputs={"artifact_id": "123"},
        producer_result="success",
        identity_available=False,
    )


@pytest.mark.parametrize("source_commit", ["2" * 40, "main"])
def test_collection_health_checks_out_validated_source(source_commit, tmp_path):
    producer = workflow_job("collect.yaml", "publish")
    deploy = workflow_job("collect.yaml", "deploy")
    pin_step = producer.split("- name: Check pinned source\n", 1)[1].split("      - ", 1)[0]
    output = tmp_path / "github-output"
    script = pin_step.split("        run: |\n", 1)[1]
    completed = subprocess.run(
        ["bash", "-c", script],
        env={**os.environ, "SOURCE_COMMIT": source_commit, "GITHUB_OUTPUT": str(output)},
        capture_output=True,
        text=True,
    )
    if source_commit == "main":
        assert completed.returncode != 0
        assert not output.exists()
    else:
        assert completed.returncode == 0, completed.stderr
        assert output.exists(), "validated source pin was not captured"
        assert output.read_text() == f"source_commit={source_commit}\n"
    assert "id: source_pin" in pin_step
    assert expression(producer, "source_commit", 6) == "steps.source_pin.outputs.source_commit"
    assert expression(producer, "ref", 10) == "steps.source_pin.outputs.source_commit"
    assert expression(deploy, "ref", 10) == "needs.publish.outputs.source_commit"
    assert "persist-credentials: false" in deploy
    assert 'python checks/public_health.py "$PUBLIC_URL"' in deploy


def test_recovery_health_uses_the_verifier_generation_and_workflow_revision():
    producer = workflow_job("pages-redeploy.yaml", "redeploy")
    deploy = workflow_job("pages-redeploy.yaml", "deploy")
    assert expression(producer, "generation", 6) == "steps.verify.outputs.generation"
    assert expression(deploy, "ref", 10) == "github.sha"
    assert expression(deploy, "GENERATION", 10) == "needs.redeploy.outputs.generation"
    assert "persist-credentials: false" in deploy
    assert "accepted/state/current.json" not in deploy
    assert "checks/pages_redeploy.py" in producer
    assert producer.index("checks/pages_redeploy.py") < producer.index("upload-pages-artifact@")
    command = 'python checks/public_health.py "$PUBLIC_URL" --generation "$GENERATION"'
    assert f"{command}\n" in deploy
    assert f"{command} --verify-archive\n" in deploy


@pytest.mark.parametrize("artifact_matches", [True, False])
def test_recovery_exports_the_generation_of_verified_bytes(candidate, artifact_matches):
    archive(candidate)
    root = candidate["root"]
    producer = workflow_job("pages-redeploy.yaml", "redeploy")
    verify_step = producer.split(
        "- name: Verify exact accepted publication before extraction\n", 1
    )[1].split("      - ", 1)[0]
    script = verify_step.split("        run: |\n", 1)[1]
    receipt_path = root / re.search(r"--receipt (\S+)", script)[1]
    receipt_path.parent.mkdir(parents=True)
    receipt_path.write_text(json.dumps(candidate["receipt"]))
    (root / "checks").symlink_to(ROOT / "checks", target_is_directory=True)
    for name in ("artifact", "run", "jobs"):
        (root / f"{name}.json").write_text(
            json.dumps(candidate["metadata" if name == "artifact" else name])
        )
    (root / "accepted.json").write_bytes(candidate["accepted"])
    (root / "artifact.zip").write_bytes(candidate["zip"] if artifact_matches else b"invalid")
    output = root / "github-output"
    public = root / "public"
    completed = subprocess.run(
        ["bash", "-c", "\n".join(line[10:] for line in script.splitlines())],
        cwd=root,
        env={
            **os.environ,
            "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
            "RETRY_TEMP": str(root),
            "ACCEPTED_MANIFEST": str(root / "accepted.json"),
            "PUBLIC_OUTPUT": str(public),
            "GITHUB_OUTPUT": str(output),
        },
        capture_output=True,
        text=True,
    )
    if artifact_matches:
        assert completed.returncode == 0, completed.stderr
        assert output.read_text() == f"generation={'1' * 32}\n"
        assert (public / "index.html").read_bytes() == b"synthetic public page"
    else:
        assert completed.returncode != 0
        assert not output.exists()
        assert not public.exists()
