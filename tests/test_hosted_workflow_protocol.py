"""The new workflow must remain safe across its separately approved source pin."""

import io
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from test_hosted_maintenance import PROFILE, effect_values, gate, workflow_steps
from test_hosted_maintenance import recovery as recovery

ROOT = Path(__file__).resolve().parents[1]
LEGACY = "57b76f7db3486588538dc93b3752327730643cce"


def script(name):
    workflow = (ROOT / ".github/workflows/collect.yaml").read_text()
    blocks = re.split(r"^      - ", workflow, flags=re.M)
    matches = [b for b in blocks if b.startswith("name: " + name + "\n")]
    assert len(matches) == 1, f"missing workflow step: {name}"
    raw = matches[0].split("        run: |\n", 1)[1]
    return "\n".join(line[10:] for line in raw.splitlines())


@pytest.fixture
def legacy_workflow(recovery, tmp_path):
    state, database, key, effects = recovery
    source = tmp_path / "pinned-source"
    source.mkdir()
    # Mandatory regression tests need neither Git nor historical objects.
    (source / "ops").mkdir()
    (source / "ops/hosted_job.py").write_bytes(
        (ROOT / "tests/compat/hosted_job_v011.py").read_bytes()
    )
    (source / "infrastructure_impact").symlink_to(
        ROOT / "infrastructure_impact", target_is_directory=True
    )
    shim = tmp_path / "uv"
    shim.write_text(
        f"#!{sys.executable}\n"
        + """
import os,runpy,sys
from pathlib import Path
args = sys.argv[1:]
assert args[:2] == ['run', '--no-dev']
args = args[2:]
assert args[0] == 'python'
if args[1] == 'ops/hosted_job.py' and '--validate-encrypted-state' not in args:
    # Stub only acquisition; execute the pinned helper's real encrypted lifecycle.
    sys.path.insert(0, os.getcwd())
    import infrastructure_impact.worker as worker
    def collect():
        from contextlib import closing
        from infrastructure_impact.storage.repository import connect, evidence
        Path(os.environ['TEST_INVOKED']).touch()
        with closing(connect()) as db:
            evidence(db, b'SYNTHETIC MIXED REVISION CAPTURE', 'https://www.arista.com/synthetic')
        if os.environ.get('TEST_FAIL') == 'true':
            raise RuntimeError('Synthetic acquisition failure')
        target = Path(os.environ['PUBLIC_OUTPUT'])
        target.mkdir()
        (target / 'index.html').write_text('synthetic public output')
        return {'outcome': 'partial', 'failures': 1}
    worker.collect_once = collect
    sys.argv = args[1:]
    runpy.run_path(args[1], run_name='__main__')
else:
    os.execv(sys.executable, [sys.executable, *args[1:]])
"""
    )
    shim.chmod(0o755)
    protocol_output = tmp_path / "protocol-output"
    env = {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "PYTHONPATH": str(source),
        "GITHUB_OUTPUT": str(protocol_output),
        "VAULT_PROFILE": "standard",
        "RECOVERY_STORAGE": "git",
        "REPARSE_LIMIT": "0",
        "REPARSE_VENDOR": "",
        "MAINTENANCE_PROFILE": "",
        "MAINTENANCE_MODE": "",
        "MAINTENANCE_PREVIEW_FINGERPRINT": "",
        "PRIVATE_STATE": str(state),
        "PUBLIC_OUTPUT": str(tmp_path / "public"),
        "PREVIEW_OUTPUT": str(tmp_path / "preview"),
        "BASE_PATH": "/example/",
        "TEST_INVOKED": str(tmp_path / "invoked"),
        "GITHUB_REPOSITORY": "example/recovery",
    }
    # This step must not receive the key or repository token.
    env.pop("IMPACT_STATE_KEY", None)
    env.pop("GH_TOKEN", None)
    return source, env, key, effects


def preflight(source, env):
    return subprocess.run(
        ["bash", "-c", script("Check hosted helper protocol")],
        cwd=source,
        env=env,
        text=True,
        capture_output=True,
    )


def publication_steps():
    return [
        s
        for s in workflow_steps()
        if any(
            action in s.get("uses", "")
            for action in ("configure-pages@", "upload-pages-artifact@", "deploy-pages@")
        )
        or s.get("name") == "Verify public availability and freshness"
    ]


def exercise_legacy_ordinary(legacy_workflow, failure):
    source, env, key, effects = legacy_workflow
    result = preflight(source, env)
    assert result.returncode == 0, result.stderr
    assert effect_values(Path(env["GITHUB_OUTPUT"])) == {"protocol": "legacy-ordinary-v0"}
    assert not Path(env["TEST_INVOKED"]).exists()
    helper_env = {
        **env,
        "HOSTED_PROTOCOL": "legacy-ordinary-v0",
        "IMPACT_STATE_KEY": key.decode(),
        "GITHUB_OUTPUT": str(effects),
        "TEST_FAIL": str(failure).lower(),
    }
    run = subprocess.run(
        ["bash", "-c", script("Restore, collect, audit and back up privately")],
        cwd=source,
        env=helper_env,
        text=True,
        capture_output=True,
    )
    assert (run.returncode != 0) is failure, run.stderr
    assert Path(env["TEST_INVOKED"]).exists()
    # The old helper produces no readiness effects. The explicit invocation is the bridge.
    outputs = effect_values(effects)
    assert outputs == {"legacy_started": "true"}
    cleanup = next(
        s for s in workflow_steps() if s.get("name") == "Retain only encrypted recovery copies"
    )
    assert gate(cleanup, outputs, protocol="legacy-ordinary-v0", success=not failure)
    checked = subprocess.run(
        [
            sys.executable,
            "ops/hosted_job.py",
            "--state-dir",
            env["PRIVATE_STATE"],
            "--encrypted-state",
            "--validate-encrypted-state",
        ],
        cwd=source,
        env=helper_env,
        capture_output=True,
        text=True,
    )
    assert checked.returncode == 0, checked.stderr
    assert all(
        gate(s, outputs, protocol="legacy-ordinary-v0", success=not failure) is not failure
        for s in publication_steps()
    )
    # A later cleanup validation/commit failure also prevents all Pages actions.
    assert all(
        not gate(s, outputs, protocol="legacy-ordinary-v0", success=False, hosted_outcome="success")
        for s in publication_steps()
    )


@pytest.mark.parametrize("failure", [False, True])
def test_mixed_revision_legacy_ordinary_preserves_publication_and_authenticated_failure_cleanup(
    legacy_workflow,
    failure,
):
    exercise_legacy_ordinary(legacy_workflow, failure)


@pytest.mark.parametrize("failure", [False, True])
def test_optional_exact_old_package_integration(legacy_workflow, failure):
    source, env, key, effects = legacy_workflow
    try:
        present = subprocess.run(
            ["git", "cat-file", "-e", LEGACY + "^{commit}"], cwd=ROOT, capture_output=True
        )
    except FileNotFoundError:
        pytest.skip("Optional exact-old-package integration: Git unavailable")
    if present.returncode:
        pytest.skip(
            "Optional exact-old-package integration: approved legacy Git object unavailable"
        )
    archive = subprocess.run(
        ["git", "archive", LEGACY, "infrastructure_impact"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout
    (source / "infrastructure_impact").unlink()
    with tarfile.open(fileobj=io.BytesIO(archive)) as tree:
        tree.extractall(source, filter="data")
    exercise_legacy_ordinary(legacy_workflow, failure)


@pytest.mark.parametrize(
    "controls",
    [
        {"MAINTENANCE_PROFILE": PROFILE, "MAINTENANCE_MODE": "preview"},
        {
            "MAINTENANCE_PROFILE": PROFILE,
            "MAINTENANCE_MODE": "apply",
            "MAINTENANCE_PREVIEW_FINGERPRINT": "a" * 64,
        },
        {"MAINTENANCE_PROFILE": "unknown"},
        {"MAINTENANCE_MODE": "preview"},
        {"MAINTENANCE_MODE": "garbage"},
        {"MAINTENANCE_PREVIEW_FINGERPRINT": "bad"},
        {"MAINTENANCE_PROFILE": " "},
        {"REPARSE_LIMIT": "-1"},
        {"REPARSE_LIMIT": "10001"},
        {"REPARSE_LIMIT": "bad"},
        {"REPARSE_VENDOR": "arista"},
        {"REPARSE_VENDOR": "unknown", "REPARSE_LIMIT": "1"},
        {"RECOVERY_STORAGE": "unknown"},
        {"VAULT_PROFILE": "unknown"},
    ],
)
def test_legacy_rejects_new_controls_and_invalid_generic_requests_before_invocation(
    legacy_workflow, controls
):
    source, env, key, effects = legacy_workflow
    state = Path(env["PRIVATE_STATE"])
    before = {p.name: p.read_bytes() for p in state.iterdir()}
    result = preflight(source, env | controls)
    assert result.returncode != 0
    assert effect_values(Path(env["GITHUB_OUTPUT"])) == {}
    assert not Path(env["TEST_INVOKED"]).exists()
    assert not effects.exists()
    assert {p.name: p.read_bytes() for p in state.iterdir()} == before
    cleanup = next(
        s for s in workflow_steps() if s.get("name") == "Retain only encrypted recovery copies"
    )
    assert not gate(cleanup, {}, protocol="", success=False)


@pytest.mark.parametrize(
    "marker",
    [
        "# changed legacy source",
        "HOSTED_WORKFLOW_PROTOCOL = 'effects-v2'",
        "HOSTED_WORKFLOW_PROTOCOL = object()",
        "HOSTED_WORKFLOW_PROTOCOL = ['effects-v1']",
        "HOSTED_WORKFLOW_PROTOCOL = 'effects-v1'\nHOSTED_WORKFLOW_PROTOCOL = 'effects-v2'",
        "HOSTED_WORKFLOW_PROTOCOL: str = 'effects-v1'",
        "HOSTED_WORKFLOW_PROTOCOL = (",
        "HOSTED_WORKFLOW_PROTOCOL = 'effects-' + 'v1'",
    ],
)
def test_unknown_or_ambiguous_protocol_never_executes_helper_or_downgrades(legacy_workflow, marker):
    source, env, key, effects = legacy_workflow
    helper = source / "ops/hosted_job.py"
    helper.write_text(helper.read_text() + "\n" + marker + "\n")
    result = preflight(source, env)
    assert result.returncode != 0
    assert effect_values(Path(env["GITHUB_OUTPUT"])) == {}
    assert not Path(env["TEST_INVOKED"]).exists()


def test_effects_protocol_never_falls_back_on_missing_helper_outputs(legacy_workflow):
    source, env, key, effects = legacy_workflow
    # Deliberately broken effects-v1 helper advertises support but emits no effects.
    helper = source / "ops/hosted_job.py"
    helper.write_text("HOSTED_WORKFLOW_PROTOCOL = 'effects-v1'\n")
    result = preflight(source, env)
    assert result.returncode == 0, result.stderr
    assert effect_values(Path(env["GITHUB_OUTPUT"])) == {"protocol": "effects-v1"}
    helper_env = {**env, "HOSTED_PROTOCOL": "effects-v1", "GITHUB_OUTPUT": str(effects)}
    run = subprocess.run(
        ["bash", "-c", script("Restore, collect, audit and back up privately")],
        cwd=source,
        env=helper_env,
        text=True,
        capture_output=True,
    )
    assert run.returncode == 0, run.stderr
    assert effect_values(effects) == {}
    cleanup = next(
        s for s in workflow_steps() if s.get("name") == "Retain only encrypted recovery copies"
    )
    assert not gate(cleanup, {}, success=True)
    assert all(not gate(s, {}, success=True) for s in publication_steps())


def test_workflow_legacy_authorization_is_not_inferred_from_helper_start_or_raw_mode():
    cleanup = next(
        s for s in workflow_steps() if s.get("name") == "Retain only encrypted recovery copies"
    )
    assert gate(cleanup, {"legacy_started": "true"}, protocol="legacy-ordinary-v0", success=False)
    assert not gate(cleanup, {}, protocol="legacy-ordinary-v0", success=False)
    assert not gate(cleanup, {"legacy_started": "true"}, protocol="effects-v1", success=False)
    assert not gate(cleanup, {"legacy_started": "true"}, protocol="", success=False)


def test_current_helper_declares_supported_nonexecuting_protocol(legacy_workflow):
    source, env, key, effects = legacy_workflow
    (source / "ops/hosted_job.py").write_bytes((ROOT / "ops/hosted_job.py").read_bytes())
    result = preflight(source, env)
    assert result.returncode == 0, result.stderr
    assert effect_values(Path(env["GITHUB_OUTPUT"])) == {"protocol": "effects-v1"}
    assert not Path(env["TEST_INVOKED"]).exists()


def test_archived_helper_provenance_and_empty_control_guard_are_exact():
    from hashlib import sha256

    raw = (ROOT / "tests/compat/hosted_job_v011.py").read_bytes()
    assert (
        sha256(raw).hexdigest()
        == "9999089977439f4ca147de292c000d824808852641c5da1432afb6993b8c60f1"
    )


@pytest.mark.parametrize(
    "effects,valid",
    [
        ({}, False),
        ({"MODE": "ordinary"}, False),
        ({"MODE": "ordinary", "RECOVERY_READY": "true", "PUBLISH_READY": "true"}, True),
        ({"MODE": "apply", "RECOVERY_READY": "true", "PUBLISH_READY": "true"}, True),
        ({"MODE": "apply", "RECOVERY_READY": "true"}, False),
        ({"MODE": "preview", "PREVIEW_READY": "true"}, True),
        ({"MODE": "preview", "PREVIEW_READY": "true", "RECOVERY_READY": "true"}, False),
        (
            {
                "MODE": "ordinary",
                "RECOVERY_READY": "true",
                "PUBLISH_READY": "true",
                "PREVIEW_READY": "true",
            },
            False,
        ),
    ],
)
def test_successful_modern_helper_must_satisfy_explicit_effect_contract(tmp_path, effects, valid):
    env = {
        **os.environ,
        "MODE": "",
        "RECOVERY_READY": "",
        "PUBLISH_READY": "",
        "PREVIEW_READY": "",
        **effects,
    }
    result = subprocess.run(
        ["bash", "-c", script("Check hosted helper effects")],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert (result.returncode == 0) is valid
    check = next(s for s in workflow_steps() if s.get("name") == "Check hosted helper effects")
    assert gate(check, {}, protocol="effects-v1", success=True)
    assert not gate(check, {}, protocol="effects-v1", success=False)
    assert not gate(check, {}, protocol="legacy-ordinary-v0", success=True)


def test_legacy_preflight_accepts_supported_replay_backend_and_capacity_controls(legacy_workflow):
    source, env, key, effects = legacy_workflow
    result = preflight(
        source,
        env
        | {
            "REPARSE_LIMIT": "1",
            "REPARSE_VENDOR": "arista",
            "RECOVERY_STORAGE": "github-draft",
            "VAULT_PROFILE": "large",
        },
    )
    assert result.returncode == 0, result.stderr
    assert effect_values(Path(env["GITHUB_OUTPUT"])) == {"protocol": "legacy-ordinary-v0"}
    assert not Path(env["TEST_INVOKED"]).exists()
