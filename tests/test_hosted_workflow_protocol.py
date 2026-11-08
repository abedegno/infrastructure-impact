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
        {"ACQUISITION_CACHE": "true"},
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


@pytest.mark.parametrize("downstream", ["push", "deploy"])
def test_completed_target_import_does_not_claim_cross_system_rollback(downstream):
    # Both rejection points follow local recovery promotion. Existing workflow
    # gates retain that verified recovery while withholding a failed deployment.
    effects = {"mode": "apply", "recovery_ready": "true", "publish_ready": "true"}
    cleanup = next(
        s for s in workflow_steps() if s.get("name") == "Retain only encrypted recovery copies"
    )
    # Execute a rejected test-local downstream action. Neither action has any
    # recovery rollback authorization; its failed exit only changes later gates.
    rejected = subprocess.run(
        [sys.executable, "-c", "import sys; sys.exit(1)", downstream],
        capture_output=True,
    )
    assert rejected.returncode == 1
    assert gate(cleanup, effects, success=False, hosted_outcome="success")
    assert all(
        not gate(s, effects, success=rejected.returncode == 0, hosted_outcome="success")
        for s in publication_steps()
    )


TARGET_IMPORT = "campus-switching-public-gap-2026-11-07-v1"


def test_manual_acquisition_cache_defaults_false_and_mirrors():
    text = (ROOT / ".github/workflows/collect.yaml").read_text()
    assert re.search(r"      acquisition_cache:\n(?:        .*\n)*        default: false", text)
    assert (
        text.count(
            "ACQUISITION_CACHE: ${{ github.event_name == 'workflow_dispatch' && inputs.acquisition_cache == true && 'true' || 'false' }}"
        )
        == 2
    )
    assert text == (ROOT / "deploy/github-public-service.yaml").read_text()


@pytest.mark.parametrize(
    "controls",
    [
        {},
        {"MAINTENANCE_PROFILE": TARGET_IMPORT, "MAINTENANCE_MODE": "preview"},
        {"MAINTENANCE_PROFILE": PROFILE, "MAINTENANCE_MODE": "apply"},
        {"MAINTENANCE_PROFILE": "target-import-unknown", "MAINTENANCE_MODE": "apply"},
    ],
)
def test_acquisition_request_rejects_ineligible_modes_before_invocation(legacy_workflow, controls):
    source, env, key, effects = legacy_workflow
    (source / "ops/hosted_job.py").write_bytes((ROOT / "ops/hosted_job.py").read_bytes())
    result = preflight(source, env | {"ACQUISITION_CACHE": "true"} | controls)
    assert result.returncode != 0
    assert not Path(env["TEST_INVOKED"]).exists()
    assert effect_values(Path(env["GITHUB_OUTPUT"])) == {}


@pytest.mark.parametrize("capability", [False, True])
def test_acquisition_preflight_requires_pinned_helper_flag(legacy_workflow, capability):
    source, env, key, effects = legacy_workflow
    (source / "ops/hosted_job.py").write_text(
        "HOSTED_WORKFLOW_PROTOCOL = 'effects-v1'\n"
        + f"print({'--acquisition-cache' if capability else '--old-flag'!r})\n"
    )
    result = preflight(
        source,
        env
        | {
            "ACQUISITION_CACHE": "true",
            "MAINTENANCE_PROFILE": TARGET_IMPORT,
            "MAINTENANCE_MODE": "apply",
            "MAINTENANCE_PREVIEW_FINGERPRINT": "a" * 64,
        },
    )
    assert (result.returncode == 0) is capability, result.stderr
    assert not Path(env["TEST_INVOKED"]).exists()


@pytest.mark.parametrize("value", ["", "false", "TRUE", "garbage", "true"])
def test_acquisition_effect_only_retains_failed_apply_and_never_publishes(value):
    cleanup = next(
        s for s in workflow_steps() if s.get("name") == "Retain only encrypted recovery copies"
    )
    for mode in ("apply", "ordinary", "preview", ""):
        effects = {"mode": mode, "acquisition_ready": value}
        assert gate(cleanup, effects, success=False) is (mode == "apply" and value == "true")
        assert all(not gate(s, effects, success=False) for s in publication_steps())
        assert all(not gate(s, effects, success=True) for s in publication_steps())
        artifact = next(
            s for s in workflow_steps() if "actions/upload-artifact@" in s.get("uses", "")
        )
        assert not gate(artifact, effects, success=False)


@pytest.fixture
def retention_tree(recovery, tmp_path):
    import shutil

    state, database, key, effects = recovery
    workspace = tmp_path / "workspace"
    service = workspace / "service"
    service.mkdir(parents=True)
    shutil.copytree(state, service / "state")
    acquisitions = service / "acquisitions"
    acquisitions.mkdir()
    for fingerprint in ("a" * 64, "b" * 64):
        shutil.copytree(state, acquisitions / fingerprint)
    (workspace / "source").symlink_to(ROOT, target_is_directory=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "git-log"
    git = bin_dir / "git"
    git.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{log}"\n')
    git.chmod(0o755)
    env = {
        **os.environ,
        "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
        "PRIVATE_STATE": str(service / "state"),
        "IMPACT_STATE_KEY": key.decode(),
        "GITHUB_WORKSPACE": str(workspace),
    }
    return service, acquisitions, env, log


def retain(retention_tree):
    service, acquisitions, env, log = retention_tree
    return subprocess.run(
        ["bash", "-c", script("Retain only encrypted recovery copies")],
        cwd=service,
        env=env,
        capture_output=True,
        text=True,
    )


def test_retention_validates_and_stages_separate_encrypted_acquisition_tree(retention_tree):
    service, acquisitions, env, log = retention_tree
    result = retain(retention_tree)
    assert result.returncode == 0, result.stderr
    assert "add state acquisitions" in log.read_text()


@pytest.mark.parametrize(
    "bad",
    [
        "root-link",
        "profile-link",
        "unknown-profile",
        "root-file",
        "plaintext",
        "leaf-link",
        "nested",
        "missing-manifest",
        "corrupt",
        "accepted-plaintext",
    ],
)
def test_retention_rejects_unmanaged_or_invalid_acquisition_before_any_staging(retention_tree, bad):
    import shutil

    service, acquisitions, env, log = retention_tree
    profile = acquisitions / ("b" * 64)
    if bad == "root-link":
        moved = service / "elsewhere"
        acquisitions.rename(moved)
        acquisitions.symlink_to(moved, target_is_directory=True)
    elif bad == "profile-link":
        shutil.rmtree(profile)
        profile.symlink_to(acquisitions / ("a" * 64), target_is_directory=True)
    elif bad == "unknown-profile":
        (acquisitions / "unknown").mkdir()
    elif bad == "root-file":
        (acquisitions / "raw.sqlite3").write_bytes(b"synthetic plaintext")
    elif bad == "plaintext":
        (profile / "cache.sqlite3").write_bytes(b"synthetic plaintext")
    elif bad == "leaf-link":
        (profile / "extra").symlink_to(profile / "current.json")
    elif bad == "nested":
        (profile / "unexpected").mkdir()
    elif bad == "missing-manifest":
        (profile / "current.json").unlink()
    elif bad == "corrupt":
        next(profile.glob("*.fernet")).write_bytes(b"unauthenticated")
    else:
        (service / "state/raw.sqlite3").write_bytes(b"synthetic plaintext")
    result = retain(retention_tree)
    assert result.returncode != 0
    assert not log.exists() or not any(
        line.startswith("add ") for line in log.read_text().splitlines()
    )


@pytest.mark.parametrize("cache", ["false", "true", "invalid"])
def test_workflow_forwards_acquisition_flag_only_when_explicitly_enabled(tmp_path, cache):
    import json

    shim = tmp_path / "uv"
    shim.write_text(f"#!{sys.executable}\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n")
    shim.chmod(0o755)
    env = {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "ACQUISITION_CACHE": cache,
        "HOSTED_PROTOCOL": "effects-v1",
        "VAULT_PROFILE": "standard",
        "RECOVERY_STORAGE": "git",
        "REPARSE_LIMIT": "0",
        "REPARSE_VENDOR": "",
        "MAINTENANCE_PROFILE": TARGET_IMPORT,
        "MAINTENANCE_MODE": "apply",
        "MAINTENANCE_PREVIEW_FINGERPRINT": "a" * 64,
        "PRIVATE_STATE": str(tmp_path / "state"),
        "PUBLIC_OUTPUT": str(tmp_path / "public"),
        "BASE_PATH": "/example/",
    }
    result = subprocess.run(
        ["bash", "-c", script("Restore, collect, audit and back up privately")],
        env=env,
        capture_output=True,
        text=True,
    )
    if cache == "invalid":
        assert result.returncode != 0
        assert "[" not in result.stdout  # The helper argv shim was never invoked.
    else:
        assert result.returncode == 0, result.stderr
        assert ("--acquisition-cache" in json.loads(result.stdout)) is (cache == "true")


def test_acquisition_effect_cannot_satisfy_successful_apply_contract(tmp_path):
    result = subprocess.run(
        ["bash", "-c", script("Check hosted helper effects")],
        env={
            **os.environ,
            "MODE": "apply",
            "ACQUISITION_READY": "true",
            "RECOVERY_READY": "",
            "PUBLISH_READY": "",
            "PREVIEW_READY": "",
        },
        cwd=tmp_path,
        capture_output=True,
    )
    assert result.returncode != 0


def test_protocol_preflight_uses_installed_interpreter():
    # Profile resolution and capability --help need the locked source dependencies.
    assert script("Check hosted helper protocol").startswith(
        "set -euo pipefail\nuv run --no-dev python - <<'PY'\n"
    )


def test_current_helper_cache_preflight_needs_no_key_or_recovery(legacy_workflow):
    source, env, key, effects = legacy_workflow
    (source / "ops/hosted_job.py").write_bytes((ROOT / "ops/hosted_job.py").read_bytes())
    result = preflight(
        source,
        env
        | {
            "ACQUISITION_CACHE": "true",
            "MAINTENANCE_PROFILE": TARGET_IMPORT,
            "MAINTENANCE_MODE": "apply",
            "MAINTENANCE_PREVIEW_FINGERPRINT": "a" * 64,
        },
    )
    assert result.returncode == 0, result.stderr
    assert effect_values(Path(env["GITHUB_OUTPUT"])) == {"protocol": "effects-v1"}
    assert not Path(env["TEST_INVOKED"]).exists()


def test_acquisition_retention_requires_existing_accepted_manifest(retention_tree):
    service, acquisitions, env, log = retention_tree
    (service / "state/current.json").unlink()
    result = retain(retention_tree)
    assert result.returncode != 0
    assert not log.exists()
