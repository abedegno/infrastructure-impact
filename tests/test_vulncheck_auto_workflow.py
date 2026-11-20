"""Hosted VulnCheck collection stays optional, private, and separately scoped."""

import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
COLLECT = ROOT / ".github/workflows/collect.yaml"
MANUAL = ROOT / ".github/workflows/vulncheck-collect.yaml"


def blocks(path):
    return re.split(r"^      - ", path.read_text(), flags=re.M)[1:]


def step(path, name):
    matches = [block for block in blocks(path) if block.startswith(f"name: {name}\n")]
    assert len(matches) == 1, f"missing step: {name}"
    return matches[0]


def scalar(block, key):
    return re.search(rf"^\s*{re.escape(key)}: (.+)$", block, re.M).group(1)


def enabled(expression, *, switch="true", ref="refs/heads/main", success=True, **inputs):
    expression = expression.removeprefix("${{").removesuffix("}}").strip()
    expression = expression.replace("&&", " and ").replace("||", " or ")
    return bool(
        eval(
            expression,
            {"__builtins__": {}},
            {
                "success": lambda: success,
                "vars": SimpleNamespace(IMPACT_VULNCHECK_COLLECTION=switch),
                "github": SimpleNamespace(ref=ref),
                "inputs": SimpleNamespace(
                    maintenance_profile="",
                    maintenance_mode="",
                    maintenance_preview_fingerprint="",
                    **inputs,
                ),
            },
        )
    )


@pytest.mark.parametrize(
    "switch,ref,success,want",
    [
        ("true", "refs/heads/main", True, True),
        ("false", "refs/heads/main", True, False),
        ("", "refs/heads/main", True, False),
        ("TRUE", "refs/heads/main", True, False),
        ("true", "refs/heads/feature", True, False),
        ("true", "refs/pull/1/merge", True, False),
        ("true", "refs/heads/main", False, False),
    ],
)
def test_daily_gate_requires_enabled_trusted_ordinary_run(switch, ref, success, want):
    block = step(COLLECT, "Collect private VulnCheck evidence")
    assert enabled(scalar(block, "if"), switch=switch, ref=ref, success=success) is want


@pytest.mark.parametrize(
    "field,value",
    [
        ("maintenance_profile", "synthetic-profile"),
        ("maintenance_mode", "preview"),
        ("maintenance_mode", "apply"),
        ("maintenance_preview_fingerprint", "synthetic-fingerprint"),
    ],
)
def test_daily_collection_skips_maintenance(field, value):
    expression = scalar(step(COLLECT, "Collect private VulnCheck evidence"), "if")
    expression = expression.replace(f"inputs.{field}", repr(value))
    assert not enabled(expression)


def test_daily_failure_does_not_block_primary_collector_and_schedule_is_unchanged():
    text = COLLECT.read_text()
    block = step(COLLECT, "Collect private VulnCheck evidence")
    assert scalar(block, "continue-on-error") == "true"
    assert text.index("name: Install locked source") < text.index(block)
    assert text.index(block) < text.index("name: Restore, collect, audit and back up privately")
    assert re.findall(r"cron: (.+)", text) == ["'43 12 * * *'"]


def test_credentials_and_uploads_are_scoped_to_private_helper_receipt():
    for path in (COLLECT, MANUAL):
        block = step(path, "Collect private VulnCheck evidence")
        assert scalar(block, "working-directory") == "source"
        assert (
            'uv run python -m ops.vulncheck_job --checkout "$GITHUB_WORKSPACE/service" --receipt "$RUNNER_TEMP/vulncheck-status.json"'
            in block
        )
        for key, value in {
            "GH_TOKEN": "${{ github.token }}",
            "IMPACT_SOURCE_COMMIT": "${{ vars.IMPACT_SOURCE_COMMIT }}",
            "IMPACT_STATE_KEY": "${{ secrets.IMPACT_STATE_KEY }}",
            "VULNCHECK_API_TOKEN": "${{ secrets.VULNCHECK_API_TOKEN }}",
        }.items():
            assert scalar(block, key) == value
        assert path.read_text().count("secrets.VULNCHECK_API_TOKEN") == 1
        upload = step(path, "Upload private VulnCheck status")
        assert "always()" in scalar(upload, "if")
        assert scalar(upload, "path") == "${{ runner.temp }}/vulncheck-status.json"
        assert (
            scalar(upload, "uses")
            == "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2"
        )
        for other in blocks(path):
            if other != block:
                assert "secrets.VULNCHECK_API_TOKEN" not in other


def test_manual_workflow_has_only_dispatch_contents_permission_and_shared_lock():
    text = MANUAL.read_text()
    assert "on:\n  workflow_dispatch:\n" in text
    assert "schedule:" not in text
    assert "permissions:\n  contents: write\nconcurrency:" in text
    assert "group: service-publication\n  cancel-in-progress: false" in text
    gate = re.search(r"^    if: (.+)$", text, re.M).group(1)
    assert enabled(gate)
    assert not enabled(gate, switch="false")
    assert not enabled(gate, ref="refs/heads/feature")
    assert "pages:" not in text and "id-token:" not in text
    assert "ref: publication-state\n          path: service" in text
    assert (
        "ref: ${{ vars.IMPACT_SOURCE_COMMIT }}\n          path: source\n          persist-credentials: false"
        in text
    )
    assert "python-version: '3.13'" in text
    assert "python -m pip install uv==0.11.21" in text
    assert "uv sync --frozen --no-dev --group hosted" in text
    assert len([b for b in blocks(MANUAL) if "actions/upload-artifact@" in b]) == 1
    assert set(re.findall(r"uses: (\S+)", text)) <= set(
        re.findall(r"uses: (\S+)", COLLECT.read_text())
    )


@pytest.mark.parametrize(
    "pin,want", [("a" * 40, 0), ("main", 1), ("a" * 39, 1), ("a" * 40 + "; true", 1)]
)
def test_manual_source_pin_check_rejects_unreviewed_refs(pin, want):
    block = step(MANUAL, "Check pinned source")
    raw = block.split("        run: |\n", 1)[1]
    script = "\n".join(line[10:] for line in raw.splitlines())
    result = subprocess.run(["bash", "-c", script], env={"SOURCE_COMMIT": pin}, capture_output=True)
    assert result.returncode == want
