"""Keep the standalone reader and its native report producer compatible in CI."""

import json
import os
import subprocess
import sys
from pathlib import Path

from infrastructure_impact.application import release_signals as signals

ROOT = Path(__file__).resolve().parents[1]


def test_reader_accepts_native_report_with_corrective_targets_and_conflicting_dates():
    observed = "2026-11-25T12:00:00Z"
    dataset = signals.new_dataset(observed)

    def fact(kind, release, day, related=None):
        return {
            "kind": kind,
            "vendor": "arista",
            "train": "4.33",
            "release": release,
            "related_release": related,
            "date": day,
            "platforms": [],
            "statement": "Synthetic publisher action for validation",
            "bug_ids": [],
            "source_locator": f"Synthetic row / {kind} / {release}",
        }

    signals.add_document(
        dataset,
        b"Synthetic source capture one",
        "https://www.arista.com/en/support/release-notes",
        observed,
        [
            fact("release", "4.33.11M", "2026-10-15"),
            fact("release", "4.33.11.2M", "2026-11-03"),
            fact("corrective_respin", "4.33.12M", "2026-11-20", "4.33.11M"),
            fact("withdrawn", "4.33.11M", "2026-11-10"),
        ],
    )
    signals.add_document(
        dataset,
        b"Synthetic source capture two with a conflicting action date",
        "https://www.arista.com/en/support/advisories-notices/fieldnotice",
        observed,
        [fact("withdrawn", "4.33.11M", "2026-10-14")],
    )
    upgrades = {
        "rows": [
            {
                "vendor": "arista",
                "train": "4.33",
                "year": 2026,
                "scenario": "publisher_first_fixed",
                "policy": "all_affected",
                "events": [
                    {"date": "2026-10-20", "target": target, "claim_ids": ["a" * 64]}
                    for target in ("4.33.11M", "4.33.12M")
                ],
            }
        ]
    }
    report = signals.build_report(dataset, start="2024-01-01", end="2026-11-25", upgrades=upgrades)
    script = """
const fs = require('fs'), vm = require('vm'), context = {window:{}};
vm.runInNewContext(fs.readFileSync('web/lossless-json.js', 'utf8'), context);
const reader = require('./web/release-signals.js');
const report = reader.parseReport(fs.readFileSync(0, 'utf8'), context.window.InfrastructureJSON.parseStrict);
if (!reader.render(report).includes('Independent human review pending')) throw Error('Missing caveat');
"""
    result = subprocess.run(
        ["node", "-e", script], input=json.dumps(report), text=True, capture_output=True, cwd=ROOT
    )
    assert result.returncode == 0, result.stderr


def test_standalone_reader_regressions_run_in_python_ci():
    result = subprocess.run(
        ["node", "--test", "tests/test_release_signals_ui.js"],
        cwd=ROOT,
        env=dict(os.environ, PYTHON=sys.executable),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
