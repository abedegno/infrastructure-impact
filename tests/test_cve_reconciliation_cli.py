"""Reconciliation dispatch must precede ambient vault initialization."""

import pytest
from test_cve_reconciliation_state import source as source_fixture

from infrastructure_impact.cli import main

source = source_fixture


def test_cli_explicit_inputs_no_ambient_vault_and_no_network(monkeypatch, capsys, tmp_path):
    from infrastructure_impact.settings import Paths

    def forbidden(*a, **kw):
        raise AssertionError("ambient vault accessed")

    monkeypatch.setattr(Paths, "from_env", forbidden)
    with pytest.raises(SystemExit) as result:
        main(
            [
                "cve-reconcile",
                "report",
                "--workspace",
                str(tmp_path / "absent"),
                "--baseline",
                str(tmp_path / "base"),
                "--json-output",
                str(tmp_path / "out"),
                "--csv-output",
                str(tmp_path / "csv"),
            ]
        )
    assert result.value.code == 2
    assert "invalid choice" not in capsys.readouterr().err


@pytest.mark.parametrize("mode", ["verify", "scan", "baseline", "report"])
def test_cli_requires_explicit_inputs(mode, capsys):
    with pytest.raises(SystemExit) as result:
        main(["cve-reconcile", mode])
    assert result.value.code == 2
    assert "required" in capsys.readouterr().err


def test_module_cli_dispatch_precedes_ambient_startup(tmp_path):
    import os
    import subprocess
    import sys

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "infrastructure_impact.cli",
            "cve-reconcile",
            "baseline",
            "--database",
            str(tmp_path / "absent"),
            "--config",
            str(tmp_path / "absent-config"),
            "--output",
            str(tmp_path / "output"),
        ],
        capture_output=True,
        text=True,
        env=dict(os.environ, IMPACT_DATA=str(tmp_path / "ambient")),
    )
    assert result.returncode == 2
    assert "NameError" not in result.stderr
    assert not (tmp_path / "ambient").exists()


def test_cli_real_scan_baseline_and_report_are_offline(source, tmp_path, monkeypatch, capsys):
    import json
    from contextlib import closing

    from infrastructure_impact.reconciliation import snapshot
    from infrastructure_impact.storage.repository import connect

    args, _ = source

    def forbidden(*a, **kw):
        raise AssertionError("network used outside explicit verify")

    monkeypatch.setattr(snapshot.http.client, "HTTPSConnection", forbidden)
    from infrastructure_impact.settings import Paths

    monkeypatch.setattr(Paths, "from_env", forbidden)
    main(
        [
            "cve-reconcile",
            "scan",
            "--repository",
            str(args["repository"]),
            "--commit",
            args["commit"],
            "--receipt",
            str(args["receipt_path"]),
            "--workspace",
            str(args["workspace"]),
            "--start-date",
            args["start_date"],
            "--end-date",
            args["end_date"],
            "--record-limit",
            "1",
        ]
    )
    progress = json.loads(capsys.readouterr().out)
    assert progress["attempted"] == 1 and not progress["scan_complete"]
    database = tmp_path / "db.sqlite3"
    config = tmp_path / "config.json"
    base = tmp_path / "baseline.json"
    with closing(connect(database)):
        pass
    config.write_text('{"vendors": []}')
    main(
        [
            "cve-reconcile",
            "baseline",
            "--database",
            str(database),
            "--config",
            str(config),
            "--output",
            str(base),
        ]
    )
    capsys.readouterr()
    out = tmp_path / "report.json"
    sheet = tmp_path / "report.csv"
    main(
        [
            "cve-reconcile",
            "report",
            "--workspace",
            str(args["workspace"]),
            "--baseline",
            str(base),
            "--json-output",
            str(out),
            "--csv-output",
            str(sheet),
        ]
    )
    returned = json.loads(capsys.readouterr().out)
    assert returned["report_id"] == json.loads(out.read_text())["report_id"]
    assert returned["coverage_complete"] is None and sheet.exists()


def test_fresh_report_import_never_resolves_ambient_paths():
    import subprocess
    import sys

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """from infrastructure_impact.settings import Paths
def forbidden():
    raise AssertionError("ambient paths resolved")
Paths.from_env = forbidden
from infrastructure_impact.reconciliation.report import validate_report, ReportError
try:
    validate_report({})
except ReportError:
    pass
""",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
