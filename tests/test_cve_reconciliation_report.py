"""Synthetic report contract and filesystem publication regressions."""

import csv
import hashlib
import importlib
import json
from contextlib import closing

import pytest
from test_cve_reconciliation_baseline import PUBLISHER, add_revision
from test_cve_reconciliation_state import source as source_fixture

from infrastructure_impact.reconciliation import baseline, scan, state
from infrastructure_impact.storage.repository import connect

source = source_fixture


def api():
    return importlib.import_module("infrastructure_impact.reconciliation.report")


def baseline_file(tmp_path, revisions=()):
    database = tmp_path / "vault.sqlite3"
    config = tmp_path / "config.json"
    config.write_text('{"vendors": []}')
    with closing(connect(database)) as db:
        for revision in revisions:
            add_revision(db, **revision)
        db.commit()
    output = tmp_path / "baseline.json"
    baseline.export_baseline(database=database, config_path=config, output=output)
    return output


def build(source, tmp_path, limit=5000, revisions=()):
    args, _ = source
    scan.scan_snapshot(**args, record_limit=limit)
    base = baseline_file(tmp_path, revisions)
    return api().build_report(workspace=args["workspace"], baseline_path=base), args, base


def rehash(report):
    report["report_id"] = hashlib.sha256(
        json.dumps(
            {k: v for k, v in report.items() if k != "report_id"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def test_report_identity_membership_totals_and_scope_are_strict(source, tmp_path):
    report, args, base = build(source, tmp_path, revisions=[dict(cve="CVE-2026-1234")])
    assert report["counts"]["unique_cves"] == 3
    assert report["counts"]["findings"] == 3
    assert report["scan"]["coverage_complete"] is None
    assert report["scan"]["scan_complete"] is True
    first = report["findings"][0]
    assert first["baseline"]["cve_family"] is True
    assert first["references"][0]["collection_state"] == "missing_reference"
    api().validate_report(report)
    assert api().build_report(workspace=args["workspace"], baseline_path=base) == report
    report["counts"]["unique_cves"] = 4
    rehash(report)
    with pytest.raises(ValueError):
        api().validate_report(report)


@pytest.mark.parametrize("limit", [0, 1, 5000])
def test_partial_empty_and_unknown_dates_remain_visible_in_both_exports(source, tmp_path, limit):
    report, args, base = build(source, tmp_path, limit)
    out = tmp_path / "out.json"
    sheet = tmp_path / "out.csv"
    api().write_report(
        report, json_path=out, csv_path=sheet, workspace=args["workspace"], baseline_path=base
    )
    rows = list(csv.DictReader(sheet.open()))
    assert rows and all(row["report_id"] == report["report_id"] for row in rows)
    assert rows[0]["scan_complete"] == str(limit == 5000).lower()
    assert rows[0]["coverage_complete"] == "null"
    assert rows[0]["row_type"] == ("summary" if limit == 0 else "finding_reference")
    assert json.loads(out.read_text()) == report


@pytest.mark.parametrize("alias", ["same", "baseline", "state", "capture", "sidecar", "existing"])
def test_all_output_aliases_and_invalid_state_fail_safely(source, tmp_path, alias):
    report, args, base = build(source, tmp_path)
    out = tmp_path / "out.json"
    sheet = tmp_path / "out.csv"
    if alias == "same":
        sheet = out
    if alias == "baseline":
        sheet = base
    if alias == "state":
        sheet = args["workspace"] / "state.sqlite3"
    if alias == "capture":
        sheet = next((args["workspace"] / "captures").iterdir())
    if alias == "sidecar":
        sheet = args["workspace"] / "state.sqlite3-wal"
    if alias == "existing":
        sheet.write_text("old")
    before = {p: p.read_bytes() for p in [out, sheet] if p.exists()}
    with pytest.raises(ValueError):
        api().write_report(
            report, json_path=out, csv_path=sheet, workspace=args["workspace"], baseline_path=base
        )
    assert all(p.read_bytes() == v for p, v in before.items())
    assert not out.exists()


def test_writer_lock_stale_state_and_pair_failure(source, tmp_path, monkeypatch):
    report, args, base = build(source, tmp_path, 1)
    kwargs = dict(
        json_path=tmp_path / "out.json",
        csv_path=tmp_path / "out.csv",
        workspace=args["workspace"],
        baseline_path=base,
    )
    with (
        state._lock(args["workspace"], write=True),
        pytest.raises(ValueError, match="workspace_locked"),
    ):
        api().write_report(report, **kwargs)
    original = api().os.link

    def fail(src, dst, *a, **kw):
        if dst == kwargs["json_path"]:
            raise OSError("interruption")
        return original(src, dst, *a, **kw)

    monkeypatch.setattr(api().os, "link", fail)
    with pytest.raises(ValueError, match="report_write_failed"):
        api().write_report(report, **kwargs)
    assert not kwargs["csv_path"].exists() and not kwargs["json_path"].exists()
    scan.scan_snapshot(**args)
    with pytest.raises(ValueError, match="stale_report"):
        api().write_report(report, **kwargs)


def changed_source(source, monkeypatch, mutate):
    from test_cve_reconciliation_snapshot import git, official

    from infrastructure_impact.reconciliation import snapshot

    args, bodies = source
    body = json.loads(bodies[0])
    mutate(body)
    path = args["repository"] / "cves/2026/1xxx/CVE-2026-1234.json"
    path.write_text(json.dumps(body))
    git(args["repository"], "add", ".")
    git(args["repository"], "commit", "-qm", "synthetic changed")
    commit, _, _, _ = official(monkeypatch, snapshot, args["repository"])
    args = args | dict(
        commit=commit, receipt_path=args["receipt_path"].with_name("changed-receipt.json")
    )
    snapshot.verify_snapshot(args["repository"], commit, args["receipt_path"])
    return args, bodies


def test_unrelated_vendor_and_reference_gaps_are_orthogonal(source, tmp_path, monkeypatch):
    def mutate(body):
        body["containers"]["cna"]["references"] = [{"url": PUBLISHER}]

    source = changed_source(source, monkeypatch, mutate)
    report, _, _ = build(
        source,
        tmp_path,
        revisions=[
            dict(
                cve="CVE-2026-1234",
                vendor="arista",
                product="EOS",
                url="https://www.arista.com/en/support/advisories-notices/security-advisory/12345-security-advisory-9999",
            )
        ],
    )
    first = report["findings"][0]
    assert first["baseline"]["cve_anywhere"] and not first["baseline"]["cve_vendor"]
    assert not first["baseline"]["cve_family"]
    assert first["references"][0]["collection_state"] == "unobserved"
    assert first["references"][0]["vendor_publication_dates"] == []


def test_registry_dates_do_not_become_unfetched_vendor_dates(source, tmp_path, monkeypatch):
    registry = "https://cveawg.mitre.org/api/cve/CVE-2026-1234"

    def mutate(body):
        body["containers"]["cna"]["references"] = [{"url": PUBLISHER}, {"url": registry}]

    source = changed_source(source, monkeypatch, mutate)
    report, _, _ = build(source, tmp_path, revisions=[dict(cve="CVE-2026-1234", url=registry)])
    first = report["findings"][0]
    assert first["baseline"]["cve_family"] is True
    publisher, cve = first["references"]
    assert publisher["collection_state"] == "unobserved"
    assert publisher["vendor_publication_dates"] == publisher["registry_publication_dates"] == []
    assert cve["collection_state"] == "normalized"
    assert cve["vendor_publication_dates"] == []
    assert cve["registry_publication_dates"][0]["published_at"] == "2026-01-01"


def test_history_does_not_establish_current_presence(source, tmp_path):
    report, _, _ = build(
        source, tmp_path, revisions=[dict(cve="CVE-2026-1234"), dict(cve="CVE-2026-9876")]
    )
    presence = report["findings"][0]["baseline"]
    assert presence["cve_anywhere"] is False
    assert presence["historical_revision_ids"] == [1]


def test_duplicates_conflicts_and_date_kinds_are_not_collapsed(source, tmp_path, monkeypatch):
    def mutate(body):
        import copy

        body["cveMetadata"]["datePublished"] = "2026-02-03broken"
        other = copy.deepcopy(body["containers"]["cna"])
        other["affected"][0]["versions"][0]["status"] = "unaffected"
        body["containers"]["adp"] = [other]

    source = changed_source(source, monkeypatch, mutate)
    report, _, _ = build(source, tmp_path)
    assert report["counts"]["findings"] == 4 and report["counts"]["unique_cves"] == 3
    assert report["findings"][0]["statuses"] == ["unknown"]
    assert report["findings"][1]["statuses"] == ["unaffected"]
    assert report["findings"][0]["registry_publication_day"] is None
    assert report["findings"][0]["date_window_state"] == "unknown"
    assert report["counts"]["dimensions"]["publication_year"] == [
        {"value": "2026", "unique_cves": 2},
        {"value": "unknown", "unique_cves": 1},
    ]


def test_csv_formula_text_roundtrips_to_literal_json(source, tmp_path, monkeypatch):
    def mutate(body):
        body["containers"]["cna"]["references"] = [{"url": '=HYPERLINK("example")'}]

    source = changed_source(source, monkeypatch, mutate)
    report, args, base = build(source, tmp_path)
    out = tmp_path / "out.json"
    sheet = tmp_path / "out.csv"
    api().write_report(
        report, json_path=out, csv_path=sheet, workspace=args["workspace"], baseline_path=base
    )
    assert list(csv.DictReader(sheet.open()))[0]["reference_url"] == '\'=HYPERLINK("example")'
    assert (
        json.loads(out.read_text())["findings"][0]["references"][0]["url"]
        == '=HYPERLINK("example")'
    )


def test_finding_identity_survives_baseline_change(source, tmp_path):
    report, args, _ = build(source, tmp_path)
    another = tmp_path / "another"
    another.mkdir()
    base = baseline_file(another, [dict(cve="CVE-2026-1234")])
    later = api().build_report(workspace=args["workspace"], baseline_path=base)
    assert later["report_id"] != report["report_id"]
    assert later["findings"][0]["finding_id"] == report["findings"][0]["finding_id"]


@pytest.mark.parametrize(
    "mutation", ["finding_id", "container", "presence", "unknown_match", "duplicate", "additional"]
)
def test_rehashed_semantic_mutations_rejected(source, tmp_path, mutation):
    import copy

    report, _, _ = build(source, tmp_path)
    bad = copy.deepcopy(report)
    finding = bad["findings"][0]
    if mutation == "finding_id":
        finding["finding_id"] = "a" * 64
    if mutation == "container":
        finding["container_locator"] = "/containers/adp/999"
    if mutation == "presence":
        finding["baseline"]["cve_family"] = True
    if mutation == "unknown_match":
        finding["references"][0]["evidence_ids"] = [99]
    if mutation == "duplicate":
        bad["findings"].append(copy.deepcopy(finding))
    if mutation == "additional":
        bad["baseline"]["private_path"] = "/private/secret"
    if mutation not in ["finding_id", "duplicate", "additional"]:
        finding["finding_id"] = api()._finding_identity(finding)
    rehash(bad)
    with pytest.raises(ValueError, match="invalid_report"):
        api().validate_report(bad)


def test_inside_workspace_quota_and_existing_pair_refusal(source, tmp_path, monkeypatch):
    report, args, base = build(source, tmp_path)
    folder = args["workspace"] / "reports"
    folder.mkdir()
    kwargs = dict(
        json_path=folder / "out.json",
        csv_path=folder / "out.csv",
        workspace=args["workspace"],
        baseline_path=base,
    )
    with monkeypatch.context() as patch:
        patch.setattr(state, "MAX_WORKSPACE_BYTES", report["scan"]["retained_bytes"] + 100)
        with pytest.raises(ValueError, match="workspace_limit"):
            api().write_report(report, **kwargs)
    assert not list(folder.iterdir())
    api().write_report(report, **kwargs)
    before = {p: p.read_bytes() for p in folder.iterdir()}
    with pytest.raises(ValueError, match="unsafe_output_path"):
        api().write_report(report, **kwargs)
    assert all(p.read_bytes() == raw for p, raw in before.items())


def test_abrupt_exit_leaves_detectable_csv_orphan(source, tmp_path):
    import subprocess
    import sys

    report, args, base = build(source, tmp_path)
    input_report = tmp_path / "input-report.json"
    input_report.write_text(json.dumps(report))
    out = tmp_path / "out.json"
    sheet = tmp_path / "out.csv"
    code = """import json,os,sys
from pathlib import Path
from infrastructure_impact.reconciliation import report
original=report.os.link
def crash(src,dst):
    if str(dst)==sys.argv[4]: os._exit(77)
    original(src,dst)
report.os.link=crash
report.write_report(json.loads(Path(sys.argv[1]).read_text()),workspace=Path(sys.argv[2]),baseline_path=Path(sys.argv[3]),json_path=Path(sys.argv[4]),csv_path=Path(sys.argv[5]))
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            code,
            str(input_report),
            str(args["workspace"]),
            str(base),
            str(out),
            str(sheet),
        ]
    )
    assert result.returncode == 77 and not out.exists() and sheet.exists()
    assert list(csv.DictReader(sheet.open()))[0]["report_id"] == report["report_id"]
    with pytest.raises(ValueError, match="unsafe_output_path"):
        api().write_report(
            report, json_path=out, csv_path=sheet, workspace=args["workspace"], baseline_path=base
        )


@pytest.mark.parametrize("mutation", ["ordinal", "source_path", "limits", "limitations", "status"])
def test_more_rehashed_semantic_mutations(source, tmp_path, mutation):
    report, _, _ = build(source, tmp_path)
    finding = report["findings"][0]
    if mutation == "ordinal":
        finding["ordinal"] = 2
    if mutation == "source_path":
        finding["source_locator"] = "../CVE-2026-1234.json"
        finding["source_url"] = (
            "https://raw.githubusercontent.com/CVEProject/cvelistV5/"
            + report["snapshot"]["commit"]
            + "/"
            + finding["source_locator"]
        )
    if mutation == "limits":
        report["snapshot"]["inventory_entries"] = 2000001
    if mutation == "limitations":
        report["limitations"] = []
    if mutation == "status":
        finding["statuses"] = ["affected"]
    finding["finding_id"] = api()._finding_identity(finding)
    rehash(report)
    with pytest.raises(ValueError, match="invalid_report"):
        api().validate_report(report)


def test_collection_states_and_exact_routes_remain_distinct(source, tmp_path, monkeypatch):
    from infrastructure_impact.storage.repository import evidence

    root = "https://csaf.arubanetworking.hpe.com/"
    names = ["retained.json", "pending.json", "error.json", "absent.json", "unknown.json"]

    def mutate(body):
        body["containers"]["cna"]["references"] = [{"url": root + name} for name in names]

    source = changed_source(source, monkeypatch, mutate)
    args, _ = source
    scan.scan_snapshot(**args)
    database = tmp_path / "vault.sqlite3"
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"vendors": [], "pinned": [{"vendor": "aruba", "url": root + "absent.json"}]})
    )
    with closing(connect(database)) as db:
        evidence(db, b"synthetic", root + "retained.json")
        db.execute(
            "INSERT INTO archive_sources(vendor,source_url,kind,started_at) VALUES(?,?,?,?)",
            ("aruba", root + "index.txt", "index", "2026-01-01"),
        )
        db.execute(
            "INSERT INTO archive_items(source_id,kind,url,state,discovered_at) VALUES(1,?,?,?,?)",
            ("document", root + "pending.json", "pending", "2026-01-01"),
        )
        db.execute(
            "INSERT INTO collection_runs(vendor,source_url,checked_at,outcome,error_code,details) VALUES(?,?,?,?,?,?)",
            ("aruba", root + "error.json", "2026-01-01", "error", "collection_error", ""),
        )
        db.commit()
    base = tmp_path / "baseline.json"
    baseline.export_baseline(database=database, config_path=config, output=base)
    report = api().build_report(workspace=args["workspace"], baseline_path=base)
    refs = report["findings"][0]["references"]
    assert [r["collection_state"] for r in refs] == [
        "retained_unparsed",
        "pending",
        "error",
        "configured_unobserved",
        "unobserved",
    ]
    assert (
        refs[0]["evidence_ids"] == [1]
        and refs[1]["queue_ids"] == [1]
        and refs[2]["check_ids"] == [1]
    )


@pytest.mark.parametrize("binding", ["queue", "observation"])
def test_retention_uses_persisted_requested_to_evidence_binding(
    source, tmp_path, monkeypatch, binding
):
    from infrastructure_impact.storage.repository import evidence

    root = "https://csaf.arubanetworking.hpe.com/"

    def mutate(body):
        body["containers"]["cna"]["references"] = [{"url": root + "requested.json"}]

    source = changed_source(source, monkeypatch, mutate)
    args, _ = source
    scan.scan_snapshot(**args)
    database = tmp_path / "vault.sqlite3"
    config = tmp_path / "config.json"
    base = tmp_path / "baseline.json"
    config.write_text('{"vendors": []}')
    with closing(connect(database)) as db:
        retained = evidence(db, b"authored retained source", root + "actual.json")["id"]
        if binding == "queue":
            db.execute(
                "INSERT INTO archive_sources(vendor,source_url,kind,started_at) VALUES(?,?,?,?)",
                ("aruba", root + "index.txt", "index", "2026-01-01"),
            )
            db.execute(
                "INSERT INTO archive_items(source_id,kind,url,state,evidence_id,discovered_at) VALUES(1,?,?,?,?,?)",
                ("document", root + "requested.json", "done", retained, "2026-01-01"),
            )
        else:
            db.execute(
                "INSERT INTO source_observations(vendor,source_url,checked_at,evidence_id,http_status) VALUES(?,?,?,?,?)",
                ("aruba", root + "requested.json", "2026-01-01", retained, 200),
            )
        db.commit()
    baseline.export_baseline(database=database, config_path=config, output=base)
    report = api().build_report(workspace=args["workspace"], baseline_path=base)
    ref = report["findings"][0]["references"][0]
    assert ref["collection_state"] == "retained_unparsed"
    assert ref["evidence_ids"] == [1]
    assert ref["observation_ids"] == ([1] if binding == "observation" else [])


@pytest.mark.parametrize("alias", ["symlink", "ancestor", "hardlink", "baseline_sidecar"])
def test_additional_output_aliases_preserve_inputs(source, tmp_path, alias):
    report, args, base = build(source, tmp_path)
    out = tmp_path / "out.json"
    sheet = tmp_path / "out.csv"
    if alias == "symlink":
        sheet.symlink_to(base)
    elif alias == "ancestor":
        link = tmp_path / "alias"
        link.symlink_to(tmp_path, target_is_directory=True)
        sheet = link / "absent.csv"
    elif alias == "hardlink":
        import os

        os.link(base, sheet)
    else:
        sheet = base.with_name(base.name + "-journal")
    original = base.read_bytes()
    with pytest.raises(ValueError, match="unsafe_output_path"):
        api().write_report(
            report, json_path=out, csv_path=sheet, workspace=args["workspace"], baseline_path=base
        )
    assert base.read_bytes() == original and not out.exists()


def test_invalid_workspace_and_changed_baseline_cannot_publish(source, tmp_path):
    import sqlite3

    report, args, base = build(source, tmp_path)
    out = tmp_path / "out.json"
    sheet = tmp_path / "out.csv"
    kwargs = dict(json_path=out, csv_path=sheet, workspace=args["workspace"], baseline_path=base)
    another = tmp_path / "another"
    another.mkdir()
    base.write_bytes(baseline_file(another, [dict(cve="CVE-2026-1234")]).read_bytes())
    with pytest.raises(ValueError, match="stale_report"):
        api().write_report(report, **kwargs)
    assert not out.exists() and not sheet.exists()
    with sqlite3.connect(args["workspace"] / "state.sqlite3") as db:
        db.execute("UPDATE meta SET value='999' WHERE key='cursor'")
    with pytest.raises(ValueError, match="state_integrity"):
        api().write_report(report, **kwargs)
    assert not out.exists() and not sheet.exists()


@pytest.mark.parametrize(
    "mutation", ["unknown_state", "reference_locator", "date_route", "retained_state"]
)
def test_reference_semantics_survive_rehashed_mutation(source, tmp_path, monkeypatch, mutation):
    def mutate(body):
        body["containers"]["cna"]["references"] = [{"url": PUBLISHER}]

    source = changed_source(source, monkeypatch, mutate)
    report, _, _ = build(source, tmp_path, revisions=[dict(cve="CVE-2026-1234", url=PUBLISHER)])
    finding = report["findings"][0]
    ref = finding["references"][0]
    if mutation == "unknown_state":
        ref["collection_state"] = "unknown_identity"
        ref["revision_ids"] = []
        ref["evidence_ids"] = []
        ref["vendor_publication_dates"] = []
    if mutation == "reference_locator":
        ref["locator"] = "/containers/cna/references/../123"
    if mutation == "date_route":
        ref["vendor_publication_dates"][0]["source_url"] = "https://unreviewed.example/article"
    if mutation == "retained_state":
        ref["collection_state"] = "unobserved"
        ref["revision_ids"] = []
        ref["vendor_publication_dates"] = []
    if mutation in {"unknown_state", "retained_state"}:
        report["counts"]["dimensions"]["collection_state"] = [
            {"value": "missing_reference", "unique_cves": 2},
            {"value": ref["collection_state"], "unique_cves": 1},
        ]
    finding["finding_id"] = api()._finding_identity(finding)
    rehash(report)
    with pytest.raises(ValueError, match="invalid_report"):
        api().validate_report(report)


def test_writer_rejects_unsafe_workspace_before_opening_database(source, tmp_path, monkeypatch):
    import os

    report, args, base = build(source, tmp_path)
    os.link(args["workspace"] / "state.sqlite3", tmp_path / "aliased.sqlite3")

    def forbidden(*a, **kw):
        raise AssertionError("unsafe state opened before census")

    monkeypatch.setattr(state, "_connect", forbidden)
    with pytest.raises(ValueError, match="unsafe_workspace"):
        api().write_report(
            report,
            json_path=tmp_path / "out.json",
            csv_path=tmp_path / "out.csv",
            workspace=args["workspace"],
            baseline_path=base,
        )


@pytest.mark.parametrize(
    "reference",
    [
        {},
        {"url": None},
        {"url": 42},
        {"url": 1.25},
        {"url": False},
        {"url": [PUBLISHER]},
        {"url": {"href": PUBLISHER}},
    ],
    ids=["missing", "null", "integer", "number", "boolean", "list", "object"],
)
def test_malformed_reference_url_preserves_literal_and_exports_unknown(
    source, tmp_path, monkeypatch, reference
):
    def mutate(body):
        body["containers"]["cna"]["references"] = [reference]

    source = changed_source(source, monkeypatch, mutate)
    report, args, base = build(source, tmp_path)
    assert report["scan"]["parsed"] == 3
    exported = report["findings"][0]["references"][0]
    assert exported["url"] is None and exported["route_identity"] is None
    assert exported["collection_state"] == "unknown_identity"
    assert exported["locator"] == "/containers/cna/references/0"
    assert json.loads(exported["literal_json"]) == reference
    assert type(json.loads(exported["literal_json"]).get("url")) is type(reference.get("url"))
    assert report["findings"][1]["references"][0]["collection_state"] == "missing_reference"
    assert report["counts"]["dimensions"]["collection_state"] == [
        {"value": "missing_reference", "unique_cves": 2},
        {"value": "unknown_identity", "unique_cves": 1},
    ]
    output = tmp_path / "out.json"
    sheet = tmp_path / "out.csv"
    api().write_report(
        report, json_path=output, csv_path=sheet, workspace=args["workspace"], baseline_path=base
    )
    row = list(csv.DictReader(sheet.open()))[0]
    assert row["reference_url"] == "" and row["collection_state"] == "unknown_identity"
    assert json.loads(row["reference_literal_json"]) == reference
    assert json.loads(output.read_text())["findings"][0]["references"][0] == exported

    # Recompute the report identity so only the invented URL projection is wrong.
    exported["url"] = "42"
    rehash(report)
    with pytest.raises(ValueError, match="invalid_report"):
        api().validate_report(report)
