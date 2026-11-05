"""Operator inventory stays explicit, bounded, read-only and source-attributed."""

import copy
import json
import os
from contextlib import closing

import pytest
from jsonschema import Draft202012Validator, ValidationError
from test_archive import document
from test_coverage_notice_transitions import ROOT, URL, notice

from infrastructure_impact import cli
from infrastructure_impact.collection import archive
from infrastructure_impact.plugins.registry import default_registry
from infrastructure_impact.settings import PACKAGE
from infrastructure_impact.storage import archive_replays
from infrastructure_impact.storage.repository import (
    collection_result,
    connect,
    evidence,
    ingest,
    now,
)

INDEX = "https://csaf.arubanetworking.hpe.com/index.txt"
CONFIG = {"vendors": [], "archives": [{"vendor": "aruba", "url": INDEX, "kind": "index"}]}


def report(*args, **kwargs):
    from infrastructure_impact.application.coverage_gaps import report as implementation

    return implementation(*args, **kwargs)


def source(db, vendor="aruba", url=INDEX, kind="index"):
    db.execute(
        "INSERT INTO archive_sources(vendor,source_url,kind,started_at) VALUES(?,?,?,?)",
        (vendor, url, kind, now()),
    )
    return dict(db.execute("SELECT * FROM archive_sources ORDER BY id DESC LIMIT 1").fetchone())


def item(db, s, url, state="pending", raw=None, error=None):
    archive.enqueue(db, s["id"], "document", url)
    e = evidence(db, raw, url) if raw is not None else None
    db.execute(
        "UPDATE archive_items SET state=?,evidence_id=?,resolved_url=?,error_code=? WHERE source_id=? AND url=?",
        (state, e["id"] if e else None, url if e else None, error, s["id"], url),
    )
    return db.execute(
        "SELECT id FROM archive_items WHERE source_id=? AND url=?", (s["id"], url)
    ).fetchone()[0]


def schema():
    return json.loads((PACKAGE / "schemas/coverage-gaps-v1.json").read_text())


def test_queue_current_history_and_bounded_triage_are_separate():
    with closing(connect(":memory:")) as db:
        s = source(db)
        one = INDEX.replace("index.txt", "one.json")
        two = INDEX.replace("index.txt", "two.json")
        raw = document(one)
        ingest(db, raw, one, default_registry().normalize, "aruba")
        item(db, s, one, "done", raw)
        item(db, s, two, "pending")
        broken = item(
            db,
            s,
            INDEX.replace("index.txt", "bad.json"),
            "error",
            b"bad",
            "unsupported_or_invalid_document",
        )
        item(db, s, INDEX.replace("index.txt", "denied.json"), "error", error="access_denied")
        item(db, s, INDEX.replace("index.txt", "other.json"), "not_applicable")
        collection_result(db, "aruba", INDEX, "error", "PRIVATE_ERROR", "access_denied")
        collection_result(db, "aruba", INDEX, "ok", "PRIVATE_ERROR")
        archive_replays.record(
            db, broken, "old", "still_unsupported", error_code="unsupported_or_invalid_document"
        )
        db.execute(
            "INSERT INTO pipeline_runs(started_at,outcome,imported,failures,details) VALUES(?,?,?,?,?)",
            (now(), "error", 3, 7, "PRIVATE_ERROR"),
        )
        result = report(db, CONFIG, vendor="aruba", limit=1)
        row = result["sources"][0]
        assert row["queue"] == {
            "discovered": 5,
            "pending": 1,
            "done": 1,
            "not_applicable": 1,
            "error": 2,
            "retrieved": 2,
            "retrieval_failures": 1,
            "unsupported": 1,
            "other_errors": 0,
        }
        assert row["current"]["parsed_advisories"] == 1
        assert row["current"]["unknown_aliases"] == 4
        assert row["current"]["publisher_total"] is None
        assert row["current"]["model_classification"] == "unknown"
        assert row["health"]["outcome"] == "ok"
        assert row["history"]["collection_attempts"] == 2
        assert row["history"]["collection_errors"] == 1
        assert row["history"]["parser_replays"] == {
            "attempts": 1,
            "recovered": 0,
            "not_applicable": 0,
            "still_unsupported": 1,
            "not_retained": 0,
        }
        assert result["last_run"]["failures"] == 7
        assert result["triage"]["available"] == 5
        assert result["triage"]["sampled"] == 1 and result["triage"]["unsampled"] == 4
        assert result["triage"]["truncated"] is True
        assert "PRIVATE_ERROR" not in json.dumps(result)
        Draft202012Validator(schema()).validate(result)


def test_positive_notice_sample_does_not_turn_generic_not_applicable_into_notice():
    with closing(connect(":memory:")) as db:
        s = source(db, "arista", ROOT, "listing")
        item(db, s, URL, "not_applicable", notice())
        item(db, s, ROOT + "/unknown", "not_applicable")
        result = report(db, {"vendors": []}, vendor="arista")
        row = result["sources"][0]
        assert row["configured"] is False
        assert row["queue"]["not_applicable"] == 2
        assert row["current"]["parsed_advisories"] == 0
        assert row["triage"]["recognized_notice"] == 1
        assert row["triage"]["not_retained"] == 1
        assert row["triage"]["other_not_applicable"] == 0
        assert result["triage"]["documents"][0]["outcome"] == "recognized_notice"
        assert "PRIVATE_NOTICE_SENTINEL" not in json.dumps(result)


def test_known_representations_deduplicate_identity_and_new_current_bytes_are_unknown():
    with closing(connect(":memory:")) as db:
        s = source(db)
        a = INDEX.replace("index.txt", "a.json")
        b = INDEX.replace("index.txt", "b.json")
        raw = document(a)
        for url in (a, b):
            ingest(db, raw, url, default_registry().normalize, "aruba")
            item(db, s, url, "done", raw)
        first = report(db, CONFIG)["sources"][0]["current"]
        assert first["parsed_advisories"] == 1
        assert first["parsed_representations"] == 2
        assert first["unknown_aliases"] == 0
        changed = evidence(db, b"changed unparsed", a)
        db.execute("INSERT INTO http_cache(url,evidence_id) VALUES(?,?)", (a, changed["id"]))
        second = report(db, CONFIG)["sources"][0]["current"]
        assert second["parsed_representations"] == 1 and second["unknown_aliases"] == 1


@pytest.mark.parametrize("limit", [True, False, 0, 201, 1.2, "1"])
def test_invalid_limits_fail(limit):
    with closing(connect(":memory:")) as db, pytest.raises(ValueError):
        report(db, {"vendors": []}, limit=limit)


def test_unknown_vendor_and_explicit_empty_config():
    with closing(connect(":memory:")) as db:
        assert report(db, {"vendors": []})["sources"] == []
        with pytest.raises(ValueError):
            report(db, {"vendors": []}, vendor="uninstalled")


def test_cli_query_only_no_native_config_network_credentials_lock_or_database_mutation(
    tmp_path, monkeypatch, capsys
):
    path = tmp_path / "vault.sqlite"
    config = tmp_path / "sources.json"
    config.write_text(json.dumps(CONFIG))
    with closing(connect(path)) as db:
        source(db)
        db.commit()
        before = list(db.iterdump())

    def forbidden(*args, **kwargs):
        raise AssertionError("Unexpected native, network, credential or writer operation")

    from infrastructure_impact.collection import cisco_openvuln, transport
    from infrastructure_impact.settings import Paths
    from infrastructure_impact.storage import locking, migrations

    monkeypatch.setattr(Paths, "from_env", forbidden)
    monkeypatch.setattr(transport, "build_opener", forbidden)
    monkeypatch.setattr(cisco_openvuln.CiscoOpenVuln, "__init__", forbidden)
    monkeypatch.setattr(locking, "writer_lock", forbidden)
    monkeypatch.setattr(migrations, "migrate", forbidden)
    from infrastructure_impact.storage import repository

    real_connect = repository.connect

    def query_only(path=None, *, read_only=False):
        assert read_only is True
        db = real_connect(path, read_only=read_only)
        with pytest.raises(Exception, match="readonly"):
            db.execute("CREATE TABLE forbidden(value)")
        return db

    monkeypatch.setattr(repository, "connect", query_only)
    cli.main(["coverage-gaps", "--database", str(path), "--config", str(config)])
    result = json.loads(capsys.readouterr().out)
    Draft202012Validator(schema()).validate(result)
    with closing(real_connect(path, read_only=True)) as db:
        assert list(db.iterdump()) == before


@pytest.mark.parametrize("missing", ["--database", "--config"])
def test_cli_requires_both_explicit_inputs(missing, tmp_path):
    args = ["coverage-gaps"]
    for flag in ("--database", "--config"):
        if flag != missing:
            args.extend([flag, str(tmp_path / "missing")])
    with pytest.raises(SystemExit) as caught:
        cli.main(args)
    assert caught.value.code == 2
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "target,alias",
    [
        ("db", "direct"),
        ("config", "direct"),
        ("db", "symlink"),
        ("config", "symlink"),
        ("db", "hardlink"),
        ("config", "hardlink"),
    ],
)
def test_cli_output_cannot_overwrite_any_input_alias(tmp_path, target, alias):
    dbpath = tmp_path / "vault.sqlite"
    cfg = tmp_path / "sources.json"
    with closing(connect(dbpath)):
        pass
    cfg.write_text('{"vendors": []}')
    original = dbpath if target == "db" else cfg
    output = original if alias == "direct" else tmp_path / "output.json"
    if alias == "symlink":
        output.symlink_to(original)
    elif alias == "hardlink":
        os.link(original, output)
    before = original.read_bytes()
    with pytest.raises(SystemExit) as caught:
        cli.main(
            [
                "coverage-gaps",
                "--database",
                str(dbpath),
                "--config",
                str(cfg),
                "--output",
                str(output),
            ]
        )
    assert caught.value.code == 2 and original.read_bytes() == before


def test_cli_missing_files_and_secret_configuration_fail_safely(tmp_path, capsys):
    path = tmp_path / "missing.sqlite"
    cfg = tmp_path / "sources.json"
    cfg.write_text('{"vendors": [], "SECRET_SENTINEL": 1}')
    with pytest.raises(SystemExit):
        cli.main(["coverage-gaps", "--database", str(path), "--config", str(cfg)])
    assert not path.exists()
    assert "SECRET_SENTINEL" not in capsys.readouterr().err


def test_schema_rejects_private_fields_wrong_counts_and_booleans():
    with closing(connect(":memory:")) as db:
        result = report(db, CONFIG)
    for path, value in [
        ((), {"private": "SECRET"}),
        (("scope",), {"private": "SECRET"}),
        (("sources", 0, "queue"), {"pending": True}),
        (("sources", 0, "current"), {"publisher_total": 10}),
    ]:
        mutated = copy.deepcopy(result)
        node = mutated
        for key in path:
            node = node[key]
        node.update(value)
        with pytest.raises(ValidationError):
            Draft202012Validator(schema()).validate(mutated)


def test_retained_feed_window_is_labelled_and_configured_unobserved_is_explicit():
    cfg = {"vendors": [{"vendor": "aruba", "url": INDEX, "kind": "index", "limit": 2}]}
    with closing(connect(":memory:")) as db:
        first = report(db, cfg)["sources"][0]
        assert first["configured"] and first["observed_window"] is None
        assert first["budgets"] == {"feed_limit": 2, "page_limit": None, "document_limit": None}
        evidence(db, b"one.json\none.json\ntwo.json\n", INDEX)
        window = report(db, cfg)["sources"][0]["observed_window"]
        assert window["entries"] == 3 and window["unique_links"] == 2
        assert window["historical_availability"] == "unknown"


def test_backfill_window_identity_and_duplicate_diagnostic_are_not_failure_totals():
    from infrastructure_impact.collection.switching_backfill import _initialize, _issue

    with closing(connect(":memory:")) as db:
        run = _initialize(
            db,
            {"id": "synthetic-study"},
            "a" * 64,
            "aruba",
            CONFIG["archives"][0],
            "2021-01-01",
            "2026-11-05",
        )
        _issue(db, run, "listing_duplicate_links")
        db.execute(
            "UPDATE switching_backfills SET enumerated=1,duplicate_entries=1 WHERE id=?", (run,)
        )
        result = report(db, CONFIG)
        rows = [r for r in result["sources"] if r["invocation"]]
        assert len(rows) == 1
        invocation = rows[0]["invocation"]
        assert invocation["run_id"] == run
        assert invocation["requested_window"] == {
            "start_date": "2021-01-01",
            "end_date": "2026-11-05",
        }
        assert invocation["enumeration_state"] == "enumerated"
        assert rows[0]["configured"] is True
        assert invocation["diagnostics"] == [
            "listing_duplicate_links",
            "pre_2022_history_not_enumerated",
        ]
        assert rows[0]["queue"]["error"] == 0
        assert rows[0]["current"]["publisher_total"] is None


def test_notice_resolution_and_current_evidence_matching_can_be_uncertain():
    with closing(connect(":memory:")) as db:
        s = source(db)
        root = INDEX.replace("index.txt", "wrapper")
        selected = INDEX.replace("index.txt", "selected.json")
        raw = document(selected)
        ingest(db, raw, selected, default_registry().normalize, "aruba")
        iid = item(db, s, root, "done")
        e = evidence(db, raw, selected)
        evidence(db, ('<a href="' + selected + '">CSAF</a>').encode(), root)
        db.execute(
            "UPDATE archive_items SET resolved_url=?,evidence_id=?,checked_at=? WHERE id=?",
            (selected, e["id"], now(), iid),
        )
        assert report(db, CONFIG)["sources"][0]["current"]["parsed_advisories"] == 1
        # New unprocessed wrapper capture cannot certify the old resolution.
        evidence(db, b"new wrapper with unresolved identity", root)
        row = report(db, CONFIG)["sources"][0]
        assert row["current"]["parsed_advisories"] == 0
        assert row["current"]["unknown_aliases"] == 1


def test_installed_external_plugin_and_generic_not_applicable_remain_supported(monkeypatch):
    from infrastructure_impact.plugins.contracts import SourceNotApplicable, VendorPlugin

    def no_document(raw, url, vendor):
        raise SourceNotApplicable("PRIVATE_PLUGIN_DIAGNOSTIC")

    plugin = VendorPlugin("external", "External primary vendor", ("vendor.example",), no_document)
    monkeypatch.setitem(default_registry()._plugins, "external", plugin)
    root = "https://vendor.example/index.txt"
    with closing(connect(":memory:")) as db:
        s = source(db, "external", root)
        item(db, s, "https://vendor.example/document", "not_applicable", b"unsupported category")
        result = report(db, {"vendors": []}, vendor="external")
        assert result["scope"]["vendor"] == "external"
        assert result["sources"][0]["triage"]["other_not_applicable"] == 1
        assert result["sources"][0]["triage"]["recognized_notice"] == 0
        assert "PRIVATE_PLUGIN_DIAGNOSTIC" not in json.dumps(result)
        Draft202012Validator(schema()).validate(result)


def test_cli_writes_utf8_json_artifact(tmp_path, capsys):
    dbpath = tmp_path / "vault.sqlite"
    cfg = tmp_path / "sources.json"
    output = tmp_path / "inventory.json"
    with closing(connect(dbpath)):
        pass
    cfg.write_text('{"vendors": []}', encoding="utf-8")
    cli.main(
        ["coverage-gaps", "--database", str(dbpath), "--config", str(cfg), "--output", str(output)]
    )
    assert json.loads(output.read_text(encoding="utf-8"))["sources"] == []
    assert capsys.readouterr().out == ""


def test_feed_links_attribute_retained_parsed_representations_without_a_queue():
    cfg = {"vendors": [{"vendor": "aruba", "url": INDEX, "kind": "index"}]}
    with closing(connect(":memory:")) as db:
        evidence(db, b"one.json\ntwo.json\n", INDEX)
        url = INDEX.replace("index.txt", "one.json")
        ingest(db, document(url), url, default_registry().normalize, "aruba")
        row = next(r for r in report(db, cfg)["sources"] if r["source_url"] == INDEX)
        assert row["queue"]["discovered"] == 0
        assert row["current"]["parsed_advisories"] == 1
        assert row["current"]["unknown_aliases"] == 1


def test_not_configured_persisted_backfill_retains_invocation_identity():
    from infrastructure_impact.collection.switching_backfill import _initialize

    with closing(connect(":memory:")) as db:
        run = _initialize(
            db, {"id": "synthetic-study"}, "a" * 64, "cisco", None, "2021-01-01", "2026-11-05"
        )
        result = report(db, {"vendors": []}, vendor="cisco")
        assert len(result["sources"]) == 1
        row = result["sources"][0]
        assert row["source_url"] is None and row["configured"] is False
        assert row["invocation"]["run_id"] == run
        assert row["invocation"]["enumeration_state"] == "not_configured"


def test_retained_unlinked_notice_is_separate_from_excluded_notice():
    from test_vendor_gaps import article

    url = "https://www.arista.com/en/support/advisories-notices/security-advisory/24500-security-advisory-0146"
    raw = article(
        "0146",
        '<h3>Affected Software</h3><a href="https://github.com/advisories/GHSA-hrxh-6v49-42gf">GHSA</a>',
    ).encode()
    with closing(connect(":memory:")) as db:
        s = source(db, "arista", ROOT, "listing")
        item(db, s, url, "done", raw)
        ingest(db, raw, url, default_registry().normalize, "arista")
        row = report(db, {"vendors": []}, vendor="arista")["sources"][0]
        assert row["current"]["parsed_advisories"] == 0
        assert row["triage"]["retained_unlinked_notice"] == 1
        assert row["triage"]["recognized_notice"] == 0
        assert row["current"]["retained_unlinked_notices"] == 1
        assert row["current"]["unknown_aliases"] == 0


def test_example_configuration_validates_offline():
    from pathlib import Path

    from infrastructure_impact.collection.config import load_config

    cfg = load_config(Path("examples/switching-coverage-sources.json"))
    assert cfg["vendors"] == []
    assert any(
        e["url"] == "https://csaf.arubanetworking.hpe.com/2021/" and e["kind"] == "listing"
        for e in cfg["archives"]
    )


def test_global_triage_limit_also_accounts_for_unqueued_pins_and_feed_links():
    cfg = {
        "vendors": [{"vendor": "aruba", "url": INDEX, "kind": "index"}],
        "pinned": [{"vendor": "arista", "url": URL}],
    }
    with closing(connect(":memory:")) as db:
        evidence(db, b"one.json\ntwo.json\n", INDEX)
        evidence(db, notice(), URL)
        result = report(db, cfg, limit=2)
        assert result["triage"]["available"] == 3
        assert result["triage"]["sampled"] == 2
        assert result["triage"]["unsampled"] == 1
        assert sum(row["triage"]["sampled"] for row in result["sources"]) == 2


def test_partial_health_and_global_run_keep_controlled_outcome():
    with closing(connect(":memory:")) as db:
        collection_result(db, "aruba", INDEX, "partial", "PRIVATE_DETAIL")
        db.execute(
            "INSERT INTO pipeline_runs(started_at,outcome,imported,failures) VALUES(?,?,?,?)",
            (now(), "partial", 1, 2),
        )
        result = report(db, CONFIG)
        assert result["sources"][0]["health"]["outcome"] == "partial"
        assert result["last_run"]["outcome"] == "partial"


def test_one_retained_response_can_contain_multiple_persisted_identities():
    with closing(connect(":memory:")) as db:
        raw = document(INDEX)
        for identity in ("one", "two"):

            def normalize(raw, url, vendor):
                normalized = default_registry().normalize(raw, url, vendor)
                normalized["advisory_id"] = identity
                return normalized

            ingest(db, raw, INDEX, normalize, "aruba")
        cfg = {"vendors": [{"vendor": "aruba", "url": INDEX, "kind": "index"}]}
        row = report(db, cfg)["sources"][0]
        assert report(db, cfg)["triage"]["available"] == 1
        assert row["current"]["parsed_advisories"] == 2
        assert row["current"]["parsed_representations"] == 2
        assert row["current"]["unknown_aliases"] == 0


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
@pytest.mark.parametrize("alias", ["reserved", "symlink", "hardlink"])
def test_cli_rejects_reserved_sidecar_paths_and_aliases_before_opening_database(
    tmp_path, monkeypatch, suffix, alias
):
    from infrastructure_impact.storage import repository

    path = tmp_path / "vault.sqlite"
    cfg = tmp_path / "sources.json"
    cfg.write_text('{"vendors": []}')
    with closing(connect(path)):
        pass
    sidecar = path.with_name(path.name + suffix)
    output = sidecar if alias == "reserved" else tmp_path / "result.json"
    if alias != "reserved":
        sidecar.touch()
        if alias == "symlink":
            output.symlink_to(sidecar)
        else:
            os.link(sidecar, output)
    before = sidecar.read_bytes() if sidecar.exists() else None

    def forbidden(*args, **kwargs):
        raise AssertionError("Must reject output before opening the database")

    monkeypatch.setattr(repository, "connect", forbidden)
    with pytest.raises(SystemExit) as caught:
        cli.main(
            [
                "coverage-gaps",
                "--database",
                str(path),
                "--config",
                str(cfg),
                "--output",
                str(output),
            ]
        )
    assert caught.value.code == 2
    assert (sidecar.read_bytes() if sidecar.exists() else None) == before


def test_wrapper_cache_reversion_cannot_reuse_an_unrelated_resolution():
    with closing(connect(":memory:")) as db:
        s = source(db)
        root = INDEX.replace("index.txt", "wrapper")
        a = INDEX.replace("index.txt", "a.json")
        b = INDEX.replace("index.txt", "b.json")
        original = evidence(db, ('<a href="' + a + '">CSAF</a>').encode(), root)
        evidence(db, ('<a href="' + b + '">CSAF</a>').encode(), root)
        iid = item(db, s, root, "done")
        raw = document(b)
        ingest(db, raw, b, default_registry().normalize, "aruba")
        selected = evidence(db, raw, b)
        db.execute(
            "UPDATE archive_items SET resolved_url=?,evidence_id=?,checked_at=? WHERE id=?",
            (b, selected["id"], now(), iid),
        )
        # Current request now selects old A wrapper bytes. A itself is missing.
        db.execute("INSERT INTO http_cache(url,evidence_id) VALUES(?,?)", (root, original["id"]))
        row = report(db, CONFIG)["sources"][0]
        assert row["current"]["parsed_advisories"] == 0
        assert row["current"]["unknown_aliases"] == 1


@pytest.mark.parametrize("expected_total", [None, 137])
def test_invocation_preserves_nullable_publisher_window_total(expected_total):
    from infrastructure_impact.collection.switching_backfill import _initialize, _issue

    with closing(connect(":memory:")) as db:
        run = _initialize(
            db,
            {"id": "synthetic-study"},
            "a" * 64,
            "aruba",
            CONFIG["archives"][0],
            "2021-01-01",
            "2026-11-05",
        )
        db.execute(
            "UPDATE switching_backfills SET expected_total=?,unstable=1 WHERE id=?",
            (expected_total, run),
        )
        _issue(db, run, "publisher_total_changed")
        row = next(r for r in report(db, CONFIG)["sources"] if r["invocation"])
        assert row["invocation"]["expected_total"] == expected_total
        assert row["invocation"]["enumeration_state"] == "unstable"
        assert "publisher_total_changed" in row["invocation"]["diagnostics"]
        assert row["current"]["publisher_total"] is None
        assert row["current"]["portfolio_completeness"] == "not_established"


@pytest.mark.parametrize("section", ["pinned", "feed"])
@pytest.mark.parametrize("ingested", [False, True])
def test_unqueued_wrapper_uses_proven_preview_without_promoting_preview_to_ingestion(
    section, ingested
):
    root = INDEX.replace("index.txt", "wrapper")
    selected = INDEX.replace("index.txt", "selected.json")
    cfg = {"vendors": []}
    if section == "pinned":
        cfg["pinned"] = [{"vendor": "aruba", "url": root}]
        report_url = root
    else:
        cfg["vendors"] = [{"vendor": "aruba", "url": INDEX, "kind": "index"}]
        report_url = INDEX
    with closing(connect(":memory:")) as db:
        if section == "feed":
            evidence(db, (root + "\n").encode(), INDEX)
            # Index discovery deliberately only accepts .json source links.
            root += ".json"
            evidence(db, (root + "\n").encode(), INDEX)
        evidence(db, ('<a href="' + selected + '">CSAF</a>').encode(), root)
        raw = document(selected)
        evidence(db, raw, selected)
        if ingested:
            ingest(db, raw, selected, default_registry().normalize, "aruba")
        before = list(db.iterdump())
        result = report(db, cfg, limit=1)
        row = next(r for r in result["sources"] if r["source_url"] == report_url)
        assert result["triage"]["sampled"] == 1
        assert result["triage"]["documents"][0]["outcome"] == "parsed_preview"
        assert row["current"]["parsed_advisories"] == int(ingested)
        assert row["current"]["parsed_representations"] == int(ingested)
        assert row["current"]["unknown_aliases"] == int(not ingested)
        assert list(db.iterdump()) == before


def test_unqueued_pin_uses_current_persisted_selection_outside_preview_sample():
    from infrastructure_impact.plugins.contracts import SourceSelection, SourceView
    from infrastructure_impact.storage.source_selections import retain

    root = INDEX.replace("index.txt", "wrapper")
    selected = INDEX.replace("index.txt", "selected.json")
    with closing(connect(":memory:")) as db:
        s = source(db)
        item(db, s, INDEX.replace("index.txt", "failed.json"), "error")
        raw = document(selected)
        wrapper = ('<a href="' + selected + '">CSAF</a>').encode()
        ingest(db, raw, selected, default_registry().normalize, "aruba")
        retain(
            db,
            "aruba",
            root,
            SourceSelection(
                SourceView(selected, raw, "CSAF", 1, "synthetic"),
                (SourceView(root, wrapper, "HTML", 0, "synthetic"),),
                "Synthetic reviewed source choice",
            ),
            record_health=False,
        )
        cfg = {"vendors": [], "pinned": [{"vendor": "aruba", "url": root}]}
        before = list(db.iterdump())
        result = report(db, cfg, limit=1)
        row = next(r for r in result["sources"] if r["source_url"] == root)
        assert result["triage"]["sampled"] == 1
        assert row["triage"]["sampled"] == 0
        assert row["current"]["parsed_advisories"] == 1
        assert row["current"]["unknown_aliases"] == 0
        assert list(db.iterdump()) == before
        # A later current wrapper capture cannot inherit the old source choice.
        evidence(db, b"new unreviewed wrapper", root)
        row = next(r for r in report(db, cfg, limit=1)["sources"] if r["source_url"] == root)
        assert row["current"]["parsed_advisories"] == 0
        assert row["current"]["unknown_aliases"] == 1

        # Restore the wrapper pointer, but change its selected representation.
        # The old selection cannot certify new selected bytes; an exact cache
        # reversion to both known captures can certify the retained relation.
        original_wrapper = evidence(db, wrapper, root)
        original_selected = evidence(db, raw, selected)
        db.execute(
            "INSERT INTO http_cache(url,evidence_id) VALUES(?,?)", (root, original_wrapper["id"])
        )
        evidence(db, b"new unparsed selected bytes", selected)
        row = next(r for r in report(db, cfg, limit=1)["sources"] if r["source_url"] == root)
        assert row["current"]["parsed_advisories"] == 0
        assert row["current"]["unknown_aliases"] == 1
        db.execute(
            "INSERT INTO http_cache(url,evidence_id) VALUES(?,?)",
            (selected, original_selected["id"]),
        )
        row = next(r for r in report(db, cfg, limit=1)["sources"] if r["source_url"] == root)
        assert row["current"]["parsed_advisories"] == 1
        assert row["current"]["unknown_aliases"] == 0


@pytest.mark.parametrize("product", [None, 123, {"PRIVATE_CONFIG_SENTINEL": "secret"}])
def test_cli_malformed_explicit_release_product_is_sanitized_with_existing_database(
    tmp_path, capsys, product
):
    dbpath = tmp_path / "vault.sqlite"
    cfg = tmp_path / "sources.json"
    output = tmp_path / "inventory.json"
    with closing(connect(dbpath)):
        pass
    cfg.write_text(
        json.dumps(
            {
                "vendors": [],
                "release_documents": [{"vendor": "aruba", "url": INDEX, "product": product}],
            }
        )
    )
    before = dbpath.read_bytes()
    with pytest.raises(SystemExit) as caught:
        cli.main(
            [
                "coverage-gaps",
                "--database",
                str(dbpath),
                "--config",
                str(cfg),
                "--output",
                str(output),
            ]
        )
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert "Coverage inventory failed" in captured.err
    assert "PRIVATE_CONFIG_SENTINEL" not in captured.err
    assert "AttributeError" not in captured.err and "Traceback" not in captured.err
    assert captured.out == "" and not output.exists()
    assert dbpath.read_bytes() == before
