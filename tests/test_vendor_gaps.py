"""Synthetic exceptional layouts, honest gap counts and bounded backup accounting."""

import json

import pytest

from checks.backup_storage import summarize
from infrastructure_impact.adapters.arista import arista_aggregate_notice
from infrastructure_impact.adapters.arista_scoped import grouped_software, non_cve_security_notice
from infrastructure_impact.adapters.common import base
from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.query import state
from infrastructure_impact.collection.archive import acknowledge_retained, enqueue
from infrastructure_impact.http import Application, BadRequest
from infrastructure_impact.storage.repository import connect, ingest

ROOT = "https://www.arista.com/en/support/advisories-notices/security-advisory/"
A = "CVE-2026-12345"
B = "CVE-2026-54321"


def article(number, body):
    return f'<div class="item-page"><h2>Security Advisory {number}</h2><table><tr><td>1.0</td><td>August 25, 2026</td><td>Initial release</td></tr></table>{body}</div>'


def grouped():
    return article(
        "0147",
        f"<p>The CVE-IDs tracking these issues: {A} {B}</p><h2>Description</h2><h3>Affected Software</h3><h4>EOS Versions</h4><div><b>{A}</b></div><ul><li>4.35.6 and below</li></ul><div><b>{B}</b></div><ul><li>4.35.5 and below</li></ul><h4>Wi-Fi Access Points Versions</h4><div><b>{A}</b><div><ul><li>21.x</li></ul><h3>Affected Platforms</h3><p>Only the listed platforms</p><h3>Required Configuration for Exploitation</h3><h4>Wi-Fi Access Points</h4><p>Non-default configuration required</p><h2>Resolution</h2><ul><li>Unrelated fixed version</li></ul>",
    )


def test_arista_local_cve_groups_and_unclosed_div_do_not_leak():
    r = grouped_software(grouped(), ROOT + "24515-security-advisory-0147", "arista")
    assert len(r["assessments"]) == 3
    a, b, w = r["assessments"]
    assert (
        a["versions"][0]["expression"] == "4.35.6 and below"
        and b["versions"][0]["expression"] == "4.35.5 and below"
    )
    assert w["cve_id"] == A and w["product"] == "Arista Wi-Fi Access Points"
    assert "Non-default configuration" in json.dumps(w["exposure"]) and all(
        not c["remediations"] for c in r["assessments"]
    )


@pytest.mark.parametrize(
    "change", ["missing_group", "unknown_product", "outside_cve", "version_cve", "negated_range"]
)
def test_arista_unreviewed_group_boundaries_fail_closed(change):
    raw = grouped()
    if change == "missing_group":
        raw = raw.replace(f"<b>{A}</b>", "<b>Group</b>")
    if change == "unknown_product":
        raw = raw.replace("EOS Versions", "Unknown Versions")
    if change == "outside_cve":
        raw = raw.replace(f"<b>{B}</b>", "<b>CVE-2026-99999</b>")
    if change == "version_cve":
        raw = raw.replace("21.x", B + " version condition")
    if change == "negated_range":
        raw = raw.replace("21.x", "21.x not affected")
    with pytest.raises(ValueError):
        grouped_software(raw, ROOT + "24515-security-advisory-0147", "arista")


def test_non_cve_notice_retains_metadata_without_upstream_cve_inference():
    raw = article(
        "0146",
        '<h3>Affected Software</h3><a href="https://github.com/advisories/GHSA-hrxh-6v49-42gf">GHSA</a>',
    )
    r = non_cve_security_notice(raw, ROOT + "24500-security-advisory-0146", "arista")
    assert not r["cves"] and not r["assessments"] and "without CVE" in r["source_format"]
    with pytest.raises(ValueError):
        non_cve_security_notice(
            raw.replace("GHSA</a>", A + "</a>"), ROOT + "24500-security-advisory-0146", "arista"
        )


def test_informational_index_does_not_become_exposure():
    raw = article(
        "0148",
        f"<p>Update Type: Informational</p><table><tr><th>Security Advisory #</th><th>Product (Component)</th><th>CVE ID</th><th>Severity</th><th>CVSS 3.1 Score</th></tr><tr><td>149</td><td>EOS</td><td>{A}</td><td>High</td><td>8</td></tr></table>",
    )
    r = arista_aggregate_notice(raw, ROOT + "24535-security-advisory-0148", "arista")
    assert r["cves"] == [A] and not r["assessments"]


def test_gap_projection_is_global_and_ignores_injected_private_fields(tmp_path):
    with connect(":memory:") as db:
        raw = article(
            "0146",
            '<h3>Affected Software</h3><a href="https://github.com/advisories/GHSA-hrxh-6v49-42gf">GHSA</a>',
        )
        url = ROOT + "24500-security-advisory-0146"
        ingest(db, raw.encode(), url, non_cve_security_notice, "arista")
        data = state(db)
    data["vendor_gaps"]["PRIVATE_SENTINEL"] = "secret"
    data["extraction_validation"]["cases"][0]["source_url"] = (
        "https://example.test/PRIVATE_SENTINEL"
    )
    generation = publish(data, tmp_path)
    report = json.loads((generation / "vendor-gaps.json").read_text())
    assert "PRIVATE_SENTINEL" not in json.dumps(report)
    arista = next(v for v in report["vendors"] if v["vendor"] == "arista")
    assert arista["without_cve_advisories"] == 1 and arista["metadata_only_advisories"] == 1
    assert (
        not report["independent_human_review_completed"] and report["scope"] == "whole_publication"
    )
    app = Application(tmp_path)
    code, _, raw = app.route(
        dict(
            REQUEST_METHOD="GET",
            PATH_INFO="/api/v1/vendor-gaps",
            QUERY_STRING="vendor=arista&cves=" + A,
        )
    )
    assert (
        code == 200
        and len(json.loads(raw)["vendors"]) == 1
        and json.loads(raw)["scope"] == "whole_publication"
    )
    with pytest.raises(BadRequest):
        app.route(
            dict(
                REQUEST_METHOD="GET", PATH_INFO="/api/v1/vendor-gaps", QUERY_STRING="vendor=unknown"
            )
        )


def test_successful_pin_only_acknowledges_matching_vendor_archive_item():
    with connect(":memory:") as db:
        for vendor in ["arista", "cisco"]:
            db.execute(
                "INSERT INTO archive_sources(vendor,source_url,kind,started_at) VALUES(?,?,?,?)",
                (vendor, "https://example.test/" + vendor, "listing", "2026-01-01T00:00:00Z"),
            )
            sid = db.execute("select id from archive_sources where vendor=?", (vendor,)).fetchone()[
                0
            ]
            enqueue(db, sid, "document", ROOT + "synthetic")
        db.execute("UPDATE archive_items SET state='error',attempts=3")
        from infrastructure_impact.storage.repository import evidence

        ev = evidence(db, b"synthetic", ROOT + "synthetic")
        acknowledge_retained(db, "arista", ROOT + "synthetic", ROOT + "synthetic", ev["id"])
        rows = list(
            db.execute(
                "select s.vendor,i.state,i.attempts from archive_items i join archive_sources s on s.id=i.source_id order by s.vendor"
            )
        )
        assert [tuple(r) for r in rows] == [("arista", "done", 0), ("cisco", "error", 3)]


def blob(n, size=100):
    return dict(path="state/vault-" + str(n) + ".fernet", sha=str(n), size=size, type="blob")


def test_current_three_copies_do_not_hide_historical_backup_growth():
    trees = [[blob(4), blob(3), blob(2)], [blob(3), blob(2), blob(1)]]
    r = summarize(trees, 1000, dict(archive="vault-4.fernet", encryption="fernet-v1"))
    assert r["retention"]["current_tree_copies"] == 3 and r["history"]["unique_backup_blobs"] == 4
    assert (
        r["history"]["logical_backup_blob_bytes"] == 400
        and not r["retention"]["automatic_history_deletion"]
    )
    assert "days_until" not in json.dumps(r)


def test_backup_history_bounds_and_size_budget_require_honest_review():
    r = summarize([[blob(1)]] * 100, 524288, dict(archive="vault-1.fernet", encryption="fernet-v1"))
    assert (
        r["history"]["may_be_truncated"]
        and r["storage_review_required"]
        and r["remaining_runs_scenario"] == 0
    )
    with pytest.raises(ValueError):
        summarize([[blob(1)]], 1, dict(archive="missing.fernet", encryption="fernet-v1"))


def test_unlinked_security_notice_opt_in_does_not_admit_arbitrary_empty_records():
    with connect(":memory:") as db:
        r = base("arista", ROOT + "unknown", "SYNTHETIC", "Synthetic empty record")
        with pytest.raises(ValueError, match="explicit CVE"):
            ingest(db, b"synthetic", r["source_url"], lambda *_: r, "arista")


def test_normal_pin_success_resolves_archive_error_but_parse_failure_does_not(
    tmp_path, monkeypatch
):
    from infrastructure_impact.collection.service import run

    path = tmp_path / "vault.sqlite3"
    url = ROOT + "24500-security-advisory-0146"
    raw = article(
        "0146",
        '<h3>Affected Software</h3><a href="https://github.com/advisories/GHSA-hrxh-6v49-42gf">GHSA</a>',
    ).encode()
    with connect(path) as db:
        db.execute(
            "INSERT INTO archive_sources(vendor,source_url,kind,started_at) VALUES(?,?,?,?)",
            ("arista", "https://www.arista.com/archive", "listing", "2026-01-01T00:00:00Z"),
        )
        sid = db.execute("select id from archive_sources").fetchone()[0]
        enqueue(db, sid, "document", url)
        db.execute("UPDATE archive_items SET state='error',attempts=3")
    monkeypatch.setattr(
        "infrastructure_impact.collection.service.resolve_document", lambda *_: (url, raw)
    )
    cfg = {"vendors": [], "pinned": [{"vendor": "arista", "url": url}]}
    assert run(cfg, db_path=path) == (1, 0)
    with connect(path) as db:
        assert db.execute("select state from archive_items").fetchone()[0] == "done"
        db.execute("UPDATE archive_items SET state='error',attempts=3")
    monkeypatch.setattr(
        "infrastructure_impact.collection.service.resolve_document",
        lambda *_: (url, b"unsupported source"),
    )
    assert run(cfg, db_path=path) == (0, 1)
    with connect(path) as db:
        assert db.execute("select state from archive_items").fetchone()[0] == "error"


def test_backup_manifest_sizes_and_current_directory_retention_are_real(tmp_path):
    from cryptography.fernet import Fernet

    from ops.hosted_job import backup, restore

    database = tmp_path / "source.sqlite3"
    with connect(database):
        pass
    key = Fernet.generate_key()
    folder = tmp_path / "encrypted"
    for _ in range(4):
        manifest = backup(folder, database, key)
    assert len(list(folder.glob("vault-*.fernet"))) == 3
    assert manifest["archive_bytes"] == (folder / manifest["archive"]).stat().st_size
    assert manifest["database_bytes"] > manifest["compressed_bytes"] > 0
    assert manifest["retention"] == {
        "current_directory_copy_target": 3,
        "git_history_pruned": False,
    }
    assert restore(folder, tmp_path / "restored.sqlite3", key)
