"""One SK can have multiple explicit CVE rows; collection must not overwrite them."""

import json
from dataclasses import replace

import pytest

from infrastructure_impact.adapters.checkpoint import checkpoint_records
from infrastructure_impact.application.publication import public_projection
from infrastructure_impact.application.query import state
from infrastructure_impact.collection import service
from infrastructure_impact.domain import validate_advisory
from infrastructure_impact.plugins import PluginRegistry
from infrastructure_impact.plugins.checkpoint import parse_feed
from infrastructure_impact.plugins.registry import default_registry
from infrastructure_impact.storage.repository import connect, latest

URL = "https://iapi-services-ucs.checkpoint.com/public/api/support-center-mms/api/securityAdvisories/getAllActive"
A, B = "CVE-2099-12345", "CVE-2099-54321"


def row(identity, cid, *, sk="sk999999", product="Synthetic gateway", affected="Take 123"):
    return {
        "id": identity,
        "skId": sk,
        "cveId": cid,
        "enable": True,
        "summary": "Synthetic row " + str(identity),
        "url": "",
        "published": 1735689600000,
        "updated": 1735776000000,
        "products": [{"name": product, "version": "R99", "affected": affected}],
    }


def parse(rows):
    documents = checkpoint_records(json.dumps(rows), URL)
    for document in documents:
        validate_advisory(document)
    return documents


def test_exact_sk_group_keeps_each_cve_product_and_status_without_crossjoin():
    (document,) = parse(
        [
            row(1, A, product="Synthetic firewall"),
            row(2, B, product="Synthetic manager", affected="none"),
        ]
    )
    assert document["advisory_id"] == "sk999999" and document["cves"] == sorted([A, B])
    assert len(document["assessments"]) == 2
    claims = {a["cve_id"]: a for a in document["assessments"]}
    assert claims[A]["product"] == "Synthetic firewall R99" and claims[A]["status"] == "affected"
    assert claims[B]["product"] == "Synthetic manager R99" and claims[B]["status"] == "unaffected"
    assert all(a["scope"] == "cve_specific" and not a["remediations"] for a in claims.values())
    assert "record[id=1]" in claims[A]["evidence_locator"]
    assert ":index-row:1" in claims[A]["product_id"]


def test_same_cve_product_label_keeps_distinct_row_conditions():
    (document,) = parse([row(1, A), row(2, A, affected="none")])
    assert document["cves"] == [A]
    assert {a["status"] for a in document["assessments"]} == {"affected", "unaffected"}
    assert len({a["product_id"] for a in document["assessments"]}) == 2
    assert len({a["product"] for a in document["assessments"]}) == 1


def test_row_order_does_not_change_a_combined_advisory_and_single_rows_keep_identity():
    rows = [row(2, B), row(1, A)]
    assert parse(rows) == parse(list(reversed(rows)))
    (single,) = parse([rows[0]])
    assert single["title"] == "Synthetic row 2" and single["advisory_id"] == "sk999999"
    assert ":index-row:" not in single["assessments"][0]["product_id"]
    assert single["published_at"] == "2025-01-01T00:00:00+00:00"
    assert "extensions" not in single


def test_disagreeing_row_dates_are_unknown_without_losing_the_private_metadata():
    first, second = row(1, A), row(2, B)
    second.update(published=1735862400000, updated=None)
    (document,) = parse([first, second])
    assert document["published_at"] is None and document["updated_at"] is None
    assert sum("Index rows disagree" in warning for warning in document["warnings"]) == 2
    assert len(document["extensions"]["checkpoint_index_rows"]) == 2
    assert document["extensions"]["checkpoint_index_rows"][0]["published_at"]


@pytest.mark.parametrize(
    "edit",
    [
        lambda rows: rows[1].update(id=1),
        lambda rows: rows[1].update(id="1"),
        lambda rows: rows[1].update(url="https://support.checkpoint.com/other-article"),
        lambda rows: [r.update(skId="unreviewed-alias") for r in rows],
    ],
)
def test_ambiguous_row_identity_or_article_link_requires_review(edit):
    rows = [row(1, A), row(2, B)]
    edit(rows)
    with pytest.raises(ValueError):
        parse(rows)


def test_disabled_entries_and_other_sks_do_not_broaden_the_group():
    rows = [
        row(1, A),
        row(2, B, sk="sk888888"),
        dict(row(3, B), enable=False),
        dict(row(4, B), cveId=""),
    ]
    documents = parse(rows)
    assert len(documents) == 2
    assert documents[0]["cves"] == [A] and documents[1]["cves"] == [B]


def test_feed_limit_and_reference_selection_apply_to_combined_documents():
    rows = [row(1, A), row(2, B), row(3, "CVE-2099-11111", sk="sk888888")]
    batch = parse_feed(json.dumps(rows), URL, 0, frozenset([A]))
    assert len(batch.records) == 1 and batch.records[0]["cves"] == sorted([A, B])
    assert batch.referenced_cves == frozenset([A, B, "CVE-2099-11111"])
    assert len(batch.document_urls) == 2


def test_collection_and_publication_retain_both_rows_once(tmp_path, monkeypatch):
    raw = json.dumps([row(1, A), row(2, B)]).encode()
    registry = PluginRegistry()
    plugin = default_registry().get("checkpoint")

    def no_followups(*args):
        return replace(plugin.parse_feed(*args), document_urls=())

    registry.register(replace(plugin, parse_feed=no_followups))
    monkeypatch.setattr(service, "default_registry", lambda: registry)
    requests = []

    def fetch(db, url, vendor):
        requests.append(url)
        assert url == URL
        return raw

    monkeypatch.setattr(service, "fetch", fetch)
    path = tmp_path / "vault.sqlite3"
    assert service.run(
        {"vendors": [{"vendor": "checkpoint", "url": URL, "kind": "checkpoint", "limit": 4}]},
        db_path=path,
    ) == (1, 0)
    assert requests == [URL]
    with connect(path, read_only=True) as db:
        records = latest(db)
        assert len(records) == 1 and records[0]["cves"] == sorted([A, B])
        assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 1
        published = public_projection(state(db))
    assert len(published["records"][0]["assessments"]) == 2
    assert "extensions" not in published["records"][0]
    assert "checkpoint_index_rows" not in json.dumps(published)


def test_retained_partial_row_is_repaired_as_parser_reinterpretation(tmp_path, monkeypatch):
    from infrastructure_impact.application.replay import replay_report
    from infrastructure_impact.storage.repository import ingest

    monkeypatch.setenv("IMPACT_HOME", str(tmp_path))
    raw = json.dumps([row(1, A), row(2, B)]).encode()
    previous = parse([row(2, B)])[0]
    previous["adapter_version"] = "synthetic-earlier-row-writer"
    path = tmp_path / "vault.sqlite3"
    with connect(path) as db:
        ingest(db, raw, URL, lambda *args: previous, "checkpoint")
        before = latest(db)[0]
        evidence_count = db.execute("SELECT count(*) FROM evidence").fetchone()[0]
    report = replay_report(vendor="checkpoint", db_path=path)
    assert (
        report["failed"] == 0
        and report["reparsed_revisions"] == 1
        and report["semantic_changes"] == 1
    )
    assert report["network_requests"] == 0
    with connect(path, read_only=True) as db:
        after = latest(db)[0]
        assert after["cves"] == sorted([A, B])
        assert (after["advisory_id"], after["sha256"], after["source_observed_at"]) == (
            before["advisory_id"],
            before["sha256"],
            before["source_observed_at"],
        )
        assert db.execute("SELECT count(*) FROM evidence").fetchone()[0] == evidence_count
        assert [r[0] for r in db.execute("SELECT kind FROM changes")] == ["parser_reinterpretation"]
        assert db.execute("SELECT count(*) FROM source_observations").fetchone()[0] == 0


def test_common_feed_writer_rejects_duplicate_identities_before_first_advisory_write(
    tmp_path, monkeypatch
):
    from infrastructure_impact.plugins import FeedBatch

    registry = PluginRegistry()
    plugin = default_registry().get("checkpoint")
    # A hypothetical extension repeats the old per-row mistake. The writer must
    # reject this source batch even if both individual documents validate.
    (first,) = parse([row(1, A)])
    (second,) = parse([row(2, B)])
    registry.register(
        replace(
            plugin,
            parse_feed=lambda *args: FeedBatch(
                (first, second), frozenset([A, B]), "Synthetic invalid batch"
            ),
        )
    )
    monkeypatch.setattr(service, "default_registry", lambda: registry)
    monkeypatch.setattr(service, "fetch", lambda *args: b"synthetic retained index")
    path = tmp_path / "vault.sqlite3"
    assert service.run(
        {"vendors": [{"vendor": "checkpoint", "url": URL, "kind": "checkpoint", "limit": 4}]},
        db_path=path,
    ) == (0, 1)
    with connect(path, read_only=True) as db:
        assert db.execute("SELECT count(*) FROM revisions").fetchone()[0] == 0
        assert not latest(db)
