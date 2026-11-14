"""Offline explicit IOS XE query worklist; socket doubles use real transport."""

import hashlib
import json

import pytest
from test_cisco_openvuln import Clock, Network, Response, client, http, token

from infrastructure_impact import cli
from infrastructure_impact.collection import cisco_first_fixed as collector
from infrastructure_impact.collection.cisco_openvuln import CiscoOpenVuln
from infrastructure_impact.storage.repository import connect, evidence

URL = "https://apix.cisco.com/security/advisories/v2/OSType/iosxe?version=17.2.1"


def response(**changes):
    # Authored existing accepted envelope. Whole current live schema is unverified;
    # cves/productNames are deliberately insufficient for firstFixed ownership.
    row = {
        "advisoryId": "cisco-sa-authored",
        "cves": ["CVE-2026-12345"],
        "productNames": ["Cisco IOS XE Software"],
        "firstFixed": ["17.9.10", "17.3.1w", "17.2.2a"],
    }
    row.update(changes)
    return json.dumps({"advisories": [row]}).encode()


def test_parser_retains_alternatives_without_inventing_cve_product_or_train_binding():
    parsed = collector.parse_response(response(), query_release="17.2.1")
    assert parsed["first_fixed"] == []
    context = parsed["advisory_context"][0]
    assert context["source_first_fixed"] == ["17.9.10", "17.3.1w", "17.2.2a"]
    assert context["advisory_id"] == "cisco-sa-authored"
    assert context["cve_refs"] == ["CVE-2026-12345"]
    assert context["ownership_state"] == "ownership_unresolved"
    assert context["source_locator"] == "/advisories/0/firstFixed"
    assert {
        "ownership_unresolved",
        "unsupported_ordering_literal",
        "other_train_alternative",
    } <= set(parsed["issues"])


def test_parser_retains_underscore_advisory_identity_without_inventing_ownership():
    parsed = collector.parse_response(
        response(advisoryId="cisco-sa-authored_example-123", firstFixed=["17.2.2"]),
        query_release="17.2.1",
    )
    assert parsed["first_fixed"] == []
    assert parsed["advisory_context"] == [
        {
            "advisory_id": "cisco-sa-authored_example-123",
            "source_locator": "/advisories/0/firstFixed",
            "source_first_fixed": ["17.2.2"],
            "first_fixed_state": "present",
            "cve_refs": ["CVE-2026-12345"],
            "ownership_state": "ownership_unresolved",
        }
    ]
    assert "advisory_identity_unresolved" not in parsed["issues"]


@pytest.mark.parametrize(
    "advisory_id",
    [
        "cisco-sa-authored/other",
        "cisco-sa-authored?other",
        "cisco-sa-authored other",
        "cisco-sa-authored.other",
        "cisco-sa-authored\nother",
        "cisco-sa-authored_é",
        "cisco-sa-",
        "cisco-sa-" + "a" * 181,
    ],
)
def test_advisory_identity_keeps_closed_ascii_namespace(advisory_id):
    parsed = collector.parse_response(response(advisoryId=advisory_id), query_release="17.2.1")
    assert parsed["advisory_context"] == []
    assert "advisory_identity_unresolved" in parsed["issues"]


def test_underscore_advisory_capture_remains_acknowledged_and_cached():
    db = connect(":memory:")
    raw = response(advisoryId="cisco-sa-authored_example-123", firstFixed=["17.2.2"])
    network = Network(token(), Response(raw))
    transport = client(db, network)
    assert collector.run(db, releases=["17.2.1"], client=transport)["counts"] == {"success": 1}
    result = collector.results(db)[0]
    assert len(result["advisory_context"]) == 1
    assert result["advisory_context"][0]["advisory_id"] == "cisco-sa-authored_example-123"
    assert result["source"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["parser_revision"] == collector.PARSER_REVISION
    assert collector.run(db, releases=["17.2.1"], client=transport)["http_requests_reserved"] == 0
    assert len(network.calls) == 2


@pytest.mark.parametrize(
    "raw,issue",
    [
        (b"{secret", "invalid_json"),
        (b'{"advisories": [], "advisories": []}', "invalid_json"),
        (b"[]", "unsupported_response"),
        (b'{"advisories":[]}', "empty_response"),
        (response(firstFixed=[]), "empty_first_fixed"),
        (response(firstFixed=None), "malformed_first_fixed"),
        (response(firstFixed="17.2.2"), "malformed_first_fixed"),
        (response(firstFixed=["17.2.2", 17]), "malformed_first_fixed"),
        (response(advisoryId="wrong"), "advisory_identity_unresolved"),
        (b'{"advisories":[{"advisoryId":"cisco-sa-authored"}]}', "missing_first_fixed"),
        (b'{"advisoryId":"cisco-sa-authored","firstFixed":["17.2.2"]}', "unsupported_response"),
        (response(password="DO_NOT_LEAK"), "credential_response_rejected"),
    ],
)
def test_parser_closed_diagnostics(raw, issue):
    parsed = collector.parse_response(raw, query_release="17.2.1")
    assert parsed["first_fixed"] == []
    assert issue in parsed["issues"]
    assert "DO_NOT_LEAK" not in json.dumps(parsed)


@pytest.mark.parametrize("value", ["notFixed", "unknown", "17.2.2w", "17.2.2A"])
def test_unsupported_literals_retained_without_migration_or_verified_fix(value):
    parsed = collector.parse_response(response(firstFixed=[value]), query_release="17.2.1")
    assert parsed["first_fixed"] == []
    assert parsed["advisory_context"][0]["source_first_fixed"] == [value]
    assert "unsupported_ordering_literal" in parsed["issues"]


def test_plan_is_idempotent_and_does_not_construct_transport(monkeypatch):
    db = connect(":memory:")
    monkeypatch.setattr(
        collector, "CiscoOpenVuln", lambda *_: pytest.fail("network client in plan")
    )
    collector.plan(db, ["17.2.1", "17.2.1"])
    collector.plan(db, ["17.2.1"])
    receipt = collector.status(db)
    assert receipt["counts"] == {"pending": 1}
    assert receipt["queries"][0]["url"] == URL
    assert db.execute("SELECT count(*) FROM switching_requests").fetchone()[0] == 0


def test_run_real_transport_retains_actual_receipt_and_never_refetches_success():
    db = connect(":memory:")
    network = Network(token(), Response(response()))
    transport = client(db, network)
    receipt = collector.run(db, releases=["17.2.1", "17.2.1"], client=transport)
    assert receipt["release_queries_attempted"] == 1
    assert receipt["http_requests_reserved"] == 2
    assert receipt["counts"] == {"success": 1}
    result = collector.results(db)[0]
    capture = db.execute("SELECT * FROM evidence").fetchone()
    assert result["source"] == {
        "url": URL,
        "sha256": hashlib.sha256(response()).hexdigest(),
        "retrieved_at": capture["observed_at"],
        "evidence_id": capture["id"],
    }
    assert result["query_release"] == "17.2.1"
    assert result["parser_revision"]
    assert result["advisory_context"][0]["source_first_fixed"][1] == "17.3.1w"
    again = collector.run(db, releases=["17.2.1"], client=transport)
    assert again["release_queries_attempted"] == 0
    assert len(network.calls) == 2


@pytest.mark.parametrize("environ", [{}, {"CISCO_OPENVULN_CLIENT_ID": "fake"}])
def test_missing_or_partial_auth_remains_resumable(environ):
    db = connect(":memory:")
    network = Network()
    transport = CiscoOpenVuln(db, environ=environ, opener=network.factory)
    receipt = collector.run(db, releases=["17.2.1"], client=transport)
    assert receipt["counts"] == {"auth_not_configured": 1}
    assert not network.calls and not collector.results(db)
    receipt = collector.run(
        db, releases=["17.2.1"], client=client(db, Network(token(), Response(response())))
    )
    assert receipt["counts"] == {"success": 1}


def test_release_budget_counts_queries_separately_from_oauth_and_http_retries():
    db = connect(":memory:")
    network = Network(token(), Response(b"", status=401), token(), Response(response()))
    receipt = collector.run(
        db, releases=["17.2.1", "17.2.2"], max_releases=1, client=client(db, network)
    )
    assert receipt["counts"] == {"pending": 1, "success": 1}
    assert receipt["release_queries_attempted"] == 1
    assert receipt["http_requests_reserved"] == 4


def test_429_persists_cooldown_and_resume_uses_existing_quota():
    db = connect(":memory:")
    clock = Clock()
    network = Network(token(), http(429, {"Retry-After": "120"}), Response(response()))
    transport = client(db, network, clock)
    first = collector.run(db, releases=["17.2.1"], client=transport)
    assert first["counts"] == {"deferred": 1}
    assert collector.status(db)["queries"][0]["error_code"] == "rate_limited"
    second = collector.run(db, releases=["17.2.1"], client=transport)
    assert second["http_requests_reserved"] == 0
    clock.advance(120)
    assert collector.run(db, releases=["17.2.1"], client=transport)["counts"] == {"success": 1}


def test_interrupt_after_raw_capture_is_not_completion_acknowledgement():
    db = connect(":memory:")

    class Interrupted:
        def get_json(self, url):
            with db:
                evidence(db, response(), url)
            raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        collector.run(db, releases=["17.2.1"], client=Interrupted())
    resumed = collector.run(db, releases=["17.2.1"], client=client(db, Network()))
    assert resumed["counts"] == {"pending": 1}
    assert resumed["queries"][0]["error_code"] == "request_state_unresolved"
    assert not collector.results(db)


def test_interrupt_without_capture_fails_closed_and_preserves_pending_http():
    db = connect(":memory:")
    network = Network(KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        collector.run(db, releases=["17.2.1"], client=client(db, network))
    receipt = collector.run(db, releases=["17.2.1"], client=client(db, Network()))
    assert receipt["queries"][0]["error_code"] == "request_state_unresolved"
    assert db.execute("SELECT count(*) FROM switching_requests WHERE pending=1").fetchone()[0] == 1


def test_stub_exception_diagnostics_and_tracebacks_never_include_upstream_text():
    db = connect(":memory:")

    class Broken:
        def get_json(self, url):
            raise RuntimeError("SECRET_STUB_VALUE")

    result = collector.run(db, releases=["17.2.1"], client=Broken())
    assert result["queries"][0]["error_code"] == "collection_error"
    assert "SECRET_STUB_VALUE" not in json.dumps(result)


def test_unretained_stub_bytes_cannot_create_a_fabricated_source_receipt():
    db = connect(":memory:")

    class Unretained:
        def get_json(self, url):
            return response()

    result = collector.run(db, releases=["17.2.1"], client=Unretained())
    assert result["queries"][0]["error_code"] == "retained_response_missing"
    assert not collector.results(db)


@pytest.mark.parametrize("release", ["17.2.1?secret=x", "", "17.2.1\n", "١٧.2.1"])
def test_query_literals_are_bounded_and_never_export_arbitrary_input(release):
    with pytest.raises(ValueError, match="Invalid release selection"):
        collector.plan(connect(":memory:"), [release])


def test_cli_plan_status_offline_and_explicit_run(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("IMPACT_DATABASE", str(tmp_path / "explicit.sqlite3"))
    monkeypatch.setattr(collector, "CiscoOpenVuln", lambda *_: pytest.fail("network client"))
    cli.main(["cisco-first-fixed", "plan", "--release", "17.2.1", "--release", "17.2.1"])
    assert json.loads(capsys.readouterr().out)["counts"] == {"pending": 1}
    cli.main(["cisco-first-fixed", "status"])
    assert json.loads(capsys.readouterr().out)["counts"] == {"pending": 1}


def test_cli_run_default_bound_and_no_implicit_config_reads(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("IMPACT_DATABASE", str(tmp_path / "explicit.sqlite3"))
    seen = {}

    def run(db, **kwargs):
        seen.update(kwargs)
        return {"outcome": "test"}

    monkeypatch.setattr(collector, "run", run)
    cli.main(["cisco-first-fixed", "run", "--release", "17.2.1"])
    assert seen == {"releases": ["17.2.1"], "max_releases": 10}
    assert json.loads(capsys.readouterr().out) == {"outcome": "test"}


def test_http_accounting_survives_expired_quota_rows_and_id_pruning():
    db = connect(":memory:")
    clock = Clock()
    with db:
        db.execute(
            "INSERT INTO switching_requests(id,service,reserved_at,pending) VALUES(50,?,?,0)",
            ("cisco_openvuln", clock().timestamp() - 86401),
        )
    result = collector.run(
        db, releases=["17.2.1"], client=client(db, Network(token(), Response(response())), clock)
    )
    assert result["http_requests_reserved"] == 2


@pytest.mark.parametrize(
    "cves,products",
    [
        (["CVE-2026-12345", "CVE-2026-23456"], ["Cisco IOS XE Software"]),
        (["CVE-2026-12345"], ["Cisco IOS XE Software", "Cisco ASA Software"]),
        (["wrong"], ["Cisco IOS XE Software"]),
        (None, []),
    ],
)
def test_mixed_or_invalid_identity_never_binds_a_common_fact(cves, products):
    parsed = collector.parse_response(
        response(cves=cves, productNames=products), query_release="17.2.1"
    )
    assert parsed["first_fixed"] == []
    assert parsed["advisory_context"][0]["ownership_state"] == "ownership_unresolved"
    if cves in (None, ["wrong"]):
        assert parsed["advisory_context"][0]["cve_refs"] == []
        assert "cve_identity_unresolved" in parsed["issues"]


def test_two_advisory_rows_never_share_alternatives_or_owners():
    raw = json.dumps(
        {
            "advisories": [
                {
                    "advisoryId": "cisco-sa-first",
                    "firstFixed": ["17.2.2"],
                    "cves": ["CVE-2026-12345"],
                },
                {
                    "advisoryId": "cisco-sa-second",
                    "firstFixed": ["17.9.10"],
                    "cves": ["CVE-2026-23456"],
                },
            ]
        }
    ).encode()
    parsed = collector.parse_response(raw, query_release="17.2.1")
    assert [(c["advisory_id"], c["source_first_fixed"]) for c in parsed["advisory_context"]] == [
        ("cisco-sa-first", ["17.2.2"]),
        ("cisco-sa-second", ["17.9.10"]),
    ]
    assert parsed["first_fixed"] == []


@pytest.mark.parametrize("window,limit", [(1, 5), (60, 30), (86400, 5000)])
def test_logical_query_cannot_bypass_existing_committed_http_quota(window, limit):
    db = connect(":memory:")
    clock = Clock()
    with db:
        db.executemany(
            "INSERT INTO switching_requests(service,reserved_at,pending) VALUES(?,?,0)",
            [("cisco_openvuln", clock().timestamp() - window / 2)] * limit,
        )
    receipt = collector.run(db, releases=["17.2.1"], client=client(db, Network(), clock))
    assert receipt["counts"] == {"deferred": 1}
    assert receipt["http_requests_reserved"] == 0
    assert receipt["queries"][0]["error_code"] == "rate_limited"


def test_reflected_secret_rejected_by_real_transport_before_retention():
    db = connect(":memory:")
    network = Network(token(), Response(response(firstFixed=["SENTINEL_CLIENT_SECRET_7aa21"])))
    receipt = collector.run(db, releases=["17.2.1"], client=client(db, network))
    assert receipt["counts"] == {"error": 1}
    assert receipt["queries"][0]["error_code"] == "credential_response_rejected"
    assert db.execute("SELECT count(*) FROM evidence").fetchone()[0] == 0
    assert "SENTINEL" not in json.dumps(receipt)


def test_cli_requires_explicit_database_before_connecting(monkeypatch):
    monkeypatch.delenv("IMPACT_DATABASE", raising=False)
    with pytest.raises(SystemExit) as caught:
        cli.main(["cisco-first-fixed", "status"])
    assert caught.value.code == 2


@pytest.mark.parametrize("budget", [0, 101, True, -1])
def test_invalid_budget_has_no_queue_or_network_side_effects(budget):
    db = connect(":memory:")
    with pytest.raises(ValueError, match="Invalid release budget"):
        collector.run(db, releases=["17.2.1"], max_releases=budget)
    assert collector.status(db)["counts"] == {}


def test_additive_migration_adopts_015_database_without_mutating_existing_evidence(tmp_path):
    import sqlite3
    from pathlib import Path

    from infrastructure_impact.storage.migrations import migrate

    directory = tmp_path / "migrations"
    directory.mkdir()
    for path in Path("infrastructure_impact/migrations").glob("*.sql"):
        if int(path.name.split("_", 1)[0]) <= 15:
            (directory / path.name).write_bytes(path.read_bytes())
    db = sqlite3.connect(":memory:")
    migrate(db, directory)
    with db:
        db.execute(
            "INSERT INTO evidence(source_url,sha256,observed_at,raw,media_type) VALUES('https://example.test','sha','actual-time',X'01','test')"
        )
    migrate(db)
    assert db.execute("SELECT source_url,sha256,observed_at,raw FROM evidence").fetchone() == (
        "https://example.test",
        "sha",
        "actual-time",
        b"\x01",
    )
    assert db.execute("SELECT max(version) FROM schema_migrations").fetchone()[0] == 17


def test_observations_preserve_literal_array_order_and_duplicates():
    parsed = collector.parse_response(
        response(firstFixed=["17.2.2w", "17.2.2", "17.2.2w"]), query_release="17.2.1"
    )
    assert parsed["advisory_context"][0]["source_first_fixed"] == ["17.2.2w", "17.2.2", "17.2.2w"]
    assert "duplicate_first_fixed_literal" in parsed["issues"]


def test_client_construction_failure_uses_closed_diagnostic(monkeypatch):
    def broken_client(db):
        raise RuntimeError("PRIVATE_CONSTRUCTOR_MESSAGE")

    monkeypatch.setattr(collector, "CiscoOpenVuln", broken_client)
    result = collector.run(connect(":memory:"), releases=["17.2.1"])
    assert result["queries"][0]["error_code"] == "collection_error"
    assert "PRIVATE_CONSTRUCTOR_MESSAGE" not in json.dumps(result)


def test_old_same_url_capture_does_not_resolve_unknown_current_request():
    from infrastructure_impact.storage.switching import SERVICE, reserve_request

    db = connect(":memory:")
    collector.plan(db, ["17.2.1"])
    with db:
        captured = evidence(db, response(), URL)
        db.execute(
            "UPDATE evidence SET observed_at='2020-01-01T00:00:00+00:00' WHERE id=?",
            (captured["id"],),
        )
        db.execute("UPDATE cisco_first_fixed_queries SET started=1")
    reserve_request(db, SERVICE, Clock()().isoformat(), pending=True)
    result = collector.run(db, releases=["17.2.1"], client=client(db, Network()))
    assert result["counts"] == {"pending": 1}
    assert result["queries"][0]["error_code"] == "request_state_unresolved"
    assert result["http_requests_reserved"] == 0
    assert not collector.results(db)
    assert db.execute("SELECT pending FROM switching_requests").fetchone()[0] == 1


@pytest.mark.parametrize("old_raw,old_url", [(b"not json", URL), (response(), URL + "0")])
def test_old_invalid_or_unrelated_capture_cannot_prevent_current_fetch(old_raw, old_url):
    db = connect(":memory:")
    with db:
        evidence(db, old_raw, old_url)
    network = Network(token(), Response(response()))
    result = collector.run(db, releases=["17.2.1"], client=client(db, network))
    assert result["counts"] == {"success": 1}
    assert result["http_requests_reserved"] == 2
    assert collector.results(db)[0]["source"]["sha256"] == hashlib.sha256(response()).hexdigest()


def test_current_successful_same_body_call_acknowledges_deduplicated_old_capture():
    db = connect(":memory:")
    with db:
        old = evidence(db, response(), URL)
        db.execute(
            "UPDATE evidence SET observed_at='2020-01-01T00:00:00+00:00' WHERE id=?", (old["id"],)
        )
    network = Network(token(), Response(response()))
    result = collector.run(db, releases=["17.2.1"], client=client(db, network))
    assert result["http_requests_reserved"] == 2
    frame = collector.results(db)[0]
    assert frame["source"]["evidence_id"] == old["id"]
    assert frame["source"]["retrieved_at"] == "2020-01-01T00:00:00+00:00"
    row = db.execute("SELECT * FROM cisco_first_fixed_queries").fetchone()
    assert row["response_attempt"] == row["attempt"] == 1
    assert row["response_evidence_id"] == old["id"]
    assert row["response_acknowledged_at"] != frame["source"]["retrieved_at"]


def test_interruption_after_completed_call_receipt_recovers_without_refetch(monkeypatch, tmp_path):
    path = tmp_path / "receipts.sqlite3"
    owner = connect(path)
    original_accept = collector._accept

    def interrupted(*args):
        raise KeyboardInterrupt()

    monkeypatch.setattr(collector, "_accept", interrupted)
    with pytest.raises(KeyboardInterrupt):
        collector.run(
            owner, releases=["17.2.1"], client=client(owner, Network(token(), Response(response())))
        )
    owner.close()
    monkeypatch.setattr(collector, "_accept", original_accept)
    resumed = connect(path)
    result = collector.run(resumed, releases=["17.2.1"], client=client(resumed, Network()))
    assert result["counts"] == {"success": 1}
    assert result["http_requests_reserved"] == 0
    assert len(collector.results(resumed)) == 1
    assert (
        collector.run(resumed, releases=["17.2.1"], client=client(resumed, Network()))[
            "release_queries_attempted"
        ]
        == 0
    )


def test_second_connection_cannot_complete_live_post_capture_owner_then_late_failure(tmp_path):
    from infrastructure_impact.storage.switching import SERVICE, reserve_request

    path = tmp_path / "two-connections.sqlite3"
    owner, other = connect(path), connect(path)
    observed = {}

    class LiveOwner:
        def get_json(self, url):
            reserve_request(owner, SERVICE, Clock()().isoformat(), pending=True)
            with owner:
                evidence(owner, response(), url)
            before = dict(other.execute("SELECT * FROM cisco_first_fixed_queries").fetchone())
            observed["other_run"] = collector.run(
                other, releases=["17.2.1"], client=client(other, Network())
            )
            after = dict(other.execute("SELECT * FROM cisco_first_fixed_queries").fetchone())
            observed["claims"] = before["started"], after["started"]
            observed["pending"] = other.execute(
                "SELECT pending FROM switching_requests"
            ).fetchone()[0]
            observed["results"] = collector.results(other)
            raise RuntimeError("PRIVATE_POST_RETENTION_FAILURE")

    result = collector.run(owner, releases=["17.2.1"], client=LiveOwner())
    assert observed["other_run"]["counts"] == {"pending": 1}
    assert observed["claims"] == (1, 1)
    assert observed["pending"] == 1 and observed["results"] == []
    assert result["counts"] == {"error": 1}
    assert result["queries"][0]["error_code"] == "collection_error"
    assert owner.execute("SELECT pending FROM switching_requests").fetchone()[0] == 1


def test_stale_owner_cannot_overwrite_recovered_receipt_or_new_attempt(tmp_path):
    from infrastructure_impact.storage import cisco_first_fixed as work

    path = tmp_path / "stale-owner.sqlite3"
    owner, other = connect(path), connect(path)
    collector.plan(owner, ["17.2.1"])
    attempt1 = work.start(owner, URL)
    assert work.outcome(owner, URL, attempt1, "error", error_code="collection_error")
    attempt2 = work.start(other, URL)
    assert attempt2 != attempt1
    assert not work.outcome(owner, URL, attempt1, "error", error_code="collection_error")
    assert other.execute("SELECT started FROM cisco_first_fixed_queries").fetchone()[0] == 1
    with other:
        captured = evidence(other, response(), URL)
    assert not work.acknowledge(owner, URL, attempt1, captured["id"])
    assert not work.accepted(owner, URL, attempt1, captured["id"], "old-parser", {})
    work.unknown(owner, URL, attempt1)
    assert other.execute("SELECT error_code FROM cisco_first_fixed_queries").fetchone()[0] is None
    assert work.acknowledge(other, URL, attempt2, captured["id"])
    result = collector.run(owner, releases=["17.2.1"], client=client(owner, Network()))
    assert result["counts"] == {"success": 1}
    assert not work.outcome(other, URL, attempt2, "error", error_code="collection_error")
    assert not work.outcome(owner, URL, attempt1, "error", error_code="collection_error")
    assert collector.status(owner)["counts"] == {"success": 1}
    assert len(collector.results(other)) == 1


def test_parser_error_receipt_does_not_block_next_generation_fetch():
    db = connect(":memory:")
    network = Network(
        token(), Response(b'{"advisoryId":"cisco-sa-authored"}'), Response(response())
    )
    transport = client(db, network)
    first = collector.run(db, releases=["17.2.1"], client=transport)
    assert first["counts"] == {"error": 1}
    assert first["queries"][0]["error_code"] == "unsupported_response"
    second = collector.run(db, releases=["17.2.1"], client=transport)
    assert second["counts"] == {"success": 1}
    assert second["http_requests_reserved"] == 1
    assert db.execute("SELECT attempt FROM cisco_first_fixed_queries").fetchone()[0] == 2


def test_migration_017_does_not_invent_receipt_for_legacy_success(tmp_path):
    import sqlite3
    from pathlib import Path

    from infrastructure_impact.storage.migrations import migrate

    directory = tmp_path / "legacy-migrations"
    directory.mkdir()
    for path in Path("infrastructure_impact/migrations").glob("*.sql"):
        if int(path.name.split("_", 1)[0]) <= 16:
            (directory / path.name).write_bytes(path.read_bytes())
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    migrate(db, directory)
    with db:
        captured = evidence(db, response(), URL)
        db.execute(
            "INSERT INTO cisco_first_fixed_queries(url,os_type,query_release,state,evidence_id,result_json) VALUES(?,'iosxe','17.2.1','success',?,'{}')",
            (URL, captured["id"]),
        )
    migrate(db)
    result = collector.run(db, releases=["17.2.1"], client=client(db, Network()))
    assert result["counts"] == {"pending": 1}
    assert result["queries"][0]["error_code"] == "request_state_unresolved"
    assert result["http_requests_reserved"] == 0
    assert not collector.results(db)
    assert (
        db.execute("SELECT response_evidence_id FROM cisco_first_fixed_queries").fetchone()[0]
        is None
    )
