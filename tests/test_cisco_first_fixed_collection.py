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


def test_interrupt_after_accepted_capture_resumes_offline_without_refetch():
    db = connect(":memory:")

    class Interrupted:
        def get_json(self, url):
            with db:
                evidence(db, response(), url)
            raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        collector.run(db, releases=["17.2.1"], client=Interrupted())
    assert collector.run(db, releases=["17.2.1"], client=client(db, Network()))["counts"] == {
        "success": 1
    }
    assert len(collector.results(db)) == 1


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
    assert db.execute("SELECT max(version) FROM schema_migrations").fetchone()[0] == 16


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
