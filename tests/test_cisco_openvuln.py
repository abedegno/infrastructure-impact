"""Offline credential-boundary and persistent rolling-quota acceptance tests."""

import json
import sqlite3
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from io import BytesIO
from threading import Barrier, Event, Timer
from time import monotonic
from urllib.error import HTTPError
from urllib.parse import parse_qs

import pytest

from infrastructure_impact.collection.cisco_openvuln import CiscoOpenVuln
from infrastructure_impact.collection.errors import CiscoAccessError, failure_code
from infrastructure_impact.storage.migrations import migrate
from infrastructure_impact.storage.repository import connect
from infrastructure_impact.storage.switching import load_cursor, reserve_request, save_cursor

URL = "https://apix.cisco.com/security/advisories/v2/all?pageIndex=1&pageSize=100"
TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
SECRET = "SENTINEL_CLIENT_SECRET_7aa21"
TOKEN = "SENTINEL_ACCESS_TOKEN_8bb32"
ENV = {"CISCO_OPENVULN_CLIENT_ID": "fake-client", "CISCO_OPENVULN_CLIENT_SECRET": SECRET}
START = datetime(2026, 11, 4, tzinfo=timezone.utc)
DOCUMENT = b'{"advisories":[{"advisoryId":"cisco-sa-synthetic"}]}'
SERVICE = "cisco_openvuln"


class Clock:
    def __init__(self):
        self.at = START

    def __call__(self):
        return self.at

    def advance(self, seconds):
        self.at += timedelta(seconds=seconds)


class Response(BytesIO):
    def __init__(self, raw, status=200, headers=None, url=None):
        super().__init__(raw)
        self.status = status
        self.headers = headers or {"Content-Type": "application/json"}
        self.url = url

    def geturl(self):
        return self.url


def token(value=TOKEN, expires=3600):
    return Response(
        json.dumps(dict(access_token=value, token_type="Bearer", expires_in=expires)).encode()
    )


def http(status, headers=None):
    return HTTPError(URL, status, SECRET + TOKEN, headers or {}, BytesIO((SECRET + TOKEN).encode()))


class Network:
    """Only the socket boundary is fake; redirects use the production handler."""

    def __init__(self, *results, db=None, on_api=None):
        self.results = list(results)
        self.calls = []
        self.handlers = []
        self.db = db
        self.on_api = on_api

    def factory(self, handler):
        session = len(self.handlers)
        self.handlers.append(handler)
        network = self

        class Session:
            def open(self, request, timeout):
                assert timeout == 25
                # A second connection must see the reservation before any I/O.
                if network.db:
                    with sqlite3.connect(network.db) as reader:
                        assert reader.execute("SELECT count(*) FROM switching_requests").fetchone()[
                            0
                        ] > len(network.calls)
                network.calls.append((session, request))
                if request.full_url == URL and network.on_api:
                    network.on_api()
                result = network.results.pop(0)
                if isinstance(result, BaseException):
                    raise result
                return result

        return Session()


def client(db, network, clock=None, environ=None):
    return CiscoOpenVuln(
        db,
        environ=ENV if environ is None else environ,
        opener=network.factory,
        clock=clock or Clock(),
    )


def rejected(transport, code, url=URL):
    with pytest.raises(CiscoAccessError) as caught:
        transport.get_json(url)
    assert caught.value.code == code
    assert failure_code(caught.value) == code
    return caught.value


def test_missing_credentials_is_safe_and_makes_no_request():
    db = connect(":memory:")
    network = Network()
    rejected(client(db, network, environ={}), "auth_not_configured")
    assert not network.calls


def test_separate_sessions_refresh_expiry_and_retain_only_api_bytes(tmp_path):
    path = tmp_path / "vault.db"
    db = connect(path)
    clock = Clock()
    network = Network(
        token(expires=2),
        Response(DOCUMENT),
        Response(DOCUMENT),
        token("second-token"),
        Response(DOCUMENT),
        db=path,
    )
    transport = client(db, network, clock)
    assert transport.get_json(URL) == DOCUMENT
    clock.advance(1)
    assert transport.get_json(URL) == DOCUMENT
    clock.advance(2)
    assert transport.get_json(URL) == DOCUMENT
    requests = [r for _, r in network.calls]
    assert [r.full_url for r in requests] == [TOKEN_URL, URL, URL, TOKEN_URL, URL]
    assert network.calls[0][0] != network.calls[1][0]
    assert parse_qs(requests[0].data.decode()) == {
        "client_id": ["fake-client"],
        "client_secret": [SECRET],
        "grant_type": ["client_credentials"],
    }
    assert requests[1].get_header("Authorization") == "Bearer " + TOKEN
    assert requests[-1].get_header("Authorization") == "Bearer second-token"
    assert not requests[0].has_header("Authorization")
    assert [r[0] for r in db.execute("SELECT raw FROM evidence")] == [DOCUMENT]
    assert db.execute("SELECT count(*) FROM http_cache").fetchone()[0] == 0
    db.close()
    assert SECRET.encode() not in path.read_bytes() and TOKEN.encode() not in path.read_bytes()


@pytest.mark.parametrize("last,want", [(Response(DOCUMENT), None), (http(401), "auth_rejected")])
def test_only_one_401_refresh_is_attempted(last, want):
    db = connect(":memory:")
    network = Network(token(), http(401), token("replacement-token"), last)
    transport = client(db, network)
    if want:
        rejected(transport, want)
    else:
        assert transport.get_json(URL) == DOCUMENT
    assert len(network.calls) == 4
    assert db.execute("SELECT count(*) FROM switching_requests").fetchone()[0] == 4


def test_403_is_terminal_without_refresh_or_evidence():
    db = connect(":memory:")
    network = Network(token(), http(403))
    rejected(client(db, network), "access_denied")
    assert len(network.calls) == 2
    assert db.execute("SELECT count(*) FROM evidence").fetchone()[0] == 0


@pytest.mark.parametrize("retry", ["120", "Wed, 04 Nov 2026 00:02:00 GMT"])
def test_429_cooldown_survives_restart_and_prevents_new_token_request(tmp_path, retry):
    path = tmp_path / "vault.db"
    db = connect(path)
    clock = Clock()
    network = Network(token(), http(429, {"Retry-After": retry}))
    error = rejected(client(db, network, clock), "rate_limited")
    assert error.retry_at == "2026-11-04T00:02:00+00:00"
    db.close()
    db = connect(path)
    network = Network(token(), Response(DOCUMENT))
    transport = client(db, network, clock)
    rejected(transport, "rate_limited")
    assert not network.calls
    clock.advance(120)
    assert transport.get_json(URL) == DOCUMENT


def test_5xx_and_timeout_use_persisted_exponential_backoff():
    db = connect(":memory:")
    clock = Clock()
    network = Network(token(), http(503), TimeoutError(SECRET + TOKEN), Response(DOCUMENT))
    transport = client(db, network, clock)
    assert rejected(transport, "service_unavailable").retry_at == "2026-11-04T00:00:01+00:00"
    rejected(transport, "rate_limited")
    clock.advance(1)
    assert rejected(transport, "network_error").retry_at == "2026-11-04T00:00:03+00:00"
    clock.advance(2)
    assert transport.get_json(URL) == DOCUMENT
    assert len(network.calls) == 4


@pytest.mark.parametrize(
    "result, expected, retry_at",
    [
        (http(429, {"Retry-After": "120"}), "rate_limited", "2026-11-04T00:02:00+00:00"),
        (http(503), "service_unavailable", "2026-11-04T00:00:01+00:00"),
        (TimeoutError(SECRET + TOKEN), "network_error", "2026-11-04T00:00:01+00:00"),
    ],
)
@pytest.mark.parametrize("brief_lock", [True, False])
def test_concurrent_writer_never_drops_received_cooldown(
    tmp_path, result, expected, retry_at, brief_lock
):
    path = tmp_path / "vault.db"
    db = connect(path)
    ready, begin, held, release = Event(), Event(), Event(), Event()

    def writer():
        connection = connect(path)
        ready.set()
        try:
            assert begin.wait(3)
            connection.execute("BEGIN IMMEDIATE")
            held.set()
            assert release.wait(3)
        finally:
            connection.rollback()
            connection.close()

    def lock_at_response():
        begin.set()
        assert held.wait(3)
        if brief_lock:
            Timer(0.05, release.set).start()

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending_writer = pool.submit(writer)
        assert ready.wait(3)
        network = Network(token(), result, on_api=lock_at_response)
        started = monotonic()
        try:
            error = rejected(
                client(db, network), expected if brief_lock else "request_state_unresolved"
            )
            assert monotonic() - started < 1
            assert error.__context__ is None and error.__cause__ is None
            assert SECRET not in str(error) and TOKEN not in str(error)
            if brief_lock:
                assert error.retry_at == retry_at
        finally:
            release.set()
        pending_writer.result(timeout=3)
    db.close()
    db = connect(path)
    if brief_lock:
        assert reserve_request(db, SERVICE, START.isoformat()) == dict(
            allowed=False, retry_at=retry_at
        )
    else:
        # Unknown completion cannot expire automatically, even once ordinary quota windows pass.
        assert reserve_request(db, SERVICE, (START + timedelta(days=2)).isoformat()) == dict(
            allowed=False, retry_at=None
        )
        reopened = Network()
        rejected(client(db, reopened), "request_state_unresolved")
        assert not reopened.calls


def test_brief_reservation_contention_cannot_clear_another_callers_cooldown(tmp_path):
    from infrastructure_impact.storage.switching import defer_request

    path = tmp_path / "vault.db"
    db = connect(path)
    defer_request(db, SERVICE, START.isoformat(), retry_at="2026-11-04T00:02:00+00:00")
    other = connect(path)
    other.execute("BEGIN IMMEDIATE")
    try:
        assert not reserve_request(db, SERVICE, START.isoformat())["allowed"]
    finally:
        other.rollback()
        other.close()
    db.close()
    db = connect(path)
    assert reserve_request(db, SERVICE, START.isoformat()) == dict(
        allowed=False, retry_at="2026-11-04T00:02:00+00:00"
    )


def test_completion_is_per_request_and_cannot_clear_another_cooldown():
    from infrastructure_impact.storage.switching import (
        complete_request,
        defer_request,
        pending_requests,
    )

    db = connect(":memory:")
    reservation = reserve_request(db, SERVICE, START.isoformat(), pending=True)
    request_id = reservation["request_id"]
    assert pending_requests(db, SERVICE) == [
        dict(request_id=request_id, reserved_at=START.isoformat())
    ]
    assert not complete_request(db, SERVICE, request_id + 1)
    assert reserve_request(db, SERVICE, START.isoformat()) == dict(allowed=False, retry_at=None)
    until = defer_request(db, SERVICE, START.isoformat(), retry_at="2026-11-04T00:02:00+00:00")
    assert until == "2026-11-04T00:02:00+00:00"
    assert complete_request(db, SERVICE, request_id)
    assert pending_requests(db, SERVICE) == []
    assert reserve_request(db, SERVICE, START.isoformat()) == dict(allowed=False, retry_at=until)


def test_explicit_recovery_must_persist_cooldown_and_resolve_only_named_request():
    from infrastructure_impact.storage.switching import defer_request, pending_requests

    db = connect(":memory:")
    request_id = reserve_request(db, SERVICE, START.isoformat(), pending=True)["request_id"]
    assert defer_request(db, SERVICE, START.isoformat(), reservation_id=request_id + 1) is None
    assert pending_requests(db, SERVICE)[0]["request_id"] == request_id
    until = defer_request(
        db,
        SERVICE,
        START.isoformat(),
        retry_at="2026-11-04T00:02:00+00:00",
        reservation_id=request_id,
    )
    assert pending_requests(db, SERVICE) == []
    assert reserve_request(db, SERVICE, START.isoformat()) == dict(allowed=False, retry_at=until)


def test_stale_completion_id_cannot_resolve_a_new_request_after_quota_pruning():
    from infrastructure_impact.storage.switching import complete_request, pending_requests

    db = connect(":memory:")
    original = reserve_request(db, SERVICE, START.isoformat(), pending=True)["request_id"]
    assert complete_request(db, SERVICE, original)
    newer = reserve_request(db, SERVICE, (START + timedelta(days=2)).isoformat(), pending=True)[
        "request_id"
    ]
    assert newer != original
    assert not complete_request(db, SERVICE, original)
    assert pending_requests(db, SERVICE)[0]["request_id"] == newer


@pytest.mark.parametrize(
    "body,code",
    [
        (b"x" * 8_000_001, "response_too_large"),
        (b"{bad", "invalid_json"),
        (b'{"unknown": []}', "unsupported_response"),
        (b'{"access_token":"oops"}', "unsupported_response"),
        (
            json.dumps({"advisories": [{"advisoryId": "x", "summary": SECRET + TOKEN}]}).encode(),
            "credential_response_rejected",
        ),
        (
            json.dumps(
                {"advisories": [{"advisoryId": "x", "client_secret": "unrecognized"}]}
            ).encode(),
            "credential_response_rejected",
        ),
    ],
)
def test_unclassified_and_credential_shaped_successes_are_not_retained(body, code):
    db = connect(":memory:")
    network = Network(token(), Response(body))
    rejected(client(db, network), code)
    assert db.execute("SELECT count(*) FROM evidence").fetchone()[0] == 0


@pytest.mark.parametrize(
    "payload",
    [
        {"access_token": TOKEN, "token_type": 3, "expires_in": 3600},
        {"access_token": TOKEN, "token_type": "Bearer", "expires_in": 10**400},
        {"access_token": TOKEN, "token_type": "Bearer", "expires_in": True},
        {"access_token": "x\r\nAuthorization: bad", "token_type": "Bearer", "expires_in": 3600},
        {"access_token": TOKEN, "token_type": "Bearer", "expires_in": 0},
    ],
)
def test_malformed_token_fields_fail_safely_without_api_or_storage(payload):
    db = connect(":memory:")
    network = Network(Response(json.dumps(payload).encode()))
    rejected(client(db, network), "auth_rejected")
    assert len(network.calls) == 1
    assert db.execute("SELECT count(*) FROM evidence").fetchone()[0] == 0


def test_refreshed_transport_rejects_echoes_of_previous_tokens():
    db = connect(":memory:")
    clock = Clock()
    echo = json.dumps({"advisories": [], "summary": TOKEN}).encode()
    network = Network(
        token(expires=1), Response(DOCUMENT), token("replacement-token"), Response(echo)
    )
    transport = client(db, network, clock)
    assert transport.get_json(URL) == DOCUMENT
    clock.advance(2)
    rejected(transport, "credential_response_rejected")
    assert db.execute("SELECT count(*) FROM evidence").fetchone()[0] == 1


def test_escaped_secret_echo_and_deep_credential_fields_are_rejected():
    secret = 'quote"and\\slash'
    env = dict(ENV, CISCO_OPENVULN_CLIENT_SECRET=secret)
    nested = {"client_secret": "another-secret"}
    for _ in range(400):
        nested = [nested]
    for value in (secret, nested):
        db = connect(":memory:")
        body = json.dumps({"advisories": [], "metadata": value}).encode()
        network = Network(token(), Response(body))
        rejected(client(db, network, environ=env), "credential_response_rejected")
        assert db.execute("SELECT count(*) FROM evidence").fetchone()[0] == 0


def test_token_size_is_bounded_and_auth_redirects_are_never_followed():
    for result, expected in (
        (Response(b"x" * 64_001), "response_too_large"),
        (http(307, {"Location": "https://tools.cisco.com/"}), "redirect_rejected"),
    ):
        db = connect(":memory:")
        network = Network(result)
        rejected(client(db, network), expected)
        assert len(network.calls) == 1
        assert db.execute("SELECT count(*) FROM evidence").fetchone()[0] == 0


def test_duplicate_json_members_cannot_hide_escaped_credential_echoes():
    escaped = "".join("\\u%04x" % ord(character) for character in TOKEN)
    raw = ('{"advisories":[],"summary":"' + escaped + '","summary":"safe"}').encode()
    db = connect(":memory:")
    rejected(client(db, Network(token(), Response(raw))), "invalid_json")
    assert db.execute("SELECT count(*) FROM evidence").fetchone()[0] == 0


def test_token_attempt_timeout_also_commits_quota_and_persisted_backoff():
    db = connect(":memory:")
    clock = Clock()
    network = Network(TimeoutError(SECRET + TOKEN))
    transport = client(db, network, clock)
    error = rejected(transport, "network_error")
    assert error.retry_at == "2026-11-04T00:00:01+00:00"
    assert error.__context__ is None
    assert db.execute("SELECT count(*) FROM switching_requests").fetchone()[0] == 1
    rejected(transport, "rate_limited")
    assert len(network.calls) == 1


def test_final_response_url_must_match_even_for_an_injected_opener():
    db = connect(":memory:")
    network = Network(token(), Response(DOCUMENT, url="https://tools.cisco.com/other"))
    rejected(client(db, network), "redirect_rejected")
    assert db.execute("SELECT count(*) FROM evidence").fetchone()[0] == 0


def test_an_interrupted_request_keeps_its_precommitted_reservation(tmp_path):
    path = tmp_path / "vault.db"
    db = connect(path)
    with pytest.raises(KeyboardInterrupt):
        client(db, Network(KeyboardInterrupt())).get_json(URL)
    db.close()
    db = connect(path)
    assert db.execute("SELECT count(*) FROM switching_requests").fetchone()[0] == 1
    assert reserve_request(db, SERVICE, (START + timedelta(days=2)).isoformat()) == dict(
        allowed=False, retry_at=None
    )
    assert db.execute("SELECT count(*) FROM switching_requests WHERE pending=1").fetchone()[0] == 1


def test_migration_012_adopts_existing_quota_and_cooldown_without_inventing_pending(tmp_path):
    from pathlib import Path

    directory = tmp_path / "migrations"
    directory.mkdir()
    for file in Path("infrastructure_impact/migrations").glob("*.sql"):
        if int(file.name.split("_", 1)[0]) < 12:
            (directory / file.name).write_bytes(file.read_bytes())
    db = sqlite3.connect(":memory:")
    migrate(db, directory)
    db.execute(
        "INSERT INTO switching_requests(service,reserved_at) VALUES(?,?)",
        (SERVICE, START.timestamp()),
    )
    db.execute(
        "INSERT INTO switching_service_state VALUES(?,?,?)",
        (SERVICE, (START + timedelta(seconds=120)).timestamp(), 1),
    )
    db.commit()
    migrate(db)
    assert db.execute("SELECT reserved_at,pending FROM switching_requests").fetchone() == (
        START.timestamp(),
        0,
    )
    assert reserve_request(db, SERVICE, START.isoformat()) == dict(
        allowed=False, retry_at="2026-11-04T00:02:00+00:00"
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://api.cisco.com/security/advisories/v2/all",
        "https://tools.cisco.com/security/advisories/v2/all",
        "http://apix.cisco.com/security/advisories/v2/all",
        "https://user:password@apix.cisco.com/security/advisories/v2/all",
        "https://apix.cisco.com:444/security/advisories/v2/all",
        "https://apix.cisco.com/other",
        "https://apix.cisco.com/security/advisories/v2/all?access_token=secret",
    ],
)
def test_only_exact_reviewed_https_api_urls_can_receive_bearer(url):
    network = Network()
    rejected(client(connect(":memory:"), network), "url_rejected", url)
    assert not network.calls


@pytest.mark.parametrize(
    "target",
    [
        "https://tools.cisco.com/security/other",
        "http://apix.cisco.com/security/advisories/v2/all",
        "https://user@apix.cisco.com/security/advisories/v2/all",
        URL,
    ],
)
def test_authenticated_sessions_reject_every_redirect(target):
    network = Network(token(), http(302, {"Location": target}))
    transport = client(connect(":memory:"), network)
    rejected(transport, "redirect_rejected")
    for handler in network.handlers:
        with pytest.raises(CiscoAccessError) as caught:
            handler.redirect_request(None, None, 302, SECRET, {}, target)
        assert caught.value.code == "redirect_rejected"
    assert len(network.calls) == 2


@pytest.mark.parametrize("auth", [True, False])
def test_reflected_errors_never_escape_exceptions_logs_or_database(tmp_path, caplog, auth):
    path = tmp_path / "vault.db"
    db = connect(path)
    network = Network(http(400)) if auth else Network(token(), http(400))
    error = rejected(client(db, network), "auth_rejected" if auth else "http_error")
    diagnostic = str(error) + repr(error) + "".join(traceback.format_exception(error)) + caplog.text
    assert error.__context__ is None and error.__cause__ is None
    assert SECRET not in diagnostic and TOKEN not in diagnostic
    assert db.execute("SELECT count(*) FROM evidence").fetchone()[0] == 0
    assert SECRET not in "\n".join(db.iterdump()) and TOKEN not in "\n".join(db.iterdump())
    db.close()
    for file in tmp_path.iterdir():
        assert SECRET.encode() not in file.read_bytes() and TOKEN.encode() not in file.read_bytes()


def test_reservations_enforce_all_three_rolling_windows():
    db = connect(":memory:")
    for _ in range(5):
        assert reserve_request(db, SERVICE, START.isoformat())["allowed"]
    assert reserve_request(db, SERVICE, START.isoformat()) == dict(
        allowed=False, retry_at="2026-11-04T00:00:01+00:00"
    )
    for second in range(1, 6):
        for _ in range(5):
            assert reserve_request(db, SERVICE, (START + timedelta(seconds=second)).isoformat())[
                "allowed"
            ]
    assert reserve_request(db, SERVICE, (START + timedelta(seconds=6)).isoformat()) == dict(
        allowed=False, retry_at="2026-11-04T00:01:00+00:00"
    )
    # 5000 calls spread across a day avoid independently tripping second/minute caps.
    db = connect(":memory:")
    for request in range(5000):
        assert reserve_request(db, SERVICE, (START + timedelta(seconds=17 * request)).isoformat())[
            "allowed"
        ]
    assert reserve_request(db, SERVICE, (START + timedelta(seconds=85000)).isoformat()) == dict(
        allowed=False, retry_at="2026-11-05T00:00:00+00:00"
    )
    assert reserve_request(db, SERVICE, (START + timedelta(days=1)).isoformat())["allowed"]


def test_reopened_and_concurrent_connections_cannot_reuse_reservations(tmp_path):
    path = tmp_path / "vault.db"
    db = connect(path)
    for _ in range(4):
        assert reserve_request(db, SERVICE, START.isoformat())["allowed"]
    db.close()
    barrier = Barrier(2)

    def attempt(_):
        connection = connect(path)
        barrier.wait()
        result = reserve_request(connection, SERVICE, START.isoformat())
        connection.close()
        return result["allowed"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt, range(2))) == [False, True]
    db = connect(path)
    assert not reserve_request(db, SERVICE, START.isoformat())["allowed"]


def test_cursor_windows_are_independent_typed_persistent_state(tmp_path):
    path = tmp_path / "vault.db"
    db = connect(path)
    save_cursor(db, SERVICE, window_start="2021-01-01", window_end="2022-01-01", page_index=7)
    save_cursor(db, SERVICE, window_start="2022-01-01", window_end="2023-01-01", page_index=2)
    db.close()
    db = connect(path)
    assert (
        load_cursor(db, SERVICE, window_start="2021-01-01", window_end="2022-01-01")["page_index"]
        == 7
    )
    assert (
        load_cursor(db, SERVICE, window_start="2022-01-01", window_end="2023-01-01")["page_index"]
        == 2
    )
    assert load_cursor(db, SERVICE, window_start="2023-01-01", window_end="2024-01-01") is None
    with pytest.raises(ValueError):
        save_cursor(db, SERVICE, window_start=SECRET, window_end="2022-01-01", page_index=7)


@pytest.mark.parametrize("nonempty", [False, True])
def test_migration_preserves_existing_vault_rows(tmp_path, nonempty):
    from pathlib import Path

    directory = tmp_path / "migrations"
    directory.mkdir()
    for file in Path("infrastructure_impact/migrations").glob("*.sql"):
        if int(file.name.split("_", 1)[0]) < 11:
            (directory / file.name).write_bytes(file.read_bytes())
    db = sqlite3.connect(":memory:")
    migrate(db, directory)
    if nonempty:
        db.execute(
            "INSERT INTO evidence(source_url,sha256,observed_at,raw,media_type) VALUES('https://example.test','digest','2021-01-01',X'7B7D','application/json')"
        )
        db.execute(
            "INSERT INTO revisions(evidence_id,vendor,advisory_id,source_url,observed_at,normalized) VALUES(1,'cisco','synthetic','https://example.test','2021-01-01','{}')"
        )
        db.commit()
    before = list(db.execute("SELECT * FROM revisions"))
    migrate(db)
    assert list(db.execute("SELECT * FROM revisions")) == before
    assert reserve_request(db, SERVICE, START.isoformat())["allowed"]


@pytest.mark.parametrize(
    "values",
    [
        {"CISCO_OPENVULN_CLIENT_ID": "synthetic-id"},
        {"CISCO_OPENVULN_CLIENT_SECRET": "synthetic-secret"},
    ],
)
def test_partial_credentials_are_safe_without_request_or_reservation(values):
    db = connect(":memory:")
    network = Network()
    rejected(client(db, network, environ=values), "auth_not_configured")
    assert not network.calls
    assert db.execute("SELECT count(*) FROM switching_requests").fetchone()[0] == 0
    db.close()
