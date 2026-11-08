"""Offline transport boundaries for an explicitly bounded import operation."""

from contextlib import closing
from http.client import IncompleteRead
from io import BytesIO
from urllib.error import HTTPError

import pytest

from infrastructure_impact.collection import transport
from infrastructure_impact.storage.repository import connect, evidence

URL = "https://www.arista.com/assets/data/synthetic-one.json"
OTHER = "https://www.arista.com/assets/data/synthetic-two.json"


class Response(BytesIO):
    headers = {"Content-Type": "application/json"}
    status = 200


@pytest.fixture
def db(tmp_path):
    with closing(connect(tmp_path / "synthetic.sqlite")) as connection:
        yield connection


@pytest.fixture
def install(monkeypatch):
    """Replace the network boundary while retaining retrieval and database behavior."""

    def setup(*outcomes):
        calls = []
        pending = iter(outcomes)

        class Opener:
            def open(self, request, timeout):
                calls.append((request.full_url, timeout))
                outcome = next(pending)
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome

        monkeypatch.setattr(transport, "build_opener", lambda *_: Opener())
        monkeypatch.setattr(transport.time, "sleep", lambda _: None)
        return calls

    return setup


def budget(attempts=348, received=80_000_000):
    from infrastructure_impact.collection.transport_budget import TransportBudget

    return TransportBudget(attempts, received)


def retrieve(db, shared, **kwargs):
    kwargs.setdefault("forbid_redirects", True)
    return transport.fetch(db, URL, "arista", budget=shared, **kwargs)


@pytest.mark.parametrize("destination", [URL, OTHER, "https://example.com/not-allowed"])
def test_refuses_every_redirect_before_a_second_open(db, monkeypatch, destination):
    calls = []

    def build(handler):
        class Opener:
            def open(self, request, timeout):
                calls.append(request.full_url)
                next_request = handler.redirect_request(
                    request, None, 302, "Found", {}, destination
                )
                calls.append(next_request.full_url)
                return Response(b"wrong")

        return Opener()

    monkeypatch.setattr(transport, "build_opener", build)
    shared = budget()
    with pytest.raises(ValueError, match="redirect"):
        retrieve(db, shared, forbid_redirects=True, allowed_urls=frozenset({URL, OTHER}))
    assert calls == [URL]
    assert shared.attempts == 1


@pytest.mark.parametrize("size", [2_999_999, 3_000_000, 3_000_001])
def test_document_size_boundary(db, install, size):
    raw = b"x" * size
    install(Response(raw))
    shared = budget()
    if size > 3_000_000:
        with pytest.raises(ValueError, match="Document exceeds"):
            retrieve(db, shared, max_bytes=3_000_000)
        assert db.execute("SELECT COUNT(*) FROM http_cache").fetchone()[0] == 0
    else:
        assert retrieve(db, shared, max_bytes=3_000_000) == raw
    assert shared.received_bytes == size


@pytest.mark.parametrize("size", [3_000_000, 3_000_001])
def test_cached_documents_still_obey_document_limit(db, install, size):
    raw = b"x" * size
    retained = evidence(db, raw, URL)
    db.execute("INSERT INTO http_cache VALUES(?,?,?,?)", (URL, "tag", None, retained["id"]))
    db.commit()
    calls = install(HTTPError(URL, 304, "Not modified", {}, BytesIO()))
    shared = budget(attempts=1)
    if size > 3_000_000:
        with pytest.raises(ValueError, match="Cached document"):
            retrieve(db, shared, max_bytes=3_000_000)
    else:
        assert retrieve(db, shared, max_bytes=3_000_000) == raw
    assert shared.received_bytes == 0
    assert shared.attempts == 1
    with pytest.raises(ValueError, match="attempt"):
        retrieve(db, shared)
    assert calls == [(URL, 25)]


@pytest.mark.parametrize("maximum,expected", [(1, 1), (2, 2), (3, 2)])
def test_retry_exhaustion_never_exceeds_either_attempt_limit(db, install, maximum, expected):
    calls = install(*(HTTPError(URL, 503, "Unavailable", {}, BytesIO()) for _ in range(3)))
    shared = budget(attempts=maximum)
    with pytest.raises((ValueError, HTTPError)):
        retrieve(db, shared)
    assert len(calls) == expected
    assert shared.attempts == expected


def test_shared_attempt_and_body_allowances_survive_between_urls(db, install):
    calls = install(Response(b"first"), Response(b"second"), Response(b"unwanted"))
    shared = budget(attempts=2, received=100)
    assert retrieve(db, shared) == b"first"
    assert transport.fetch(db, OTHER, "arista", budget=shared, forbid_redirects=True) == b"second"
    with pytest.raises(ValueError, match="attempt"):
        retrieve(db, shared)
    assert calls == [(URL, 25), (OTHER, 25)]
    assert shared.received_bytes == 11


def test_retry_error_bodies_and_final_error_body_are_charged(db, install):
    install(
        HTTPError(URL, 503, "Unavailable", {}, BytesIO(b"x" * 20_000)),
        HTTPError(URL, 403, "Forbidden", {}, BytesIO(b"denied")),
    )
    shared = budget()
    with pytest.raises(HTTPError) as caught:
        retrieve(db, shared)
    assert caught.value.code == 403
    assert shared.received_bytes == 15_006
    assert shared.attempts == 2


def test_error_body_budget_exhaustion_prevents_retry(db, install):
    calls = install(HTTPError(URL, 503, "Unavailable", {}, BytesIO(b"x" * 40)))
    shared = budget(received=10)
    with pytest.raises(ValueError, match="received"):
        retrieve(db, shared)
    assert shared.received_bytes == 10
    assert len(calls) == 1


def test_budget_exhaustion_rejects_unverified_prefix_and_does_not_cache(db, install):
    install(Response(b"a complete document"))
    shared = budget(received=5)
    with pytest.raises(ValueError, match="received"):
        retrieve(db, shared)
    assert shared.received_bytes == 5
    assert db.execute("SELECT COUNT(*) FROM http_cache").fetchone()[0] == 0


def test_received_boundary_with_room_for_empty_eof_probe(db, install):
    install(Response(b"exact"))
    shared = budget(received=6)
    assert retrieve(db, shared) == b"exact"
    assert shared.received_bytes == 5


def test_exact_received_boundary_without_eof_proof_fails_closed(db, install):
    install(Response(b"exact"))
    shared = budget(received=5)
    with pytest.raises(ValueError, match="received"):
        retrieve(db, shared)
    assert shared.received_bytes == 5
    assert db.execute("SELECT COUNT(*) FROM http_cache").fetchone()[0] == 0


def test_partial_read_exception_bytes_are_charged_and_never_cached(db, install):
    class Interrupted(Response):
        def read(self, size):
            raise IncompleteRead(b"partial", 10)

    install(Interrupted())
    shared = budget()
    with pytest.raises(IncompleteRead):
        retrieve(db, shared)
    assert shared.received_bytes == 7
    assert db.execute("SELECT COUNT(*) FROM http_cache").fetchone()[0] == 0


def test_unknown_partial_read_charges_requested_chunk_and_cannot_escape_budget(db, install):
    requested = []

    class Interrupted(Response):
        def read(self, size):
            requested.append(size)
            raise OSError("interrupted after unknown delivery")

    calls = install(Interrupted(), Response(b"unwanted"))
    shared = budget(received=10)
    with pytest.raises(ValueError, match="received"):
        retrieve(db, shared)
    assert requested == [10]
    assert shared.received_bytes == 10
    assert len(calls) == 1


def test_success_then_partial_failure_preserves_both_byte_counts(db, install):
    class Interrupted(Response):
        reads = 0

        def read(self, size):
            self.reads += 1
            if self.reads == 1:
                return b"delivered"
            raise IncompleteRead(b"partial", 10)

    install(Interrupted())
    shared = budget()
    with pytest.raises(IncompleteRead):
        retrieve(db, shared)
    assert shared.received_bytes == 16


def test_interrupted_retryable_error_body_retains_http_retry_classification(db, install):
    class Interrupted(BytesIO):
        def read(self, size):
            raise IncompleteRead(b"partial", 10)

    calls = install(HTTPError(URL, 503, "Unavailable", {}, Interrupted()), Response(b"success"))
    shared = budget()
    assert retrieve(db, shared) == b"success"
    assert shared.received_bytes == 14
    assert len(calls) == 2


def test_unknown_partial_success_body_can_retry_with_remaining_allowance(db, install):
    requested = []

    class Interrupted(Response):
        def read(self, size):
            requested.append(size)
            raise OSError("unknown partial delivery")

    calls = install(Interrupted(), Response(b"success"))
    shared = budget(received=100_000)
    assert retrieve(db, shared) == b"success"
    assert requested == [64_000]
    assert shared.received_bytes == 64_007
    assert len(calls) == 2


def test_budget_requires_redirect_refusal_before_any_http(db, install):
    calls = install(Response(b"unwanted"))
    shared = budget(attempts=1)
    with pytest.raises(ValueError, match="redirect"):
        transport.fetch(db, URL, "arista", budget=shared)
    assert shared.attempts == 0
    assert calls == []


@pytest.mark.parametrize("attempts,received", [(-1, 10), (1, -1), (True, 10), (1, 1.5)])
def test_invalid_budget_limits_cannot_disable_bounds(attempts, received):
    with pytest.raises(ValueError):
        budget(attempts, received)


def test_budget_counters_are_read_only_and_invalid_charges_do_not_refund():
    shared = budget(attempts=1, received=4)
    shared.start_attempt()
    shared.consume_received(4)
    with pytest.raises(ValueError):
        shared.start_attempt()
    with pytest.raises(ValueError):
        shared.consume_received(-1)
    with pytest.raises(ValueError):
        shared.consume_received(1)
    for name in ("attempts", "received_bytes"):
        with pytest.raises(AttributeError):
            setattr(shared, name, 0)
    assert shared.attempts == 1
    assert shared.received_bytes == 4


def test_ordinary_collection_retains_fifteen_megabyte_default_and_retry(db, install):
    raw = b"x" * 15_000_000
    calls = install(HTTPError(URL, 503, "Unavailable", {}, BytesIO()), Response(raw))
    assert transport.fetch(db, URL, "arista") == raw
    assert calls == [(URL, 25), (URL, 25)]
    install(Response(raw + b"x"))
    with pytest.raises(ValueError, match="Document exceeds"):
        transport.fetch(db, URL, "arista")


def test_ordinary_collection_still_allows_official_domain_redirects(db, monkeypatch):
    redirected = []

    def build(handler):
        class Opener:
            def open(self, request, timeout):
                redirected.append(handler.redirect_request(request, None, 302, "Found", {}, OTHER))
                return Response(b"official")

        return Opener()

    monkeypatch.setattr(transport, "build_opener", build)
    assert transport.fetch(db, URL, "arista") == b"official"
    assert redirected[0].full_url == OTHER
