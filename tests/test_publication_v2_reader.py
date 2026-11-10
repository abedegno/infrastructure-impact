"""Route-first bounded selections preserve full-claim validation and reducer semantics."""

import copy
import json
from pathlib import Path

import pytest
from test_current_evidence_delivery import arista_case  # noqa: F401
from test_current_evidence_delivery import delivery_db as _delivery_db
from test_static_delivery import CID, dataset

from infrastructure_impact.application import switching_comparison as comparison
from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.publication_reader import PublicationReader
from infrastructure_impact.exports import switching_csv

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures/publication-v2-query-vectors.json").read_text()
)
AT = "2026-11-07T18:00:00Z"

# Reuse retained-evidence fixtures without launching their browser checks.
delivery_db = _delivery_db


@pytest.fixture(scope="module")
def generation(tmp_path_factory):
    data = dataset()
    data["research"]["switching_input"] = copy.deepcopy(FIXTURE["report"]["inputs"]["evidence"])
    return publish(data, tmp_path_factory.mktemp("v2-query"), publication_format="v2")


@pytest.mark.parametrize(
    "options",
    [
        {},
        {"vendor": "arista"},
        {"vendor": "cisco"},
        {"vendor": "aruba"},
        {"scope_level": "model_qualified"},
        {"window": "2025"},
        {"window": "pre"},
        {"window": "post"},
        {"window": "undated"},
        {"cve_ids": []},
        {"cve_ids": None},
        {"cve_ids": ["CVE-2025-12345"]},
    ],
)
def test_selection_matches_full_v1(generation, options):
    reader = PublicationReader(generation)
    native = json.loads(b"".join(reader.stream_root("switching-comparison.json")))
    expected = comparison.summary(comparison.select_report(native, **options, evaluated_at=AT))
    actual = reader.switching_selection(options, evaluated_at=AT)
    assert actual == expected
    assert switching_csv(actual) == switching_csv(expected)


@pytest.mark.parametrize("vendor", [None, "cisco", "aruba", "arista"])
@pytest.mark.parametrize("at", [AT, "2027-12-01T00:00:00Z"])
def test_published_vendor_selection_never_reads_claims(generation, monkeypatch, vendor, at):
    reader = PublicationReader(generation)
    native = json.loads(b"".join(reader.stream_root("switching-comparison.json")))
    expected = comparison.summary(comparison.select_report(native, vendor=vendor, evaluated_at=at))

    def forbidden(*args, **kwargs):
        raise AssertionError("eligible published selection read claims")

    monkeypatch.setattr(reader, "iter_claims", forbidden)
    actual = reader.switching_selection({"vendor": vendor, "cve_ids": None}, evaluated_at=at)
    assert actual == expected
    assert switching_csv(actual) == switching_csv(expected)
    actual["rows"].clear()
    assert reader.switching_selection({"vendor": vendor}, evaluated_at=at) == expected


def test_optional_source_root_is_not_snapshot_data(generation):
    reader = PublicationReader(generation)
    name = "switching-row-sources.json"
    assert name in reader.catalog["roots"]
    index = reader.materialize_range(reader.ranges(name)[()])
    assert index["representation"] == "switching-row-sources"
    assert len(index["rows"]) == 3
    assert "sources" not in index
    for root in ("snapshot.json", "runtime-snapshot"):
        assert "switching_row_sources" not in reader.ranges(root)


def test_open_is_metadata_only_and_narrow_runtime_does_not_touch_whole_root(generation):
    reader = PublicationReader(generation, limits={"selected": 1_000_000})
    assert reader._strings is None and not reader._roots
    actual = reader.runtime_snapshot(cohort=[CID])
    assert actual["records"]
    assert "runtime-snapshot" not in reader._roots
    assert actual["product_label_index"]["hpe"]["all"]


def test_claims_validate_full_shape_and_private_projection_is_distinct(generation):
    from infrastructure_impact.application.switching_comparison import ReducerClaim

    reader = PublicationReader(generation)
    claims = list(reader.iter_claims())
    assert claims
    reduced = ReducerClaim.from_validated(claims[0])
    assert not isinstance(reduced, dict)
    assert reduced.sources
    assert "source" not in reduced.fields
    assert len(reduced.fields) < len(claims[0])


def test_reducer_working_budget_is_separate_from_response_budget(generation, monkeypatch):
    seen = []
    original = comparison.ReducerClaim.from_validated

    def capture(claim, *, budget=None):
        seen.append(budget.max_bytes)
        return original(claim, budget=budget)

    monkeypatch.setattr(comparison.ReducerClaim, "from_validated", capture)
    reader = PublicationReader(generation)
    assert reader.switching_selection({"scope_level": "model_qualified"}, evaluated_at=AT)["rows"]
    assert seen and set(seen) == {512_000_000}
    assert reader.limits["selected"] == 128_000_000
    with pytest.raises(ValueError, match="budget"):
        PublicationReader(generation, limits={"working": 1}).switching_selection(
            {"scope_level": "model_qualified"}, evaluated_at=AT
        )
    with pytest.raises(ValueError, match="increase"):
        PublicationReader(generation, limits={"working": 512_000_001})


def test_paged_details_bind_selection_generation_and_kind(generation):
    reader = PublicationReader(generation)
    selected = reader.switching_selection({}, evaluated_at=AT)
    page = reader.detail_page(selected, "claims", limit=1)
    assert len(page["items"]) == 1 and page["total"] > 1
    if page["next_cursor"]:
        second = reader.detail_page(selected, "claims", limit=1, cursor=page["next_cursor"])
        assert second["items"][0]["claim_id"] != page["items"][0]["claim_id"]
        with pytest.raises(ValueError):
            reader.detail_page(selected, "sources", limit=1, cursor=page["next_cursor"])


def test_http_health_and_small_selection_do_not_open_whole_runtime(generation):
    from infrastructure_impact.http import Application

    app = Application(generation.parent.parent)
    _, opened = app.store.open()
    assert isinstance(opened, PublicationReader) and not opened._roots
    code, _, body = app.route({"REQUEST_METHOD": "GET", "PATH_INFO": "/api/v1/health"})
    assert code == 200 and json.loads(body)["publication"] == opened.identity["publication"]
    code, _, body = app.route(
        {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/v1/assessments", "QUERY_STRING": "cves=" + CID}
    )
    assert code == 200 and json.loads(body)["items"]
    assert "runtime-snapshot" not in opened._roots


def test_http_full_state_stream_contains_original_summary_not_overview(generation):
    from infrastructure_impact.http import Application

    app = Application(generation.parent.parent)
    code, _, body = app.route(
        {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/state", "QUERY_STRING": "cves=" + CID}
    )
    assert code == 200 and not isinstance(body, bytes)
    value = json.loads(b"".join(body))
    assert value["switching_comparison"]["representation"] == "summary"
    assert "switching_overview" not in value
    reader = PublicationReader(generation)
    snapshot = json.loads(b"".join(reader.stream_root("snapshot.json")))
    assert value["records"] == snapshot["records"]
    assert value["switching_comparison"] == snapshot["switching_comparison"]


def test_query_batch_validates_full_claims_once(generation, monkeypatch):
    reader = PublicationReader(generation)
    original = reader.iter_claims
    calls = []

    def counted():
        calls.append(True)
        yield from original()

    monkeypatch.setattr(reader, "iter_claims", counted)
    results = list(
        reader.switching_selections([{}, {"scope_level": "model_qualified"}], evaluated_at=AT)
    )
    assert len(results) == 2 and len(calls) == 1


def test_reviewed_cross_claim_links_survive_stream_projection(tmp_path):
    data = dataset()
    data["research"]["switching_input"] = json.loads(
        (Path(__file__).parent / "fixtures/publication-v2-reviewed-link.json").read_text()
    )
    reader = PublicationReader(publish(data, tmp_path, publication_format="v2"))
    native = json.loads(b"".join(reader.stream_root("switching-comparison.json")))
    actual = reader.switching_selection({}, evaluated_at=AT)
    assert actual == comparison.summary(comparison.select_report(native, evaluated_at=AT))
    assert any(r["counts"]["remediation_events"] for r in actual["rows"])


def test_mandatory_whole_root_cannot_be_omitted(generation):
    from infrastructure_impact.application.publication_v2 import verify_projection

    reader = PublicationReader(generation)
    projected = json.loads(b"".join(reader.stream_root("snapshot.json")))
    projected["switching_comparison"] = json.loads(
        b"".join(reader.stream_root("switching-comparison.json"))
    )
    projected["switching_evidence"] = projected["switching_comparison"]["inputs"]["evidence"]
    if "switching-release-history.json" in reader.catalog["roots"]:
        projected["switching_release_history"] = json.loads(
            b"".join(reader.stream_root("switching-release-history.json"))
        )
    reader.catalog["roots"].pop("catalogue.json")
    with pytest.raises(ValueError, match="mandatory logical root"):
        verify_projection(reader, projected)


def test_actual_large_runtime_root_leaves_health_and_small_cohort_available(generation):
    from infrastructure_impact import publication_codec as codec
    from infrastructure_impact.application.publication_v2 import Writer

    reader = PublicationReader(generation)
    strings, shapes = reader._tables()
    index = max(range(len(strings)), key=lambda i: len(strings[i]))
    repetitions = 128_000_001 // codec.string_cost(strings[index]) + 2
    tokens = [[-1, repetitions]] + [-index - 2] * repetitions
    logical = codec.digest(codec.stream_tokens(tokens, strings, shapes))
    assert logical["bytes"] > 128_000_000
    writer = Writer(generation, reader.identity)
    page = writer.part("tokens", tokens)
    bound = dict(
        root="runtime-snapshot",
        first_token=0,
        end_token=len(tokens),
        logical_bytes=logical["bytes"],
        logical_sha256=logical["sha256"],
    )
    ranges = writer.part("ranges", [dict(path=[], range=bound)])
    root = writer.part(
        "root",
        dict(
            name="runtime-snapshot",
            token_count=len(tokens),
            logical=logical,
            pages=[
                dict(
                    part=page,
                    first_token=0,
                    count=len(tokens),
                    decoded_upper_bound=logical["bytes"],
                )
            ],
            ranges=[ranges],
        ),
    )
    reader.catalog["roots"]["runtime-snapshot"] = root
    assert reader.metadata()["publication"]
    assert reader.runtime_snapshot(cohort=[CID])["records"]
    with pytest.raises(ValueError, match="selected byte budget"):
        reader.runtime_snapshot()


def test_query_projection_and_narrow_cohort_aggregate_bounds(generation):
    reader = PublicationReader(generation, limits={"selected": 30000})
    with pytest.raises(ValueError, match="budget"):
        reader.runtime_snapshot(cohort=[CID])
    with pytest.raises(ValueError, match="budget"):
        PublicationReader(generation, limits={"selected": 10000}).switching_selection(
            {}, evaluated_at=AT
        )


@pytest.mark.parametrize("maximum", [0, False])
def test_explicit_zero_materialization_authority(generation, maximum):
    reader = PublicationReader(generation)
    with pytest.raises(ValueError):
        reader.materialize_range(
            reader.ranges("snapshot.json")[("generated_at",)], max_bytes=maximum
        )


@pytest.mark.parametrize("field", ["record_index", "first_token", "end_token", "logical_bytes"])
@pytest.mark.parametrize("invalid", [0.0, True])
def test_record_route_transport_types(generation, field, invalid):
    from infrastructure_impact.application.publication_v2 import Writer

    reader = PublicationReader(generation)
    rows = reader.fetch(reader.catalog["routes"]["records"][0], kind="record_routes")
    rows[0][field] = float(rows[0][field]) if type(invalid) is float else invalid
    writer = Writer(generation, reader.identity)
    descriptor = writer.part("record_routes", rows)
    with pytest.raises(ValueError):
        reader.fetch(descriptor, kind="record_routes")


@pytest.mark.parametrize("invalid", [0.0, True, -1, 9007199254740992])
def test_range_path_transport_types(generation, invalid):
    reader = PublicationReader(generation)
    original = reader.fetch

    def fetch(desc, **kwargs):
        value = original(desc, **kwargs)
        if kwargs.get("kind") == "ranges":
            for row in value:
                if row["path"] == ["records", 0]:
                    row["path"][1] = invalid
        return value

    reader.fetch = fetch
    with pytest.raises(ValueError):
        reader.ranges("snapshot.json")


def test_cohort_complete_structure_budget(generation):
    result = PublicationReader(generation).runtime_snapshot(cohort=[CID])
    size = len(json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode())
    with pytest.raises(ValueError, match="budget"):
        PublicationReader(generation, limits={"selected": size - 1}).runtime_snapshot(cohort=[CID])
    assert (
        PublicationReader(generation, limits={"selected": size}).runtime_snapshot(cohort=[CID])
        == result
    )


def test_cohort_retained_wrapper_budget(delivery_db, tmp_path):
    from infrastructure_impact.application.query import state

    out = publish(
        state(delivery_db, ["CVE-2023-5501", "CVE-2024-6858"]), tmp_path, publication_format="v2"
    )
    cohort = ["CVE-2023-5501"]
    result = PublicationReader(out).runtime_snapshot(cohort=cohort)
    assert result["retained_advisories"]
    size = len(json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode())
    with pytest.raises(ValueError, match="budget"):
        PublicationReader(out, limits={"selected": size - 1}).runtime_snapshot(cohort=cohort)
    assert (
        PublicationReader(out, limits={"selected": size}).runtime_snapshot(cohort=cohort) == result
    )


def test_reducer_rejects_before_row_allocation(generation, monkeypatch):
    reader = PublicationReader(generation)
    claims = [comparison.ReducerClaim.from_validated(c) for c in reader.iter_claims()]
    original = comparison._row
    built = []

    def row(*args, **kwargs):
        value = original(*args, **kwargs)
        built.append(value)
        return value

    monkeypatch.setattr(comparison, "_row", row)
    with pytest.raises(ValueError, match="budget"):
        comparison.select_reducer_claims(
            reader.switching_overview(),
            claims,
            reader.field("switching-evidence.json", "coverage"),
            reader.field("switching-evidence.json", "issues"),
            reader.materialize_range(reader.catalog["switching"]["kev"]),
            {},
            evaluated_at=AT,
            max_bytes=32,
        )
    assert built == []


@pytest.mark.parametrize("kind", ["sources", "claims"])
def test_detail_full_envelope_exact_bound(generation, kind):
    reader = PublicationReader(generation)
    selected = reader.switching_selection({}, evaluated_at=AT)
    expected = reader.detail_page(selected, kind, limit=1)
    size = len(json.dumps(expected, ensure_ascii=True, separators=(",", ":")).encode())
    reader.limits["selected"] = size
    assert reader.detail_page(selected, kind, limit=1) == expected
    reader.limits["selected"] = size - 1
    with pytest.raises(ValueError, match="budget"):
        reader.detail_page(selected, kind, limit=1)


def test_http_json_actual_bytes_bound(generation):
    from infrastructure_impact.http import Application

    app = Application(generation.parent.parent)
    _, reader = app.store.open()
    environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/v1/current-evidence"}
    code, _, body = app.route(environ)
    assert code == 200
    reader.limits["selected"] = len(body)
    assert app.route(environ)[2] == body
    reader.limits["selected"] -= 1
    with pytest.raises(ValueError, match="budget"):
        app.route(environ)


def test_retained_page_bound_and_missing_cohort_skips_parts(delivery_db, tmp_path):
    from infrastructure_impact.application.query import state
    from infrastructure_impact.http import Application

    out = publish(
        state(delivery_db, ["CVE-2023-5501", "CVE-2024-6858"]), tmp_path, publication_format="v2"
    )
    app = Application(out.parent.parent)
    _, reader = app.store.open()
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/api/v1/retained-advisories",
        "QUERY_STRING": "limit=1",
    }
    code, _, body = app.route(environ)
    assert code == 200 and json.loads(body)["items"]
    reader.limits["selected"] = len(body)
    assert app.route(environ)[2] == body
    reader.limits["selected"] -= 1
    with pytest.raises(ValueError, match="budget"):
        app.route(environ)
    reader.limits["selected"] = 128_000_000
    original = reader.fetch
    reads = []

    def fetch(desc, **kwargs):
        reads.append(desc["path"])
        return original(desc, **kwargs)

    reader.fetch = fetch
    environ["QUERY_STRING"] = "limit=1&cves=CVE-2099-9999"
    assert json.loads(app.route(environ)[2])["total"] == 0
    assert not set(reads).intersection(
        p["part"]["path"] for p in reader.index["current_evidence"]["retained"]
    )


@pytest.mark.parametrize("exporter", ["switching", "retained"])
def test_csv_requested_bytes_preflight(generation, exporter):
    from infrastructure_impact.exports import csv_export
    from infrastructure_impact.http import Application

    if exporter == "switching":
        report = PublicationReader(generation).switching_selection({}, evaluated_at=AT)

        def encode(bound):
            return switching_csv(report, max_bytes=bound)

        expected = switching_csv(report)
    else:
        data = {
            "records": [{"cves": [CID], "assessments": [{"cve_id": CID, "product": 'é,"' * 30}]}],
            "comparison": {"cohort": [CID]},
        }

        def encode(bound):
            return csv_export(data, max_bytes=bound)

        expected = csv_export(data)
    size = len(expected.encode())
    assert encode(size) == expected
    with pytest.raises(ValueError, match="budget"):
        encode(size - 1)
    # Native materialized response must enforce the exact spaced ASCII form too.
    value = {"values": ['é,"' * 20, None, True]}
    size = len(json.dumps(value).encode())
    assert len(Application.json(value, max_bytes=size)[2]) == size
    with pytest.raises(ValueError, match="budget"):
        Application.json(value, max_bytes=size - 1)


def test_projection_rejects_before_constructor(generation, monkeypatch):
    reader = PublicationReader(generation)
    claims = list(reader.iter_claims())
    original = comparison.ReducerClaim.__init__
    built = []

    def construct(self, fields, sources):
        built.append(fields)
        original(self, fields, sources)

    monkeypatch.setattr(comparison.ReducerClaim, "__init__", construct)
    monkeypatch.setattr(reader, "iter_claims", lambda: iter(claims))
    reader.limits["working"] = 32
    with pytest.raises(ValueError, match="budget"):
        reader.switching_selection({}, evaluated_at=AT)
    assert built == []


def test_runtime_fields_shared_ascii_envelope_bound(generation):
    reader = PublicationReader(generation)
    fields = ["generated_at", "publication", "vendors"]
    expected = reader.runtime_snapshot(fields=fields)
    size = len(json.dumps(expected, ensure_ascii=True, separators=(",", ":")).encode())
    reader.limits["selected"] = size
    assert reader.runtime_snapshot(fields=fields) == expected
    reader.limits["selected"] -= 1
    with pytest.raises(ValueError, match="budget"):
        reader.runtime_snapshot(fields=fields)


def test_retained_export_filter_page_and_partition_parity(delivery_db, tmp_path):
    from infrastructure_impact.application.query import state
    from infrastructure_impact.exports import retained_assessment_export, retained_csv_export
    from infrastructure_impact.http import Application

    out = publish(
        state(delivery_db, ["CVE-2023-5501", "CVE-2024-6858"]), tmp_path, publication_format="v2"
    )
    app = Application(out.parent.parent)
    _, reader = app.store.open()
    snapshot = json.loads(b"".join(reader.stream_root("snapshot.json")))
    base = {"REQUEST_METHOD": "GET", "PATH_INFO": "/api/v1/retained-advisories"}
    expected = retained_assessment_export(snapshot)
    assert json.loads(app.route({**base, "QUERY_STRING": "format=json"})[2]) == expected
    assert (
        app.route({**base, "QUERY_STRING": "format=csv"})[2]
        == retained_csv_export(snapshot).encode()
    )
    page = json.loads(app.route({**base, "QUERY_STRING": "offset=1&limit=1"})[2])
    assert page["items"] == [] and page["total"] == 1
    filtered = json.loads(app.route({**base, "QUERY_STRING": "format=json&cves=CVE-2023-5501"})[2])
    assert all(
        a["cve_id"] == "CVE-2023-5501" for r in filtered["records"] for a in r["assessments"]
    )
    body = app.route({**base, "QUERY_STRING": "format=json"})[2]
    reader.limits["selected"] = len(body)
    assert app.route({**base, "QUERY_STRING": "format=json"})[2] == body
    reader.limits["selected"] -= 1
    with pytest.raises(ValueError, match="budget"):
        app.route({**base, "QUERY_STRING": "format=json"})
    reader.limits["selected"] = 128_000_000
    reader.index["current_evidence"]["retained"][0]["cve_ids"] = []
    with pytest.raises(ValueError, match="membership"):
        app.route({**base, "QUERY_STRING": "cves=CVE-2099-9999"})


def test_delegated_http_csv_exact_response_bytes(generation, monkeypatch):
    from datetime import datetime

    from infrastructure_impact.application import kev
    from infrastructure_impact.http import Application

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls.fromisoformat("2026-11-07T18:00:00+00:00")

    monkeypatch.setattr(kev, "datetime", Clock)
    app = Application(generation.parent.parent)
    _, reader = app.store.open()
    snapshot = json.loads(b"".join(reader.stream_root("snapshot.json")))
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/api/export.csv",
        "QUERY_STRING": "cves=" + CID,
    }

    # Exercise the real legacy-route delegation used by v2, with its already
    # validated input. Isolate the response allowance from the larger input view.
    def response():
        return app.route(environ, _opened=(generation, snapshot), _reader=reader)

    code, mime, body = response()
    assert code == 200 and mime == "text/csv"
    reader.limits["selected"] = len(body)
    assert response()[2] == body
    reader.limits["selected"] -= 1
    with pytest.raises(ValueError, match="budget"):
        response()


def test_json_preflight_happens_before_encoder(monkeypatch):
    from infrastructure_impact import http
    from infrastructure_impact.http import Application

    value = {"large": "é" * 100}
    original = http.json.dumps

    def dumps(obj, *args, **kwargs):
        assert obj is not value, "response string allocated before budget rejection"
        return original(obj, *args, **kwargs)

    monkeypatch.setattr(http.json, "dumps", dumps)
    with pytest.raises(ValueError, match="budget"):
        Application.json(value, max_bytes=100)


def test_empty_retained_page_independent_of_large_current_records(generation):
    from infrastructure_impact.http import Application

    app = Application(generation.parent.parent)
    _, reader = app.store.open()
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/api/v1/retained-advisories",
        "QUERY_STRING": "limit=1&cves=CVE-2099-9999",
    }
    code, _, body = app.route(environ)
    assert code == 200 and json.loads(body)["items"] == []
    assert len(body) == 578
    assert all(route["logical_bytes"] > len(body) for route in reader.record_routes())
    reader.limits["selected"] = len(body)
    assert app.route(environ)[2] == body
    stream_limit = reader.ranges("snapshot.json")[("records",)]["logical_bytes"]
    reader.limits["stream"] = stream_limit
    assert app.route(environ)[2] == body
    reader.limits["stream"] -= 1
    with pytest.raises(ValueError, match="budget"):
        app.route(environ)
    reader.limits["stream"] = stream_limit
    reader.limits["selected"] -= 1
    with pytest.raises(ValueError, match="budget"):
        app.route(environ)


@pytest.mark.parametrize("tamper", ["payload", "identity"])
def test_retained_identity_scan_rejects_tampering(generation, monkeypatch, tamper):
    from infrastructure_impact.http import Application

    app = Application(generation.parent.parent)
    _, reader = app.store.open()
    strings, _ = reader._tables()
    original = reader.iter_tokens
    old_value, new_value = (
        ("Junos OS Evolved", "HPE ProLiant Compute DL325 Gen12")
        if tamper == "payload"
        else ("juniper", "hpe")
    )
    old = -strings.index(old_value) - 2
    replacement = -strings.index(new_value) - 2

    def tokens(name, first=0, end=None):
        for token in original(name, first, end):
            yield replacement if name == "snapshot.json" and token == old else token

    monkeypatch.setattr(reader, "iter_tokens", tokens)
    reader.limits["selected"] = 578
    with pytest.raises(ValueError, match="digest"):
        app.route(
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/api/v1/retained-advisories",
                "QUERY_STRING": "limit=1&cves=CVE-2099-9999",
            }
        )


def test_current_identity_projection_retains_overlap_detection(delivery_db, tmp_path, monkeypatch):
    from infrastructure_impact.application.query import state
    from infrastructure_impact.http import Application

    out = publish(
        state(delivery_db, ["CVE-2023-5501", "CVE-2024-6858"]), tmp_path, publication_format="v2"
    )
    app = Application(out.parent.parent)
    _, reader = app.store.open()
    routes = reader.record_routes()
    real_keys = list(reader._current_record_keys(routes))
    assert len(real_keys) == len(set(real_keys)) == 2
    from infrastructure_impact import publication_codec as codec

    strings, shapes = reader._tables()
    bound = reader.ranges("snapshot.json")[("records",)]
    original = reader.iter_tokens
    raw_tokens = list(original("snapshot.json", bound["first_token"], bound["end_token"]))
    positions = {}
    fields = {"vendor", "advisory_id", "revision_id", "source_url", "sha256"}

    def observe(event, path, position):
        if event == "start" and len(path) == 3 and path[2] in fields:
            positions[(path[1], path[2])] = position

    for _ in codec.stream_tokens(
        raw_tokens, strings, shapes, path=("records",), node_observer=observe
    ):
        pass
    replacements = {
        bound["first_token"] + positions[(1, field)]: raw_tokens[positions[(0, field)]]
        for field in fields
    }

    # Bind the substituted array to its actual length/digest. Thus this case
    # requires the partition overlap check, not merely a hash mismatch.
    altered = [
        replacements.get(bound["first_token"] + i, token) for i, token in enumerate(raw_tokens)
    ]
    measured = codec.digest(codec.stream_tokens(altered, strings, shapes))
    bound.update(logical_bytes=measured["bytes"], logical_sha256=measured["sha256"])

    def tokens(name, first=0, end=None):
        for position, token in enumerate(original(name, first, end), first):
            yield replacements.get(position, token) if name == "snapshot.json" else token

    monkeypatch.setattr(reader, "iter_tokens", tokens)
    with pytest.raises(ValueError, match="Duplicate retained/current identity"):
        app.route(
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/api/v1/retained-advisories",
                "QUERY_STRING": "limit=1&cves=CVE-2099-9999",
            }
        )


@pytest.fixture
def detail_reader(generation, monkeypatch, tmp_path):
    from infrastructure_impact.application import publication_v2

    reader = PublicationReader(generation)
    monkeypatch.setattr(publication_v2, "TARGET", 700)
    writer = publication_v2.Writer(tmp_path, reader.identity)
    expected = [
        {"vendor": "arista" if i % 2 else "cisco", "unknown": ["🚀", i, i + 0.5]} for i in range(63)
    ]
    writer.root("snapshot.json", {"switching_comparison": {"sources": []}})
    writer.root("switching-evidence.json", {"score_availability": expected})
    writer.tables()
    reader.directory = tmp_path
    reader.catalog = {
        **reader.catalog,
        "roots": writer.roots,
        "strings": writer.string_parts,
        "shapes": writer.shape_parts,
        "switching": {
            "diagnostics": writer.root_ranges["switching-evidence.json"][("score_availability",)],
            "detail_indexes": writer.detail_indexes(),
        },
    }
    reader._strings = reader._shapes = None
    reader._roots.clear()
    reader._ranges.clear()
    selected = {**reader.identity, "rows": [], "sources": [], "selection": {}}
    return reader, selected, expected, writer


def test_detail_envelope_does_not_validate_unrelated_variants(detail_reader, monkeypatch):
    from jsonschema import Draft202012Validator

    reader, _, expected, _ = detail_reader
    original = Draft202012Validator.VALIDATORS["oneOf"]

    def check(validator, alternatives, instance, schema):
        assert not any("kind" in option.get("properties", {}) for option in alternatives), (
            "envelope must dispatch by kind before validating its payload"
        )
        yield from original(validator, alternatives, instance, schema)

    monkeypatch.setitem(Draft202012Validator.VALIDATORS, "oneOf", check)
    descriptor = reader.catalog["switching"]["detail_indexes"]["diagnostics"][0]
    entries = reader.fetch(descriptor["part"], kind="detail_index")
    assert entries[0]["vendor"] == expected[0]["vendor"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", 1),
        ("publication", {"id": "bad", "advisory_schema_version": 2}),
        ("generated_at", 42),
        ("kind", "strings"),
        ("data", [{"ordinal": -1}]),
        ("extra", True),
    ],
)
def test_exact_envelope_validation_preserves_rejections(detail_reader, field, value):
    from jsonschema import ValidationError

    from infrastructure_impact.application.publication_v2 import validate_envelope, validators

    reader, _, _, _ = detail_reader
    descriptor = reader.catalog["switching"]["detail_indexes"]["diagnostics"][0]["part"]
    envelope = json.loads((reader.directory / descriptor["path"]).read_bytes())
    generic = validators()["publication-v2.json"].evolve(
        schema={"$ref": "urn:infrastructure-impact:publication:2#/$defs/envelope"}
    )
    generic.validate(envelope)
    validate_envelope(envelope, "detail_index")
    envelope[field] = value
    with pytest.raises(ValidationError):
        generic.validate(envelope)
    with pytest.raises(ValidationError):
        validate_envelope(envelope, "detail_index")
    with pytest.raises(ValueError, match="unknown or ambiguous"):
        validate_envelope(envelope, "unknown")


def test_diagnostic_page_reads_only_requested_children(detail_reader, monkeypatch):
    reader, selected, expected, _ = detail_reader

    def no_array_scan(*args, **kwargs):
        raise AssertionError("detail page scanned the complete diagnostic array")

    monkeypatch.setattr(reader, "iter_array", no_array_scan)
    page = reader.detail_page(selected, "diagnostics", limit=1)
    assert page["items"] == expected[:1]
    assert page["total"] == len(expected)


def test_indexed_diagnostic_pages_match_legacy_bytes_and_budget(detail_reader):
    reader, selected, expected, _ = detail_reader
    indexes = reader.catalog["switching"]["detail_indexes"]
    seen, cursor = [], None
    while True:
        page = reader.detail_page(selected, "diagnostics", cursor=cursor)
        del reader.catalog["switching"]["detail_indexes"]
        legacy = reader.detail_page(selected, "diagnostics", cursor=cursor)
        reader.catalog["switching"]["detail_indexes"] = indexes
        assert json.dumps(page, ensure_ascii=True) == json.dumps(legacy, ensure_ascii=True)
        assert page["total"] == 63
        seen.extend(page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == expected
    page = reader.detail_page(selected, "diagnostics", limit=1)
    size = len(json.dumps(page, ensure_ascii=True, separators=(",", ":")).encode())
    reader.limits["selected"] = size
    assert reader.detail_page(selected, "diagnostics", limit=1) == page
    reader.limits["selected"] = size - 1
    with pytest.raises(ValueError, match="budget"):
        reader.detail_page(selected, "diagnostics", limit=1)


@pytest.mark.parametrize("corruption", ["hash", "ordinal", "vendor"])
def test_selected_detail_routing_and_hash_are_verified(detail_reader, corruption):
    reader, selected, _, writer = detail_reader
    descriptor = reader.catalog["switching"]["detail_indexes"]["diagnostics"][0]
    entries = reader.fetch(descriptor["part"], kind="detail_index")
    if corruption == "hash":
        entries[0]["range"]["logical_sha256"] = "0" * 64
    elif corruption == "ordinal":
        entries[0]["ordinal"] = 1
    else:
        # Matching summary counts alone cannot substitute another item's vendor.
        entries[0]["vendor"] = "arista"
        descriptor["vendors"]["cisco"] -= 1
        if not descriptor["vendors"]["cisco"]:
            del descriptor["vendors"]["cisco"]
        descriptor["vendors"]["arista"] = descriptor["vendors"].get("arista", 0) + 1
    descriptor["part"] = writer.part("detail_index", entries)
    with pytest.raises(ValueError, match="digest|routing|vendor"):
        reader.detail_page(selected, "diagnostics", limit=1)


def test_detail_indexes_are_separate_from_default_root_ranges(generation):
    reader = PublicationReader(generation)
    indexes = reader.catalog["switching"]["detail_indexes"]
    assert set(indexes) == {"diagnostics", "sources"}
    assert indexes["sources"]
    assert not any(
        len(p) == 2 and p[0] == "score_availability"
        for p in reader.ranges("switching-evidence.json")
    )
    assert not any(
        len(p) == 3 and p[:2] == ("switching_comparison", "sources")
        for p in reader.ranges("snapshot.json")
    )
    for kind, descriptors in indexes.items():
        for descriptor in descriptors:
            rows = reader.fetch(descriptor["part"], kind="detail_index")
            assert len(rows) == descriptor["count"]


def test_projection_verification_accepts_optional_detail_membership(generation):
    from infrastructure_impact.application.publication_v2 import verify_projection

    reader = PublicationReader(generation)
    projected = json.loads(b"".join(reader.stream_root("snapshot.json")))
    projected["switching_comparison"] = json.loads(
        b"".join(reader.stream_root("switching-comparison.json"))
    )
    projected["switching_evidence"] = projected["switching_comparison"]["inputs"]["evidence"]
    if "switching-release-history.json" in reader.catalog["roots"]:
        projected["switching_release_history"] = json.loads(
            b"".join(reader.stream_root("switching-release-history.json"))
        )
    verify_projection(reader, projected)


def test_projection_verification_checks_optional_detail_membership(generation):
    from infrastructure_impact.application.publication_v2 import verify_projection

    reader = PublicationReader(generation)
    projected = json.loads(b"".join(reader.stream_root("snapshot.json")))
    projected["switching_comparison"] = json.loads(
        b"".join(reader.stream_root("switching-comparison.json"))
    )
    projected["switching_evidence"] = projected["switching_comparison"]["inputs"]["evidence"]
    if "switching-release-history.json" in reader.catalog["roots"]:
        projected["switching_release_history"] = json.loads(
            b"".join(reader.stream_root("switching-release-history.json"))
        )
    reader.catalog["switching"]["detail_indexes"]["sources"][0]["count"] += 1
    with pytest.raises(ValueError, match="detail"):
        verify_projection(reader, projected)


@pytest.fixture
def native_projection(generation):
    reader = PublicationReader(generation)
    projected = json.loads(b"".join(reader.stream_root("snapshot.json")))
    projected["switching_comparison"] = json.loads(
        b"".join(reader.stream_root("switching-comparison.json"))
    )
    projected["switching_evidence"] = projected["switching_comparison"]["inputs"]["evidence"]
    if "switching-release-history.json" in reader.catalog["roots"]:
        projected["switching_release_history"] = json.loads(
            b"".join(reader.stream_root("switching-release-history.json"))
        )
    return reader, projected


def test_native_root_verification_hashes_each_native_view_only_once(native_projection, monkeypatch):
    from infrastructure_impact.application import publication_v2

    reader, projected = native_projection
    original = publication_v2.codec.digest
    calls = []

    def digest(chunks):
        result = original(chunks)
        calls.append(result)
        return result

    monkeypatch.setattr(publication_v2.codec, "digest", digest)
    publication_v2.verify_projection(reader, projected)
    # Reader._stream authenticates decoded bytes itself. An external digest of
    # those same bytes duplicates the per-chunk work for every logical root.
    assert len(calls) == len(reader.catalog["roots"])


def test_native_root_verification_exhausts_every_stream_through_eof(native_projection, monkeypatch):
    from infrastructure_impact.application.publication_v2 import verify_projection

    reader, projected = native_projection
    original = reader.stream_root
    completed = []

    def stream(name):
        yield from original(name)
        completed.append(name)

    monkeypatch.setattr(reader, "stream_root", stream)
    verify_projection(reader, projected)
    assert set(completed) == set(reader.catalog["roots"])
    assert len(completed) == len(reader.catalog["roots"])


@pytest.mark.parametrize(
    "corruption",
    [
        "eof",
        "trailing_token",
        "unvisited_range",
        "physical_token",
        "range",
        "native",
        "root_digest",
    ],
)
def test_native_root_verification_preserves_rejections(
    native_projection, monkeypatch, tmp_path, corruption
):
    import shutil

    from infrastructure_impact.application.publication_v2 import verify_projection

    reader, projected = native_projection
    name = "benchmark.json"
    if corruption == "eof":
        original = reader.stream_root

        def stream(root):
            yield from original(root)
            if root == name:
                raise ValueError("injected EOF failure")

        monkeypatch.setattr(reader, "stream_root", stream)
        match = "EOF failure"
    elif corruption == "trailing_token":
        original = reader.iter_tokens

        def tokens(root, first=0, end=None):
            yield from original(root, first, end)
            if root == name:
                yield None

        monkeypatch.setattr(reader, "iter_tokens", tokens)
        match = "extra node"
    elif corruption == "unvisited_range":
        reader.ranges(name)[("missing",)] = reader.ranges(name)[()].copy()
        match = "unvisited range"
    elif corruption == "physical_token":
        shutil.copytree(reader.directory, tmp_path / "tampered")
        reader = PublicationReader(tmp_path / "tampered")
        descriptor = reader.root(name)["pages"][0]["part"]
        path = reader.directory / descriptor["path"]
        envelope = json.loads(path.read_bytes())
        envelope["data"][0] = [-1, 0]
        path.write_text(json.dumps(envelope))
        match = "hash|digest|bytes"
    elif corruption == "range":
        reader.ranges(name)[()]["logical_sha256"] = "0" * 64
        match = "range.*digest"
    elif corruption == "native":
        projected["benchmark"]["changed_native_fact"] = True
        match = "native logical root mismatch"
    else:
        reader.root(name)["logical"]["sha256"] = "0" * 64
        match = "native logical root mismatch|root/range digest"
    with pytest.raises(ValueError, match=match):
        verify_projection(reader, projected)


def test_native_roots_phase_is_static_and_reusable(native_projection, capsys):
    from infrastructure_impact.application.publication_v2 import verify_projection

    reader, projected = native_projection
    for _ in range(2):
        verify_projection(reader, projected)
    events = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert [(event["phase"], event["state"]) for event in events] == [
        ("publication.native_roots", state) for _ in range(2) for state in ("started", "completed")
    ]
    required = {"event", "phase", "state", "elapsed_seconds"}
    allowed = required | {"process_cpu_seconds", "peak_resident_bytes"}
    assert all(required <= set(event) <= allowed for event in events)


def test_inspection_and_native_parity_emit_static_nested_phases(tmp_path, monkeypatch, capsys):
    from io import StringIO

    from infrastructure_impact.application import publication_v2, query
    from infrastructure_impact.storage import repository

    native = dataset()
    native["research"]["switching_input"] = copy.deepcopy(FIXTURE["report"]["inputs"]["evidence"])
    generation = publish(native, tmp_path, publication_format="v2")
    capsys.readouterr()
    monkeypatch.setattr(repository, "connect", lambda *args, **kwargs: StringIO())
    monkeypatch.setattr(query, "state", lambda db: copy.deepcopy(native))
    for _ in range(2):
        reader = publication_v2.inspect_bundle(generation, {})
        publication_v2.native_parity("synthetic-native-only", generation, generation, reader)
    events = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert [(event["phase"], event["state"]) for event in events] == [
        item
        for _ in range(2)
        for item in (
            ("publication.inspection", "started"),
            ("publication.inspection", "completed"),
            ("publication.native_parity", "started"),
            ("publication.projection", "started"),
            ("publication.projection", "completed"),
            ("publication.native_roots", "started"),
            ("publication.native_roots", "completed"),
            ("publication.native_queries", "started"),
            ("publication.native_expected", "started"),
            ("publication.native_expected", "completed"),
            ("publication.native_reader", "started"),
            ("publication.native_reader", "completed"),
            ("publication.native_queries", "completed"),
            ("publication.native_parity", "completed"),
        )
    ]
    required = {"event", "phase", "state", "elapsed_seconds"}
    allowed = required | {"process_cpu_seconds", "peak_resident_bytes"}
    assert all(required <= set(event) <= allowed for event in events)


def test_claim_reader_uses_compiled_shapes_without_losing_semantics(generation, monkeypatch):
    from infrastructure_impact.application import switching_evidence as contracts

    contracts._compiled_validators()
    legacy = contracts._validators()["switching-evidence-v1.json"]

    def unnecessary_walk(self, value):
        raise AssertionError("Valid decoded claims should not repeat the Python schema walk")

    monkeypatch.setattr(type(legacy), "validate", unnecessary_walk)
    assert list(PublicationReader(generation).iter_claims())
