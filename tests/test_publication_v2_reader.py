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
