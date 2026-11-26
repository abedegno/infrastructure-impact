"""Packed delivery preserves the complete analysis and enforces expansion bounds."""

import copy
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from test_analysis_delivery import rich_source
from test_static_delivery import dataset

from infrastructure_impact import publication_codec as codec
from infrastructure_impact.application import analysis_delivery, publication, publication_v2
from infrastructure_impact.application import switching_analysis as analysis
from infrastructure_impact.application.publication_reader import PublicationReader

ROOT = "switching-analysis-packed.json"


def packed_api():
    from infrastructure_impact.application import analysis_packing

    return analysis_packing


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def rehash(value):
    value["content_sha256"] = analysis._hash(
        {k: v for k, v in value.items() if k != "content_sha256"}
    )


@pytest.fixture(scope="module")
def rich():
    return rich_source()


@pytest.fixture(scope="module")
def packed(rich):
    return packed_api().pack_report(rich)


def test_literal_layout_rows_and_native_json_spellings():
    # This deliberately tiny encoder fixture isolates pooling from scientific validation.
    source = {
        "publication": None,
        "generated_at": "2026-11-13T00:00:00Z",
        "definition_sha256": "a" * 64,
        "observation_end": "2026-11-13",
        "claims": {"a": {"a": 8.0, "b": {"é": 9007199254740993, "x": 8}}},
        "requirements": {"requirements": [{"a": 8}], "members": {"a": {"a": 8.0}}},
        "content_sha256": "b" * 64,
    }
    actual = packed_api()._pack_validated(source)
    assert actual["layouts"] == [["a", "b"], ["a"]]
    assert actual["values_json"] == [['"a"'], ["8.0"], ['{"é":9007199254740993,"x":8}'], ["8"]]
    assert actual["tables"] == {
        "claims": [[0, 0, 1, 2]],
        "members": [[0, 1, 1]],
        "requirements": [[1, 3]],
    }
    assert actual["source_logical_bytes"] == len(compact(source).encode())
    assert json.loads("".join(actual["skeleton_json"]))["requirements"] == {
        "requirements": None,
        "members": None,
    }


def test_native_roundtrip_preserves_order_and_does_not_share_subvalues(rich, packed):
    first = packed_api().unpack_report(packed)
    assert compact(first) == compact(rich)
    claim, other = list(first["claims"].values())[:2]
    claim["issues"].append("changed")
    assert "changed" not in other["issues"]
    assert compact(packed_api().unpack_report(packed)) == compact(rich)


def test_public_codec_preserves_exact_numbers_unicode_and_nested_key_order(rich):
    source = copy.deepcopy(rich)
    claim = next(iter(source["claims"].values()))
    claim["product"] += " — café"
    retained = source["release_history"]["sources"][0]["retained"]
    retained["revision_id"] = 9007199254740993
    # The older vectors contain authoritative float scores inside the pooled
    # claims and make a separate native round trip for integral floats.
    rehash(source)
    report = packed_api().unpack_report(packed_api().pack_report(source))
    assert compact(report) == compact(source)
    vectors = json.loads(Path("tests/fixtures/switching-analysis-vectors.json").read_text())
    full = vectors["compiled"]
    assert compact(packed_api().unpack_report(packed_api().pack_report(full))) == compact(full)


def test_native_selected_json_and_both_csv_match(rich, packed):
    unpacked = packed_api().unpack_report(packed)
    for vendor in (None, "cisco", "aruba", "arista"):
        for scope in ("os_family", "model_qualified"):
            for window in ("all", "pre", "post", "undated", "2025", "2026"):
                for cves in (None, [], ["CVE-2026-7473"]):
                    study = analysis.selection_context(
                        rich, dict(vendor=vendor, scope_level=scope, window=window, cve_ids=cves)
                    )
                    expected = analysis.select_report(rich, study)
                    actual = analysis.select_report(unpacked, study)
                    assert compact(actual) == compact(expected)
                    assert analysis.analysis_csv_export(actual) == analysis.analysis_csv_export(
                        expected
                    )
                    assert analysis.csv_export(actual["upgrades"]) == analysis.csv_export(
                        expected["upgrades"]
                    )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda p: p["values_json"].append(['"unused"']), "closure"),
        (lambda p: p["values_json"].append(p["values_json"][0]), "duplicate"),
        (lambda p: p["layouts"].append(p["layouts"][0]), "duplicate"),
        (lambda p: p["layouts"][0].append(p["layouts"][0][0]), "layout"),
        (lambda p: p["tables"]["claims"][0].pop(), "row"),
        (lambda p: p["tables"]["claims"][0].append(0), "row"),
        (lambda p: p["tables"]["claims"][0].__setitem__(0, True), "integer"),
        (lambda p: p["tables"]["claims"][0].__setitem__(0, 2**53), "integer"),
        (lambda p: p["tables"]["claims"][0].__setitem__(1, len(p["layouts"])), "index"),
        (lambda p: p["tables"]["claims"].__setitem__(1, p["tables"]["claims"][0]), "duplicate"),
        (lambda p: p["counts"].__setitem__("claims", 1), "counts"),
        (lambda p: p.__setitem__("observation_end", "2030-01-01"), "identity"),
        (lambda p: p.__setitem__("source_content_sha256", "0" * 64), "fingerprint"),
        (lambda p: p.__setitem__("source_logical_bytes", 1), "budget"),
        (lambda p: p["values_json"].__setitem__(0, ['{"a":0,"a":1}']), "duplicate"),
        (lambda p: p["values_json"].__setitem__(0, ["1e9999"]), "nonfinite"),
    ],
)
def test_rehashed_corruption_is_rejected(packed, mutate, message):
    bad = copy.deepcopy(packed)
    mutate(bad)
    rehash(bad)
    with pytest.raises(ValueError, match="(?i)" + message):
        packed_api().unpack_report(bad)


def test_repeated_pool_expansion_rejects_before_allocating_rows(monkeypatch, packed):
    packing = packed_api()
    bad = copy.deepcopy(packed)
    rows = bad["tables"]["requirements"]
    cell = rows[0][1]
    bad["values_json"][cell] = packing._chunks('"' + "a" * 4_000_000 + '"')
    for row in rows:
        row[1] = cell
    bad["source_logical_bytes"] = codec.MAX_SELECTED
    rehash(bad)
    assert len(rows) > 32

    def forbid(*args, **kwargs):
        pytest.fail("allocated expanded rows before checking the expansion bound")

    monkeypatch.setattr(packing, "_expand_tables", forbid)
    with pytest.raises(ValueError, match="budget"):
        packing.unpack_report(bad)


def test_public_input_validation_and_byte_limits(rich, packed):
    with pytest.raises(ValueError, match="budget"):
        packed_api().pack_report(rich, max_bytes=1)
    with pytest.raises(ValueError, match="budget"):
        packed_api().unpack_report(packed, max_bytes=packed["source_logical_bytes"] - 1)
    altered = dict(rich, content_sha256="0" * 64)
    with pytest.raises(ValueError, match="fingerprint"):
        packed_api().pack_report(altered)


def make_preview(destination):
    data = dataset()
    data["publication"] = {"id": "a" * 32, "advisory_schema_version": 2}
    data["current_evidence"]["publication"] = data["publication"]
    data["research"]["switching_input"] = json.loads(
        Path("tests/fixtures/switching-cases.json").read_text()
    )["evidence"]
    public = publication.public_projection(
        data, publication_format="v2", include_switching_analysis=True
    )
    publication_v2.write_bundle(destination, public, analysis_packed_delivery=True)
    return public


def test_v2_opt_in_preserves_legacy_descriptors_and_regenerates(tmp_path):
    preview = tmp_path / "preview"
    public = make_preview(preview)
    reader = PublicationReader(preview)
    publication_v2.verify_projection(reader, public)
    envelope = reader.materialize_range(reader.ranges(ROOT)[()])
    assert compact(packed_api().unpack_report(envelope)) == compact(public["switching_analysis"])

    baseline = tmp_path / "baseline"
    publication.write_bundle(baseline, public, publication_format="v2")
    old = PublicationReader(baseline)
    assert set(reader.catalog["roots"]) == {*old.catalog["roots"], ROOT}
    for name in old.catalog["roots"]:
        assert reader.catalog["roots"][name] == old.catalog["roots"][name]
    for key in ("strings", "shapes"):
        assert reader.catalog[key][: len(old.catalog[key])] == old.catalog[key]
    assert reader.catalog["routes"] == old.catalog["routes"]


def test_rehashed_locally_valid_alternate_is_rejected_by_native_regeneration(tmp_path):
    public = make_preview(tmp_path)
    baseline = PublicationReader(tmp_path)
    framed = copy.deepcopy(public["switching_analysis"])
    next(iter(framed["claims"].values()))["product"] += " Alternative fixture text"
    rehash(framed)
    alternate = packed_api().pack_report(framed)

    # Build independently hashed token and table parts with the same prefix
    # dictionary. The reader locally accepts the alternate's compiled report.
    strings, shapes = baseline._tables()
    writer = publication_v2.Writer(tmp_path, baseline.identity)
    writer.encoder.strings = list(strings)
    writer.encoder.shapes = list(shapes)
    writer.encoder._strings = {literal: i for i, literal in enumerate(strings)}
    writer.encoder._shapes = {tuple(keys): i for i, keys in enumerate(shapes)}
    boundary = writer.snapshot_tables = (len(strings), len(shapes))
    descriptor = writer.root(ROOT, alternate)
    writer.tables(boundary)

    reader = PublicationReader(tmp_path)
    reader.catalog["roots"][ROOT] = descriptor
    for name, parts, first in zip(
        ("strings", "shapes"), (writer.string_parts, writer.shape_parts), boundary, strict=True
    ):
        reader.catalog[name].extend(part for part in parts if part["first"] >= first)
    decoded = reader.materialize_range(reader.ranges(ROOT)[()])
    assert compact(packed_api().unpack_report(decoded)) == compact(framed)
    with pytest.raises(ValueError, match="native logical root mismatch: " + ROOT):
        publication_v2.verify_projection(reader, public)


def test_vendor_projection_retains_independently_owned_payload_and_selection(rich):
    baseline = compact(rich)
    vendor = "cisco"
    envelope = analysis_delivery.project_vendor(rich, vendor)
    study = analysis.selection_context(rich, dict(vendor=vendor))
    selected = analysis_delivery.select_vendor(envelope, study)
    selected["disclosure"]["pairs"][0]["claim_ids"].append("local mutation")
    second = analysis_delivery.select_vendor(envelope, study)
    assert "local mutation" not in second["disclosure"]["pairs"][0]["claim_ids"]
    next(iter(envelope["payload"]["claims"].values()))["issues"].append("payload mutation")
    envelope["payload"]["release_history"]["sources"][0]["issues"].append("history mutation")
    assert compact(rich) == baseline


def test_v2_flags_require_bool_complete_report_and_single_codec(tmp_path):
    for options, message in (
        ({"analysis_packed_delivery": True}, "v2"),
        ({"publication_format": "v2", "analysis_packed_delivery": 1}, "bool"),
        ({"publication_format": "v2", "analysis_packed_delivery": True}, "complete"),
        (
            {
                "publication_format": "v2",
                "analysis_vendor_delivery": True,
                "analysis_packed_delivery": True,
            },
            "combine",
        ),
    ):
        with pytest.raises(ValueError, match=message):
            publication.write_bundle(tmp_path, {}, **options)


def test_browser_packed_delivery_in_ordinary_ci(tmp_path, monkeypatch, rich, packed):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable")
    bundle = tmp_path / "bundle"
    # Exercise distinct source metadata and later token pages on a small real bundle.
    monkeypatch.setattr(publication_v2, "PAGE_LOGICAL", 4000)
    public = make_preview(bundle)
    exact = copy.deepcopy(rich)
    exact["release_history"]["sources"][0]["retained"]["revision_id"] = 9007199254740993
    rehash(exact)
    fixture = tmp_path / "packed.json"
    fixture.write_text(
        compact(
            {
                "rich": rich,
                "packed": packed,
                "exact": exact,
                "exact_packed": packed_api().pack_report(exact),
                "compiled": public["switching_analysis"],
            }
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [node, "tests/test_analysis_packing.js", str(bundle), str(fixture)],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "TZ": "UTC"},
        check=True,
        timeout=180,
    )
