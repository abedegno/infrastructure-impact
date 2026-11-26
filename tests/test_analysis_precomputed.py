"""Precomputed selected delivery uses exact, bounded native JSON and source authority."""

import gzip
import json
from hashlib import sha256
from pathlib import Path

import pytest

from infrastructure_impact.application import switching_analysis as analysis


def test_view_is_single_native_json_document_split_on_byte_boundaries():
    from infrastructure_impact.application import analysis_precomputed as precomputed

    # The first byte of the three-byte code point ends the first decoded slice.
    report = {"note": "x" * 3_999_990 + "☃", "id": 9007199254740997, "score": 5.7}
    options = dict(vendor=None, window="all", scope_level="os_family", cve_ids=None)
    report["selection"] = {"requested_window": "all"}
    expected = json.dumps(report, ensure_ascii=False, separators=(",", ":")).encode()
    parts = {}
    view = precomputed.encode_view(report, options, parts.__setitem__)
    assert view["options"] == options
    assert view["selection"] == report["selection"]
    assert view["decoded"] == dict(bytes=len(expected), sha256=sha256(expected).hexdigest())
    assert len(view["chunks"]) == 2
    for index, chunk in enumerate(view["chunks"]):
        wire = parts[chunk["part"]["path"]]
        decoded = expected[index * 4_000_000 : (index + 1) * 4_000_000]
        digest = sha256(wire).hexdigest()
        assert chunk == dict(
            offset=index * 4_000_000,
            decoded=dict(bytes=len(decoded), sha256=sha256(decoded).hexdigest()),
            part=dict(path=f"data/v2/{digest}.json.gz", bytes=len(wire), sha256=digest),
        )
        assert wire[:10] == bytes.fromhex("1f8b08000000000000ff")
        assert gzip.decompress(wire) == decoded
    assert precomputed.encode_view(report, options, None) == view


def test_view_candidate_native_export_order(tmp_path):
    from infrastructure_impact.application import analysis_precomputed as precomputed

    compiled = json.loads(Path("tests/fixtures/switching-analysis-vectors.json").read_bytes())[
        "compiled"
    ]
    options = dict(vendor="cisco", window="2025", scope_level="os_family", cve_ids=None)
    study = analysis.selection_context(compiled, options)
    expected = analysis.select_report(compiled, study)
    manifest = precomputed.write_views(tmp_path, compiled, [options])
    assert manifest["source_content_sha256"] == compiled["content_sha256"]
    assert precomputed.validate_manifest(manifest, study) == manifest
    bad_study = dict(study, definition=dict(study["definition"], start_date="2022-01-01"))
    with pytest.raises(ValueError, match="definition"):
        precomputed.read_selected(tmp_path, manifest, bad_study)
    actual = precomputed.read_selected(tmp_path, manifest, study)

    def encode(report):
        return json.dumps(report, ensure_ascii=False, separators=(",", ":"))

    assert encode(actual) == encode(expected)
    assert analysis.analysis_csv_export(actual) == analysis.analysis_csv_export(expected)
    assert analysis.csv_export(actual["upgrades"]) == analysis.csv_export(expected["upgrades"])


def write_candidate(directory, compiled, option, report):
    from infrastructure_impact.application import analysis_precomputed as precomputed

    def write(path, raw):
        target = directory / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)

    view = precomputed.encode_view(report, option, write)
    return precomputed.build_manifest(compiled, [view])


def test_selected_native_enforces_ascii_output_cap_at_exact_boundary(tmp_path):
    from infrastructure_impact import publication_codec as codec
    from infrastructure_impact.application import analysis_precomputed as precomputed

    compiled = numeric_source()
    option = precomputed.DEFAULT_OPTION | {"vendor": "arista"}
    study = analysis.selection_context(compiled, option)
    report = analysis.select_report(compiled, study)
    report["model_coverage"]["interpretation"] = "Authored ☃ and 🛰 text"
    manifest = write_candidate(tmp_path, compiled, option, report)
    wire_size = manifest["views"][0]["decoded"]["bytes"]
    output_size = len(json.dumps(report, ensure_ascii=True, separators=(",", ":")))
    assert wire_size < output_size - 1
    assert precomputed.read_selected(tmp_path, manifest, study, output_size) == report
    with pytest.raises(ValueError, match="decoded byte budget"):
        codec.charge_value(report, codec.Budget(output_size - 1))
    with pytest.raises(ValueError, match="decoded byte budget"):
        precomputed.read_selected(tmp_path, manifest, study, output_size - 1)
    with pytest.raises(ValueError, match="Selected analysis decoded byte budget"):
        precomputed.read_selected(tmp_path, manifest, study, wire_size - 1)


def test_benchmark_rejects_oversized_contexts_before_reading(tmp_path):
    import shutil
    import subprocess

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is unavailable")
    directory = tmp_path / "publication"
    directory.mkdir()
    contexts = tmp_path / "oversized.json"
    with contexts.open("wb") as stream:
        stream.truncate(2_000_001)
    destination = tmp_path / "receipt.json"
    # Fail if the harness attempts to read this file before checking its size.
    guard = tmp_path / "guard.cjs"
    guard.write_text(
        """
const fs = require('node:fs');
const input = process.argv[6];
const readFile = fs.readFileSync;
const open = fs.openSync;
const read = fs.readSync;
let descriptor;
fs.openSync = (path, ...options) => {
  const handle = open(path, ...options);
  if (path === input) descriptor = handle;
  return handle;
};
fs.readFileSync = (path, ...options) => {
  if (path === input || path === descriptor) throw Error('Unexpected context read');
  return readFile(path, ...options);
};
fs.readSync = (handle, ...options) => {
  if (handle === descriptor) throw Error('Unexpected context read');
  return read(handle, ...options);
};
"""
    )
    result = subprocess.run(
        [
            node,
            "--require",
            guard,
            "checks/benchmark_analysis_delivery.cjs",
            "infrastructure_impact/web",
            directory,
            "baseline",
            destination,
            contexts,
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 1
    assert "Study contexts byte bound" in result.stderr, result.stderr
    assert not destination.exists()


def test_browser_precomputed_delivery(tmp_path):
    import shutil
    import subprocess

    from test_analysis_delivery import rich_source

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is unavailable")
    compiled = rich_source()
    (tmp_path / "source.json").write_bytes(json.dumps({"compiled": compiled}).encode())
    from infrastructure_impact.application import analysis_precomputed as precomputed

    manifest = precomputed.write_views(
        tmp_path,
        compiled,
        [{}, {"vendor": "cisco", "window": "2025"}, {"vendor": "aruba", "window": "undated"}],
    )
    (tmp_path / "selected.json").write_bytes(precomputed.compact_bytes(manifest))

    numeric = numeric_source()
    (tmp_path / "numeric-source.json").write_bytes(precomputed.compact_bytes({"compiled": numeric}))
    numeric_manifest = precomputed.write_views(tmp_path, numeric, [{"vendor": "arista"}])
    (tmp_path / "numeric-selected.json").write_bytes(precomputed.compact_bytes(numeric_manifest))

    from infrastructure_impact.application import publication_v2

    public = public_projection()
    preview = tmp_path / "preview"
    publication_v2.write_bundle(
        preview,
        public,
        analysis_precomputed_delivery=True,
        analysis_precomputed_options=[{"vendor": "cisco"}, {"vendor": "aruba"}],
    )
    (tmp_path / "preview-source.json").write_bytes(
        precomputed.compact_bytes(public["switching_analysis"])
    )
    subprocess.run([node, "tests/test_analysis_precomputed.js", tmp_path], check=True, timeout=120)


def public_projection():
    from test_static_delivery import dataset

    from infrastructure_impact.application import publication

    data = dataset()
    data["publication"] = {"id": "a" * 32, "advisory_schema_version": 2}
    data["current_evidence"]["publication"] = data["publication"]
    data["research"]["switching_input"] = json.loads(
        Path("tests/fixtures/switching-cases.json").read_text()
    )["evidence"]
    return publication.public_projection(
        data, publication_format="v2", include_switching_analysis=True
    )


def test_public_writer_preview_keeps_legacy_descriptors_and_checks_native_membership(tmp_path):
    from infrastructure_impact.application import analysis_precomputed as precomputed
    from infrastructure_impact.application import publication, publication_v2
    from infrastructure_impact.application.publication_reader import PublicationReader

    public = public_projection()
    publication.write_bundle(tmp_path / "ordinary", public, publication_format="v2")
    ordinary = PublicationReader(tmp_path / "ordinary")
    assert precomputed.ROOT not in ordinary.catalog["roots"]
    assert not (tmp_path / "ordinary" / "analysis-precomputed.js").exists()
    options = [{"vendor": "cisco"}, {"vendor": "aruba", "window": "2025"}]
    out = tmp_path / "preview"
    publication_v2.write_bundle(
        out, public, analysis_precomputed_delivery=True, analysis_precomputed_options=options
    )
    preview = publication_v2.inspect_bundle(out, {})
    script = (out / "analysis-precomputed.js").read_bytes()
    assert f"/assets/{sha256(script).hexdigest()}.js" in (out / "index.html").read_text()
    actual = preview.switching_analysis(options={"vendor": "cisco"})
    assert precomputed.compact_bytes(actual) == precomputed.compact_bytes(
        ordinary.switching_analysis(options={"vendor": "cisco"})
    )
    assert preview._strings is None and preview._shapes is None
    custom = {"vendor": "cisco", "cve_ids": []}
    assert preview.switching_analysis(options=custom) == ordinary.switching_analysis(options=custom)
    for key in ("strings", "shapes"):
        entries = ordinary.catalog[key]
        assert preview.catalog[key][: len(entries)] == entries
    for key in ("switching", "archive", "routes"):
        assert preview.catalog[key] == ordinary.catalog[key]
    assert {
        name: preview.catalog["roots"][name] for name in ordinary.catalog["roots"]
    } == ordinary.catalog["roots"]
    assert all(
        preview.catalog["table_transports"][k] == v
        for k, v in ordinary.catalog.get("table_transports", {}).items()
    )
    publication_v2.verify_projection(preview, public, analysis_precomputed_options=options)
    with pytest.raises(ValueError, match="native selected|membership"):
        publication_v2.verify_projection(preview, public, analysis_precomputed_options=options[:1])
    sidecar, _ = precomputed.manifest_descriptor(preview.root(precomputed.ROOT))
    (out / sidecar).write_bytes(b"{}")
    with pytest.raises(ValueError, match="Native selected analysis asset"):
        publication_v2.verify_projection(preview, public, analysis_precomputed_options=options)


def test_preview_writer_rejects_flag_options_and_forged_authority(tmp_path):
    import copy

    from infrastructure_impact.application import analysis_delivery, publication, publication_v2

    for kwargs in (
        dict(analysis_precomputed_delivery=True),
        dict(publication_format="v2", analysis_precomputed_delivery=1),
        dict(publication_format="v2", analysis_precomputed_options=[{}]),
        dict(
            publication_format="v2",
            analysis_precomputed_delivery=True,
            analysis_vendor_delivery=True,
        ),
        dict(publication_format="v2", analysis_precomputed_delivery=True),
    ):
        with pytest.raises(ValueError, match="[Pp]recomputed"):
            publication.write_bundle(tmp_path / "rejected", {}, **kwargs)
    assert not (tmp_path / "rejected").exists()

    public = public_projection()
    forged = copy.deepcopy(public)
    # This reduced source passes standalone validation and supplies its own
    # fingerprint. Complete enclosing evidence still owns publication membership.
    source = analysis_delivery.project_vendor(public["switching_analysis"], "aruba")["payload"]
    analysis.validate_report(source)
    forged["switching_analysis"] = source
    with pytest.raises(ValueError, match="ownership|membership|reconciliation|selection"):
        publication_v2.write_bundle(tmp_path / "forged", forged, analysis_precomputed_delivery=True)
    assert not (tmp_path / "forged").exists()


def test_preview_default_membership_and_unbound_gzip(tmp_path):
    import copy

    from infrastructure_impact.application import analysis_precomputed as precomputed
    from infrastructure_impact.application import publication, publication_v2

    public = public_projection()
    source = public["switching_analysis"]
    year = int(source["observation_end"][:4]) - 1
    expected = {
        (vendor, window, "os_family", None)
        for vendor in (None, "cisco", "aruba", "arista")
        for window in ("all", str(year))
    }
    actual = precomputed.options_for(source, None)
    assert {(o["vendor"], o["window"], o["scope_level"], o["cve_ids"]) for o in actual} == expected
    with pytest.raises(ValueError, match="Duplicate"):
        precomputed.options_for(source, [{}, {"window": "all"}])
    with pytest.raises(ValueError, match="options"):
        precomputed.options_for(source, [{"cve_ids": []}])
    publication_v2.write_bundle(tmp_path, public, analysis_precomputed_delivery=True)
    reader = publication_v2.inspect_bundle(tmp_path, {})
    manifest = reader._precomputed_manifest()
    assert [v["options"] for v in manifest["views"]] == actual
    for change in (
        lambda m: m["views"].append(m["views"][0]),
        lambda m: m["views"][0]["chunks"][0].update(offset=1),
        lambda m: m["views"][0]["decoded"].update(bytes=128_000_001),
        lambda m: m["views"][0]["chunks"][0]["part"].update(path="../forged.json.gz"),
        lambda m: m.update(definition_sha256="0" * 64),
    ):
        changed = copy.deepcopy(manifest)
        change(changed)
        with pytest.raises(ValueError):
            precomputed.validate_manifest(changed, reader.identity)
    extra = gzip.compress(b"unbound", mtime=0)
    (tmp_path / f"data/v2/{sha256(extra).hexdigest()}.json.gz").write_bytes(extra)
    publication.write_manifest(tmp_path, public)
    with pytest.raises(ValueError, match="unbound"):
        publication_v2.inspect_bundle(tmp_path, {})


def numeric_source():
    from test_switching_kev_reconciliation import AT, CID, claim, inputs

    from infrastructure_impact.adapters.cvss import public_metrics

    c = claim()
    c["scores"] = public_metrics(
        [
            dict(
                system="CVSS",
                version="3.1",
                value=7.5,
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cve_id=CID,
                product_ids=[],
                scope="cve_specific",
                source=c["source"],
                origin="vendor_advisory",
                validation="valid",
                provider="Arista",
            )
        ]
    )
    _, _, _, study = inputs([c])
    retained = dict(
        vendor="arista",
        advisory_id="SA137",
        cves=[CID],
        document_status="draft",
        source_url=c["source"]["source_url"],
        sha256="b" * 64,
        source_observed_at=AT,
        revision_id=9007199254740997,
        evidence_id=9007199254740999,
    )
    return analysis.build_report([], [retained], study)


def change_release_date(history):
    release = next(node for node in history["releases"] if node["history"])
    release["history"][0]["reported_release_date"] = "2024-02-31"
    release["reported_release_dates"] = sorted(
        {row["reported_release_date"] for row in release["history"] if row["reported_release_date"]}
    )


def add_unused_compact_reference(upgrades, kind):
    compact = upgrades["requirements"]
    if kind == "facts":
        old = next(
            f for f in compact["facts"].values() if isinstance(f, dict) and "source_url" in f
        )
        fact = dict(old, source_locator="authored-unused")
        compact["facts"][analysis._hash(fact)] = fact
    elif kind == "inference":
        group = dict(compact["inference_groups"][0], maximum_affected="17.15.99")
        group.pop("group_id")
        group["group_id"] = analysis._hash(group)
        compact["inference_groups"].append(group)
    else:
        compact["source_groups"][0]["advisory_id"] = "authored-unused"
    compact["content_sha256"] = analysis._hash(
        {key: value for key, value in compact.items() if key != "content_sha256"}
    )


def add_empty_disclosure_bundle(report):
    pair = report["pairs"][0]
    report["bundles"].append(
        dict(
            kind="explicit_publisher_bundle",
            vendor=pair["vendor"],
            family=pair["family"],
            publisher_id="authored-bundle",
            initial_published_at=None,
            date_period="unknown",
            member_advisory_ids=["authored-unselected"],
            member_cve_ids=[],
            selected_advisory_ids=[],
            selected_cve_ids=[],
            source=pair["source"],
            upstream=None,
        )
    )


def change_model_group(report, field):
    row = next(m for m in report["models"] if m["by_source"])
    group = row["by_source"][0]
    if field == "duplicate":
        row["by_source"].append(group)
    else:
        old = group["source"]
        changed = {
            "source_url": "https://example.org/authored-unowned",
            "source_sha256": "1" * 64,
            "retrieved_at": "2024-01-01T00:00:00Z",
            "source_locator": "authored-unowned",
        }
        group["source"] = old | {field: changed[field]}


def test_selected_native_allows_bound_model_without_source_group(tmp_path):
    from test_analysis_delivery import rich_source

    from infrastructure_impact.application import analysis_precomputed as precomputed

    compiled = rich_source()
    option = precomputed.DEFAULT_OPTION
    study = analysis.selection_context(compiled, option)
    report = analysis.select_report(compiled, study)
    row = next(m for m in report["model_coverage"]["models"] if m["by_source"])
    assert row["claim_ids"]
    row["by_source"] = []
    manifest = write_candidate(tmp_path, compiled, option, report)
    assert precomputed.read_selected(tmp_path, manifest, study) == report


@pytest.mark.parametrize(
    ("child", "mutate", "failure"),
    [
        ("disclosure", lambda d: d["coverage"].update(selected_affected_claims=999), "Disclosure"),
        (
            "disclosure",
            lambda d: d["coverage"].update(unsupported_advisory_types=["unknown"]),
            "Disclosure coverage",
        ),
        ("disclosure", add_empty_disclosure_bundle, "Disclosure.*bundle"),
        ("model_coverage", lambda d: d["models"][0]["counts"].update(claims=999), "Model"),
        *(
            ("model_coverage", lambda d, field=field: change_model_group(d, field), "Model.*source")
            for field in (
                "source_url",
                "source_sha256",
                "retrieved_at",
                "source_locator",
                "duplicate",
            )
        ),
        (
            "kev_reconciliation",
            lambda d: d["summary"].update(state_counts={"unknown": 999}),
            "Reconciliation",
        ),
        ("release_history", lambda d: d.update(method="forged"), "Release"),
        ("release_history", change_release_date, "Invalid analysis DTO"),
        (
            "kev_reconciliation",
            lambda d: d["catalogue"].update(released_at="2026-02-31T12:00:00Z"),
            "Invalid analysis DTO",
        ),
        (
            "disclosure",
            lambda d: d["pairs"][0]["source"].update(source_url="https://example.org/%GG"),
            "Invalid analysis DTO",
        ),
        ("upgrades", lambda d: d["rows"][0].update(supported_event_count=999), "event count"),
        ("upgrades", lambda d: add_unused_compact_reference(d, "facts"), "reference closure"),
        ("upgrades", lambda d: add_unused_compact_reference(d, "inference"), "reference closure"),
        ("upgrades", lambda d: add_unused_compact_reference(d, "source"), "source group"),
    ],
)
def test_selected_native_rechecks_child_report_semantics(tmp_path, child, mutate, failure):
    from test_analysis_delivery import rich_source

    from infrastructure_impact.application import analysis_precomputed as precomputed

    compiled = rich_source()
    option = dict(vendor=None, scope_level="os_family", window="all", cve_ids=None)
    study = analysis.selection_context(compiled, option)
    report = analysis.select_report(compiled, study)
    mutate(report[child])

    if failure in ("Disclosure coverage", "Disclosure.*bundle"):
        from infrastructure_impact.application import switching_disclosure

        switching_disclosure.validate_report(report[child])
    manifest = write_candidate(tmp_path, compiled, option, report)
    with pytest.raises(ValueError, match=failure):
        precomputed.read_selected(tmp_path, manifest, study)
