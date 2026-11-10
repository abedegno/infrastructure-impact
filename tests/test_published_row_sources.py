"""Published Source ordinals retain native provenance and reject substituted metadata."""

import copy
import json
from collections import Counter
from hashlib import sha256
from pathlib import Path

import pytest
from jsonschema import ValidationError

from infrastructure_impact.application import publication_v2
from infrastructure_impact.application import switching_comparison as comparison
from infrastructure_impact.application.publication_reader import PublicationReader
from infrastructure_impact.application.switching_row_sources import ROOT, derive, membership_digest

pytest_plugins = ["test_publication_v2_reader"]
AT = "2026-11-07T18:00:00Z"


def rewrite_index(reader, change):
    value = reader.materialize_range(reader.ranges(ROOT)[()])
    change(value)
    strings, shapes = reader._tables()
    writer = publication_v2.Writer(reader.directory, reader.identity)
    writer.encoder.strings = list(strings)
    writer.encoder.shapes = list(shapes)
    writer.encoder._strings = {v: i for i, v in enumerate(strings)}
    writer.encoder._shapes = {tuple(v): i for i, v in enumerate(shapes)}
    writer.snapshot_tables = (len(strings), len(shapes))
    writer.root(ROOT, value)
    writer.tables()
    reader.catalog["roots"][ROOT] = writer.roots[ROOT]
    reader.catalog.update(strings=writer.string_parts, shapes=writer.shape_parts)
    reader.catalog.pop("table_transports", None)
    reader._strings = reader._shapes = None
    reader._roots.pop(ROOT, None)
    reader._ranges.pop(ROOT, None)
    return value


@pytest.mark.parametrize("missing_details", [False, True])
@pytest.mark.parametrize(
    "change",
    [
        lambda v: v.update(schema_version=1.0),
        lambda v: v.update(schema_version=True),
        lambda v: v.update(sources_count=float(v["sources_count"])),
        lambda v: v["rows"][0].update(row_ordinal=0.0),
        lambda v: v["sources_range"].update(first_token=float(v["sources_range"]["first_token"])),
        lambda v: v.update(generated_at="2025-01-01T00:00:00Z"),
        lambda v: v["publication"].update(id="0" * 32),
        lambda v: v.update(definition_sha256="0" * 64),
        lambda v: v.update(observation_end="2025-01-01"),
        lambda v: v.update(scope_level="model_qualified"),
        lambda v: v.update(requested_cve_ids=[]),
        lambda v: v["rows"][0].update(row_id="aruba:os_family:all"),
        lambda v: v["rows"][0].update(row_ordinal=1),
        lambda v: v["rows"][0].update(row_ordinal=False),
        lambda v: v["rows"][0].update(published_row_sha256="0" * 64),
        lambda v: v["rows"][2].update(claim_membership_sha256="0" * 64),
        lambda v: v["sources_range"].update(logical_sha256="0" * 64),
        lambda v: v.update(sources_count=v["sources_count"] + 1),
        lambda v: v.update(sources_count=True),
        lambda v: v["rows"].pop(),
        lambda v: v["rows"].append(copy.deepcopy(v["rows"][0])),
        lambda v: v.update(extra=True),
        *[
            lambda v, x=x: v["rows"][2].update(source_ordinals=x)
            for x in [[True], [0.0], [-1], [0, 0], [1, 0], [9007199254740992], [1]]
        ],
    ],
)
def test_present_rehashed_index_corruption_rejects(
    generation, monkeypatch, change, missing_details
):
    reader = PublicationReader(generation)
    rewrite_index(reader, change)
    if missing_details:
        del reader.catalog["switching"]["detail_indexes"]
    monkeypatch.setattr(reader, "iter_claims", lambda: pytest.fail("corruption hidden by fallback"))
    with pytest.raises((ValueError, ValidationError)):
        reader.switching_selection({"vendor": "arista"}, evaluated_at=AT)


def test_semantically_wrong_rehashed_index_fails_native_gate(native_projection):
    reader, projected = native_projection
    rewrite_index(reader, lambda v: v["rows"][2].update(source_ordinals=[]))
    # Transport, shape and all provenance identities remain valid; only the
    # independent native Source membership can distinguish this substitution.
    with pytest.raises(ValueError, match="native logical root mismatch"):
        publication_v2.verify_projection(reader, projected)


def test_old_artifact_fallback_and_unknown_root_membership(native_projection, monkeypatch):
    reader, projected = native_projection
    del reader.catalog["roots"][ROOT]
    original, seen = reader.iter_claims, []

    def claims():
        seen.append(1)
        yield from original()

    monkeypatch.setattr(reader, "iter_claims", claims)
    got = reader.switching_selection({"vendor": "arista"}, evaluated_at=AT)
    expected = comparison.summary(
        comparison.select_report(
            projected["switching_comparison"], vendor="arista", evaluated_at=AT
        )
    )
    assert got == expected and seen == [1]
    publication_v2.verify_projection(reader, projected)
    reader.catalog["roots"]["unexpected.json"] = reader.catalog["roots"]["snapshot.json"]
    with pytest.raises(ValueError, match="mandatory logical root"):
        publication_v2.verify_projection(reader, projected)


@pytest.mark.parametrize(
    "options",
    [
        {"vendor": "arista", "cve_ids": []},
        {"window": "2025"},
        {"scope_level": "model_qualified"},
        {"scope_level": None},
        {"window": None},
        {"extra": True},
        {"vendor": "invalid"},
    ],
)
def test_ineligible_options_keep_complete_reducer(generation, monkeypatch, options):
    reader = PublicationReader(generation)
    native = json.loads(b"".join(reader.stream_root("switching-comparison.json")))
    original, seen = reader.iter_claims, []

    def claims():
        seen.append(1)
        yield from original()

    monkeypatch.setattr(reader, "iter_claims", claims)
    if (
        options.get("scope_level", "") is None
        or options.get("window", "") is None
        or "extra" in options
        or options.get("vendor") == "invalid"
    ):
        with pytest.raises(ValueError):
            reader.switching_selection(options, evaluated_at=AT)
    else:
        assert reader.switching_selection(options, evaluated_at=AT) == comparison.summary(
            comparison.select_report(native, **options, evaluated_at=AT)
        )
    assert seen == [1]


def test_selected_source_chunks_read_once_and_no_claim_routes(generation, monkeypatch):
    reader = PublicationReader(generation)
    seen = Counter()
    fetch = reader.fetch

    def counted(descriptor, **kwargs):
        if kwargs.get("kind") == "detail_index":
            seen[descriptor["path"]] += 1
        return fetch(descriptor, **kwargs)

    monkeypatch.setattr(reader, "fetch", counted)
    monkeypatch.setattr(reader, "_claim_routes", lambda: pytest.fail("selected claims"))
    got = reader.switching_selection({"vendor": "arista"}, evaluated_at=AT)
    assert got["sources"] and seen
    assert set(seen.values()) == {1}
    assert not reader.switching_selection({"vendor": "aruba"}, evaluated_at=AT)["sources"]


@pytest.mark.parametrize("tamper", ["count", "range", "hash", "ordinal"])
def test_source_chunk_corruption_rejects(generation, tamper):
    reader = PublicationReader(generation)
    chunk = reader.catalog["switching"]["detail_indexes"]["sources"][0]
    if tamper == "count":
        chunk["count"] += 1
    else:
        entries = reader.fetch(chunk["part"], kind="detail_index")
        if tamper == "range":
            entries[0]["range"]["end_token"] += 1
        elif tamper == "hash":
            entries[0]["range"]["logical_sha256"] = "0" * 64
        else:
            entries[0]["ordinal"] = True
        chunk["part"] = publication_v2.Writer(reader.directory, reader.identity).part(
            "detail_index", entries
        )
    with pytest.raises((ValueError, ValidationError)):
        reader.switching_selection({"vendor": "arista"}, evaluated_at=AT)


def test_missing_source_detail_capability_keeps_complete_fallback(generation, monkeypatch):
    reader = PublicationReader(generation)
    del reader.catalog["switching"]["detail_indexes"]
    original, seen = reader.iter_claims, []

    def claims():
        seen.append(1)
        yield from original()

    monkeypatch.setattr(reader, "iter_claims", claims)
    assert reader.switching_selection({"vendor": "arista"}, evaluated_at=AT)["sources"]
    assert seen == [1]


def test_direct_v2_writer_freshly_validates_and_omits_only_at_size_boundary(
    native_projection, tmp_path, monkeypatch
):
    from infrastructure_impact.application import switching_evidence as contracts
    from infrastructure_impact.application import switching_row_sources

    _, projected = native_projection
    original, validations = contracts.validate_comparison, []

    def validate(*args, **kwargs):
        validations.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(contracts, "validate_comparison", validate)
    first = publication_v2.write_bundle(tmp_path / "first", projected)
    assert ROOT in first["roots"] and validations == [1]
    monkeypatch.setattr(switching_row_sources, "MAX_BYTES", 1)
    second = publication_v2.write_bundle(tmp_path / "omitted", projected)
    assert ROOT not in second["roots"] and validations == [1, 1]
    projected["switching_comparison"]["inputs"]["evidence"]["claims"][0]["source"][
        "source_locator"
    ] += "/mutated"
    with pytest.raises((ValueError, ValidationError)):
        publication_v2.write_bundle(tmp_path / "changed", projected)


def test_index_limit_precedes_materialization_and_lower_working_limit(generation, monkeypatch):
    reader = PublicationReader(generation)
    root = reader.root(ROOT)
    root["logical"]["bytes"] = 8_000_001
    original = reader.materialize_range

    def materialize(bound, **kwargs):
        assert bound["root"] != ROOT, "oversized metadata materialized"
        return original(bound, **kwargs)

    monkeypatch.setattr(reader, "materialize_range", materialize)
    with pytest.raises(ValueError, match="index byte budget"):
        reader.switching_selection({"vendor": "arista"}, evaluated_at=AT)
    with pytest.raises(ValueError, match="budget"):
        PublicationReader(generation, limits={"working": 1}).switching_selection(
            {"vendor": "arista"}, evaluated_at=AT
        )


def test_nested_event_only_sources_four_field_identity_and_global_order(generation):
    reader = PublicationReader(generation)
    report = json.loads(b"".join(reader.stream_root("switching-comparison.json")))
    source = report["sources"][0]
    variants = [dict(source)] + [
        {**source, field: value}
        for field, value in [
            ("source_locator", "/different"),
            ("source_sha256", "b" * 64),
            ("retrieved_at", "2026-01-01T00:00:00Z"),
            ("source_url", source["source_url"] + "?v=2"),
        ]
    ]
    # Independently literal claim membership: only an event references this claim;
    # every nested occurrence contributes, repeated sources deduplicate exactly.
    report["inputs"]["evidence"]["claims"] = [
        {"claim_id": "a" * 64, "unused": {"nested": variants + [variants[0]]}},
        {"claim_id": "b" * 64, "unused": {"nested": [variants[0]]}},
        {"claim_id": "c" * 64, "unused": {"nested": [{**source, "source_locator": "/excluded"}]}},
    ]
    for row in report["rows"]:
        row.update(claim_ids=[], events=[])
    report["rows"][0]["events"] = [{"claim_ids": ["a" * 64]}]
    report["rows"][1]["claim_ids"] = ["b" * 64]
    report["sources"] = sorted(
        variants, key=lambda s: json.dumps(s, sort_keys=True, separators=(",", ":"))
    )
    got = derive(report)
    assert got["rows"][0]["source_ordinals"] == [0, 1, 2, 3, 4]
    assert got["rows"][1]["source_ordinals"] == [report["sources"].index(variants[0])]
    assert got["rows"][2]["source_ordinals"] == []
    assert (
        membership_digest(report["rows"][0])
        == sha256(("[" + '"' + "a" * 64 + '"' + "]").encode()).hexdigest()
    )
    assert membership_digest(report["rows"][2]) == sha256(b"[]").hexdigest()
    report["sources"].reverse()
    with pytest.raises(ValueError, match="global Sources order"):
        derive(report)
    report["sources"].reverse()
    report["sources"].append(report["sources"][-1])
    with pytest.raises(ValueError, match="duplicate global Source"):
        derive(report)
    report["sources"] = report["sources"][:-2]
    with pytest.raises(ValueError, match="missing globally"):
        derive(report)


def rich_data():
    """All vendors retain nested Unicode, draft and fixed-only provenance."""
    from test_static_delivery import dataset

    from infrastructure_impact.application import switching_evidence as contracts

    data = dataset()
    evidence = copy.deepcopy(
        json.loads((Path(__file__).parent / "fixtures/switching-cases.json").read_text())[
            "evidence"
        ]
    )
    original = evidence["claims"][0]
    evidence["claims"] = []
    for vendor, family, product, url in [
        ("cisco", "cisco-iosxe", "IOS XE", "https://www.cisco.com/synthetic"),
        ("aruba", "aruba-aoscx", "AOS-CX", "https://csaf.arubanetworking.hpe.com/synthetic"),
        ("arista", "arista-eos", "EOS", "https://www.arista.com/synthetic"),
    ]:
        for mode in ("affected", "draft", "fixed"):
            claim = copy.deepcopy(original)
            claim.update(
                vendor=vendor,
                family=family,
                product=product,
                named_platforms=[],
                platform_bindings=[],
                scope_level="os_family",
            )
            if mode == "draft":
                claim["publisher"]["status"] = "draft"
            elif mode == "fixed":
                claim["status"] = "fixed"

            def replace_sources(node):
                if isinstance(node, dict):
                    if set(node) == {
                        "source_url",
                        "source_sha256",
                        "retrieved_at",
                        "source_locator",
                    }:
                        node["source_url"] = url
                        node["source_locator"] += "/" + mode + "/é😀"
                    else:
                        for child in node.values():
                            replace_sources(child)
                elif isinstance(node, list):
                    for child in node:
                        replace_sources(child)

            replace_sources(claim)
            # Retain an otherwise unused nested score Source independently of
            # the main Source, with the same URL/hash/time and another locator.
            claim["scores"][0]["source"]["source_locator"] += "/unused-score"
            claim["claim_id"] = contracts.definition_sha256(
                {k: v for k, v in claim.items() if k != "claim_id"}
            )
            evidence["claims"].append(claim)
    data["research"]["switching_input"] = evidence
    return data


@pytest.fixture(scope="module")
def rich_generation(tmp_path_factory):
    from infrastructure_impact.application.publication import publish

    return publish(
        rich_data(), tmp_path_factory.mktemp("published-rich-vendors"), publication_format="v2"
    )


@pytest.mark.parametrize("vendor", ["cisco", "aruba", "arista"])
@pytest.mark.parametrize("at", [AT, "2027-12-01T00:00:00Z"])
def test_nonempty_vendor_native_summary_csv_unicode_and_draft_provenance(
    rich_generation, monkeypatch, vendor, at
):
    from infrastructure_impact.exports import switching_csv

    reader = PublicationReader(rich_generation)
    native = json.loads(b"".join(reader.stream_root("switching-comparison.json")))
    expected = comparison.summary(comparison.select_report(native, vendor=vendor, evaluated_at=at))
    monkeypatch.setattr(
        reader, "iter_claims", lambda: pytest.fail("eligible vendor decoded claims")
    )
    actual = reader.switching_selection({"vendor": vendor}, evaluated_at=at)
    assert actual == expected
    assert switching_csv(actual) == switching_csv(expected)
    assert len(actual["sources"]) >= 4
    assert any("/draft/" in source["source_locator"] for source in actual["sources"])
    assert any("/fixed/" in source["source_locator"] for source in actual["sources"])
    assert any("/unused-score" in source["source_locator"] for source in actual["sources"])


def test_public_writer_rejects_caller_supplied_source_index_authority(native_projection, tmp_path):
    _, projected = native_projection
    projected["switching_row_sources"] = {"validated": True, "rows": [], "sources_count": 0}
    with pytest.raises(ValueError, match="writer-owned"):
        publication_v2.write_bundle(tmp_path, projected)


def force_summary_diagnostic_fallback(monkeypatch):
    """Exercise the established compatibility validator without changing it."""
    contracts = comparison.contracts
    compiled = contracts._compiled_validators()

    class DiagnosticFallback:
        def is_valid(self, value):
            return False

    monkeypatch.setattr(
        contracts,
        "_compiled_validators",
        lambda: {**compiled, "switching-summary-v1.json": DiagnosticFallback()},
    )


@pytest.mark.parametrize("compatibility", [False, True])
def test_indexed_summary_validation_avoids_pairwise_source_comparisons(
    rich_generation, monkeypatch, compatibility
):
    import jsonschema._utils as utils

    from infrastructure_impact.exports import switching_csv

    reader = PublicationReader(rich_generation)
    native = json.loads(b"".join(reader.stream_root("switching-comparison.json")))
    expected = comparison.summary(comparison.select_report(native, evaluated_at=AT))
    assert len(expected["sources"]) > 1
    if compatibility:
        force_summary_diagnostic_fallback(monkeypatch)
    source_comparisons = []
    original = utils._mapping_equal
    fields = set(comparison.contracts._SOURCE_FIELDS)

    def mapping_equal(one, two):
        if set(one) == fields and set(two) == fields:
            source_comparisons.append(1)
        return original(one, two)

    monkeypatch.setattr(utils, "_mapping_equal", mapping_equal)
    monkeypatch.setattr(reader, "iter_claims", lambda: pytest.fail("eligible path read claims"))
    actual = reader.switching_selection({}, evaluated_at=AT)
    assert actual == expected
    assert switching_csv(actual) == switching_csv(expected)
    assert len(source_comparisons) == 0, "indexed summary used pairwise Source mapping equality"


@pytest.mark.parametrize("compatibility", [False, True])
def test_indexed_summary_validation_rejects_authenticated_duplicate_sources(
    rich_generation, tmp_path, monkeypatch, compatibility
):
    reader = PublicationReader(rich_generation)
    projected = json.loads(b"".join(reader.stream_root("snapshot.json")))
    report = json.loads(b"".join(reader.stream_root("switching-comparison.json")))
    projected["switching_comparison"] = report
    projected["switching_evidence"] = report["inputs"]["evidence"]
    if "switching-release-history.json" in reader.catalog["roots"]:
        projected["switching_release_history"] = json.loads(
            b"".join(reader.stream_root("switching-release-history.json"))
        )
    membership = derive(report)
    row = membership["rows"][0]
    duplicate = report["sources"][row["source_ordinals"][0]]
    row["source_ordinals"].append(membership["sources_count"])
    membership["sources_count"] += 1
    original = publication_v2.Writer.root

    def root(self, name, value, **kwargs):
        # A foreign publisher can serialize duplicate Source values into distinct,
        # correctly hashed intervals. Keep all row/header/membership proofs intact
        # so only the final complete summary contract rejects this artifact.
        if name == "snapshot.json":
            value = {
                **value,
                "switching_comparison": {
                    **value["switching_comparison"],
                    "sources": [*value["switching_comparison"]["sources"], duplicate],
                },
            }
        return original(self, name, value, **kwargs)

    monkeypatch.setattr(publication_v2.Writer, "root", root)
    publication_v2._write_bundle(tmp_path, projected, membership)
    if compatibility:
        force_summary_diagnostic_fallback(monkeypatch)
    foreign = PublicationReader(tmp_path)
    monkeypatch.setattr(foreign, "iter_claims", lambda: pytest.fail("eligible path read claims"))
    with pytest.raises(ValidationError, match="duplicate|non-unique"):
        foreign.switching_selection({"vendor": "cisco"}, evaluated_at=AT)
