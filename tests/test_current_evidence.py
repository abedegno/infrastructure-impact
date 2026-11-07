"""Synthetic policies exercise retained/current separation and its trust boundary."""

import base64
import copy
import importlib
import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from infrastructure_impact.plugins.contracts import VendorPlugin
from infrastructure_impact.plugins.registry import PluginRegistry, default_registry
from infrastructure_impact.plugins.shared import structured
from infrastructure_impact.storage.repository import connect, evidence

URL = "https://example.invalid/reviewed"
AT = "2026-11-06T12:00:00Z"
RAW = b"synthetic reviewed representation"
DIGEST = sha256(RAW).hexdigest()


def api():
    return importlib.import_module("infrastructure_impact.application.current_evidence")


def identity():
    return importlib.import_module("infrastructure_impact.application.evidence_identity")


def synthetic_policy(records, context):
    target = next((r for r in records if r["advisory_id"] == "EXCLUDED"), None)
    if target is None:
        return {"decisions": [], "issues": []}
    proof = (
        {k: v for k, v in context["sources"][0].items() if k != "raw_b64"}
        if context["sources"]
        else {
            "source_url": URL,
            "source_sha256": DIGEST,
            "evidence_id": 1,
            "source_observed_at": AT,
        }
    )
    return {
        "decisions": [
            {
                "target_key": identity().record_key(target),
                "proofs": [{**proof, "locator": "document"}],
            }
        ],
        "issues": [],
    }


synthetic_policy.policy_id = "synthetic-reviewed-v1"
synthetic_policy.policy_version = "1"
synthetic_policy.proof_sources = (URL,)
synthetic_policy.reason_text = "Reviewed representations establish conflicting scope."
synthetic_policy.policy_dependencies = (structured,)


def make_registry(hook=synthetic_policy):
    registry = PluginRegistry()
    registry.register(
        VendorPlugin(
            "example", "Synthetic", ("example.invalid",), structured, current_evidence_policy=hook
        )
    )
    return registry


def frame(raw=RAW, url=URL, evidence_id=1):
    return {
        "source_url": url,
        "source_sha256": sha256(raw).hexdigest(),
        "evidence_id": evidence_id,
        "source_observed_at": AT,
        "raw_b64": base64.b64encode(raw).decode(),
    }


def record(advisory="EXCLUDED", revision=2):
    return {
        "vendor": "example",
        "advisory_id": advisory,
        "revision_id": revision,
        "source_url": URL,
        "sha256": DIGEST,
        "notes": ["original"],
        "metrics": {"x": 1},
    }


@pytest.fixture
def partition_case():
    return {
        "records": [record("CURRENT", 1), record()],
        "selection_context": {"selections": [], "sources": [frame()]},
        "registry": make_registry(),
        "publication": {"id": "a" * 32, "advisory_schema_version": 2},
        "generated_at": AT,
    }


def test_partition_preserves_retained_record_without_current_claim(partition_case):
    result = api().partition(**partition_case)
    assert len(result["records"]) == len(result["retained_advisories"]) == 1
    assert result["current_evidence"]["counts"] == {
        "current": 1,
        "retained_total": 2,
        "excluded": 1,
    }
    assert result["records"][0]["advisory_id"] == "CURRENT"
    retained = result["retained_advisories"][0]
    assert retained["record"] == partition_case["records"][1]
    assert retained["record_scope"] == "retained_latest_excluded"
    assert retained["decision_id"] == result["current_evidence"]["decisions"][0]["decision_id"]
    assert {identity().record_key(r) for r in result["records"]} | {
        identity().record_key(r["record"]) for r in result["retained_advisories"]
    } == {identity().record_key(r) for r in partition_case["records"]}


def test_partition_isolated_and_stable_across_analysis_time_and_projection(partition_case):
    before = copy.deepcopy(partition_case["records"])
    first = api().partition(**partition_case)
    partition_case.update(
        publication={"id": "b" * 32, "advisory_schema_version": 2},
        generated_at="2026-11-07T12:00:00Z",
    )
    partition_case["records"][1]["metrics"] = {"changed": 8}
    second = api().partition(**partition_case)
    assert first["current_evidence"]["decisions"] == second["current_evidence"]["decisions"]
    assert first["current_evidence"]["publication"] == {
        "id": "a" * 32,
        "advisory_schema_version": 2,
    }
    assert before[0] == partition_case["records"][0]
    assert before[1]["notes"] == ["original"]
    first["retained_advisories"][0]["record"]["notes"].append("mutated output")
    assert partition_case["records"][1]["notes"] == ["original"]
    assert "raw_b64" not in json.dumps(first)
    assert RAW.decode() not in json.dumps(first)


def test_default_and_external_plugins_without_hooks_pass_through(partition_case):
    partition_case["registry"] = make_registry(None)
    result = api().partition(**partition_case)
    assert result["records"] == partition_case["records"]
    assert result["retained_advisories"] == []
    assert result["current_evidence"]["decisions"] == []
    assert result["current_evidence"]["issues"] == []
    assert result["current_evidence"]["policies"] == []
    assert all(
        p.current_evidence_policy is None for p in default_registry().all() if p.id != "arista"
    )


@pytest.mark.parametrize("revision", [True, False, None, 0, -1, [], {}])
def test_invalid_revision_cannot_impersonate_typed_retained_identity(revision):
    with pytest.raises(ValueError):
        identity().record_key(record(revision=revision))


def test_identity_preserves_json_types_and_ignores_public_projection_fields():
    assert identity().record_key(record(revision=2)) != identity().record_key(record(revision="2"))
    r = record()
    r.update(metrics={}, notes=[], observed_at="later", parsed_at="later", record_scope="public")
    assert identity().record_key(r) == identity().record_key(record())
    assert identity().canonical_json({"z": "é", "a": 1}) == b'{"a":1,"z":"\xc3\xa9"}'
    assert identity().canonical_json(1) != identity().canonical_json(True)
    for invalid in [float("nan"), float("inf"), {1: "not a JSON key"}]:
        with pytest.raises(ValueError):
            identity().canonical_json(invalid)


def wrapped_policy(transform):
    def hook(records, context):
        return transform(synthetic_policy(records, context), records, context)

    for name in (
        "policy_id",
        "policy_version",
        "proof_sources",
        "reason_text",
        "policy_dependencies",
    ):
        setattr(hook, name, getattr(synthetic_policy, name))
    return hook


@pytest.mark.parametrize(
    "mutation",
    [
        lambda out, *_: {**out, "raw": RAW.decode()},
        lambda out, *_: {**out, "decisions": [dict(out["decisions"][0], target_key="f" * 64)]},
        lambda out, *_: {**out, "decisions": out["decisions"] * 2},
        lambda out, *_: {**out, "decisions": [dict(out["decisions"][0], disposition="current")]},
        lambda out, *_: {
            **out,
            "decisions": [dict(out["decisions"][0], reason="arbitrary raw text")],
        },
        lambda out, *_: {
            **out,
            "issues": [{"target_key": out["decisions"][0]["target_key"], "code": RAW.decode()}],
        },
        lambda out, *_: {
            **out,
            "decisions": [
                dict(
                    out["decisions"][0],
                    proofs=[dict(out["decisions"][0]["proofs"][0], locator=RAW.decode())],
                )
            ],
        },
    ],
)
def test_policy_output_cannot_forge_targets_flags_or_echo_private_diagnostics(
    partition_case, mutation
):
    partition_case["registry"] = make_registry(wrapped_policy(mutation))
    with pytest.raises(ValueError):
        api().partition(**partition_case)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda c: c.update(approved=True),
        lambda c: c["sources"][0].update(raw_b64="invalid base64!"),
        lambda c: c["sources"][0].update(source_sha256="0" * 64),
        lambda c: c["sources"][0].update(evidence_id=True),
        lambda c: c["sources"][0].update(source_url="https://attacker.invalid/raw"),
        lambda c: c["sources"][0].update(official=True),
        lambda c: c["sources"].append(copy.deepcopy(c["sources"][0])),
    ],
)
def test_context_validation_precedes_hook_and_rejects_forged_or_mismatched_frames(
    partition_case, mutation
):
    mutation(partition_case["selection_context"])
    with pytest.raises(ValueError):
        api().partition(**partition_case)


def test_unresolved_proof_is_issue_never_exclusion(partition_case):
    partition_case["selection_context"]["sources"] = []
    result = api().partition(**partition_case)
    assert result["records"] == partition_case["records"]
    assert result["retained_advisories"] == []
    assert result["current_evidence"]["issues"][0]["code"] == "proof_unresolved"


def test_hook_cannot_mutate_another_vendors_inputs_or_original_context(partition_case):
    def mutate(out, records, context):
        records.clear()
        context["sources"].clear()
        return out

    partition_case["records"].append({**record("OTHER", 3), "vendor": "other"})
    registry = make_registry(wrapped_policy(mutate))
    registry.register(VendorPlugin("other", "Other", ("other.invalid",), structured))
    partition_case["registry"] = registry
    result = api().partition(**partition_case)
    assert [r["advisory_id"] for r in result["records"]] == ["CURRENT", "OTHER"]
    assert len(partition_case["records"]) == 3
    assert len(partition_case["selection_context"]["sources"]) == 1


def test_proof_frame_decoded_size_is_inclusive(partition_case):
    partition_case["selection_context"]["sources"] = [frame(b"x" * 2_000_000)]
    # A different retained proof is unresolved, but a valid boundary frame is accepted.
    api().partition(**partition_case)
    partition_case["selection_context"]["sources"] = [frame(b"x" * 2_000_001)]
    with pytest.raises(ValueError, match="frame"):
        api().partition(**partition_case)


def test_context_serialized_limit_is_inclusive_and_checked_before_hook(partition_case, monkeypatch):
    context = partition_case["selection_context"]
    size = len(identity().canonical_json(context))
    monkeypatch.setattr(api(), "MAX_CONTEXT_BYTES", size)
    api().partition(**partition_case)
    monkeypatch.setattr(api(), "MAX_CONTEXT_BYTES", size - 1)
    with pytest.raises(ValueError, match="context"):
        api().partition(**partition_case)
    monkeypatch.setattr(api(), "MAX_CONTEXT_BYTES", 8_000_000)
    context["sources"] = [frame(b"x" * 1_500_000, evidence_id=n) for n in range(1, 5)]
    with pytest.raises(ValueError, match="context"):
        api().partition(**partition_case)


def test_report_wire_encoding_is_shared_inclusive_and_counts_missingness(
    partition_case, monkeypatch
):
    report = api().partition(**partition_case)["current_evidence"]
    encoded = api().report_bytes(report)
    assert encoded == identity().canonical_json(report) + b"\n"
    monkeypatch.setattr(api(), "MAX_REPORT_BYTES", len(encoded))
    api().validate_report(
        report, publication={"id": "a" * 32, "advisory_schema_version": 2}, generated_at=AT
    )
    monkeypatch.setattr(api(), "MAX_REPORT_BYTES", len(encoded) - 1)
    with pytest.raises(ValueError, match="report"):
        api().report_bytes(report)
    monkeypatch.setattr(api(), "MAX_REPORT_BYTES", 2_000_000)
    with pytest.raises(ValueError, match="publication"):
        api().validate_report(report, publication="forged-generation")
    old = api().unavailable_report(
        publication={"id": "c" * 32, "advisory_schema_version": 2}, generated_at=AT
    )
    assert old["availability"] == "unavailable"
    assert old["counts"] == {"current": None, "retained_total": None, "excluded": None}
    old["counts"]["excluded"] = 0
    with pytest.raises(ValueError):
        api().validate_report(old)


def test_report_rejects_forged_identity_duplicate_decisions_and_counts(partition_case):
    original = api().partition(**partition_case)["current_evidence"]
    for mutate in [
        lambda r: r.update(raw_b64="secret"),
        lambda r: r["decisions"].append(copy.deepcopy(r["decisions"][0])),
        lambda r: r["decisions"][0].update(decision_id="0" * 64),
        lambda r: r["counts"].update(excluded=0),
        lambda r: r["policies"][0].update(fingerprint="0" * 64),
    ]:
        value = copy.deepcopy(original)
        mutate(value)
        with pytest.raises(ValueError):
            api().validate_report(value)


def test_more_than_one_thousand_decisions_fails_instead_of_truncating(partition_case):
    def many(out, records, context):
        return {
            "issues": [],
            "decisions": [
                dict(out["decisions"][0], target_key=identity().record_key(r)) for r in records
            ],
        }

    partition_case["registry"] = make_registry(wrapped_policy(many))
    partition_case["records"] = [record("EXCLUDED", n) for n in range(1, 1002)]
    with pytest.raises(ValueError, match="decision"):
        api().partition(**partition_case)


def test_collect_reads_only_registered_proof_urls_and_verifies_retained_bytes(partition_case):
    with connect(":memory:") as db:
        retained = evidence(db, RAW, URL)
        evidence(db, b"private unrelated bytes", "https://unrelated.invalid/private")
        context = api().collect_policy_input(
            db, partition_case["records"], registry=partition_case["registry"]
        )
        assert len(context["sources"]) == 1
        assert context["sources"][0]["evidence_id"] == retained["id"]
        assert context["sources"][0]["raw_b64"] == base64.b64encode(RAW).decode()
        assert "private unrelated bytes" not in json.dumps(context)
        db.execute("UPDATE evidence SET raw=? WHERE id=?", (b"tampered", retained["id"]))
        with pytest.raises(ValueError, match="hash"):
            api().collect_policy_input(
                db, partition_case["records"], registry=partition_case["registry"]
            )


def test_policy_fingerprint_tracks_explicit_dependencies_separately_from_normalization(monkeypatch):
    plugin = replace(make_registry().get("example"), normalizer_dependencies=())
    registry = PluginRegistry()
    registry.register(plugin)
    before_policy = registry.current_evidence_decisions(
        "example", [], {"selections": [], "sources": []}
    )["policy"]["fingerprint"]
    before_normalizer = registry.fingerprint("example")
    source = Path(__file__).resolve()
    original = Path.read_bytes
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda p: original(p) + b"\n# policy edit\n" if p.resolve() == source else original(p),
    )
    after_policy = registry.current_evidence_decisions(
        "example", [], {"selections": [], "sources": []}
    )["policy"]["fingerprint"]
    assert after_policy != before_policy
    assert registry.fingerprint("example") == before_normalizer


@pytest.mark.parametrize(
    "attribute,value",
    [
        ("proof_sources", ("https://attacker.invalid/proof",)),
        ("proof_sources", (URL,) * 21),
        ("policy_dependencies", (len,)),
        ("reason_text", ""),
    ],
)
def test_registered_policy_metadata_must_be_bounded_official_and_fingerprintable(attribute, value):
    hook = wrapped_policy(lambda out, *_: out)
    setattr(hook, attribute, value)
    with pytest.raises(ValueError):
        make_registry(hook)


def test_collect_uses_exact_retained_sha_when_newer_same_url_exists(partition_case):
    with connect(":memory:") as db:
        retained = evidence(db, RAW, URL)
        newer = evidence(db, b"newer unrelated representation", URL)
        statements = []
        db.set_trace_callback(statements.append)
        context = api().collect_policy_input(
            db, partition_case["records"], registry=partition_case["registry"]
        )
        assert [f["evidence_id"] for f in context["sources"]] == [retained["id"]]
        assert newer["id"] not in [f["evidence_id"] for f in context["sources"]]
        assert all("ORDER BY id DESC LIMIT 1" not in sql for sql in statements)


def test_collect_registered_historical_capture_and_selected_primary_without_unrelated_alternates(
    partition_case,
):
    primary = "https://example.invalid/primary"
    alternate = "https://example.invalid/alternate"
    hook = wrapped_policy(lambda out, *_: out)
    hook.proof_sources = (URL, primary, alternate)
    hook.proof_captures = ({"source_url": URL, "source_sha256": DIGEST},)
    registry = make_registry(hook)
    with connect(":memory:") as db:
        historical = evidence(db, RAW, URL)
        evidence(db, b"newest does not prove historical conflict", URL)
        primary_capture = evidence(db, b"primary scope", primary)
        selection = db.execute(
            "INSERT INTO source_selections(vendor,requested_url,observed_at,reason,selected_evidence_id) VALUES(?,?,?,?,?)",
            ("example", primary, AT, "Synthetic reviewed selection", primary_capture["id"]),
        )
        db.execute(
            "INSERT INTO source_selection_views(selection_id,evidence_id,source_format,adapter_version,assessments) VALUES(?,?,?,?,?)",
            (selection.lastrowid, primary_capture["id"], "text/html", "synthetic", 1),
        )
        db.execute(
            "INSERT INTO source_selection_issues(selection_id,source_url,error_code) VALUES(?,?,?)",
            (selection.lastrowid, URL, "unavailable"),
        )
        evidence(db, b"unneeded alternate", alternate)
        context = api().collect_policy_input(
            db,
            [
                record("CURRENT")
                | {"source_url": primary, "sha256": sha256(b"primary scope").hexdigest()}
            ],
            registry=registry,
        )
        assert {(f["source_url"], f["source_sha256"]) for f in context["sources"]} == {
            (URL, DIGEST),
            (primary, sha256(b"primary scope").hexdigest()),
        }
        assert historical["id"] in [f["evidence_id"] for f in context["sources"]]
        assert len(context["selections"]) == 1
        assert context["selections"][0]["views"][0]["selected"] is True


def test_hook_exception_cannot_echo_raw_private_context(partition_case):
    def explode(*_):
        raise RuntimeError(RAW.decode())

    partition_case["registry"] = make_registry(wrapped_policy(explode))
    with pytest.raises(ValueError) as caught:
        api().partition(**partition_case)
    assert RAW.decode() not in str(caught.value)
    assert caught.value.__suppress_context__


def test_report_accepts_existing_publication_generation_identity(partition_case):
    publication = {"id": "a" * 32, "advisory_schema_version": 2}
    partition_case["publication"] = publication
    result = api().partition(**partition_case)
    assert result["current_evidence"]["publication"] == publication
    api().validate_report(result["current_evidence"], publication=publication, generated_at=AT)
    publication["id"] = "b" * 32
    assert result["current_evidence"]["publication"]["id"] == "a" * 32


def test_private_selection_requires_one_selected_view_bound_to_retained_record(partition_case):
    f = frame()
    view = {k: v for k, v in f.items() if k != "raw_b64"} | {"selected": True}
    partition_case["selection_context"]["selections"] = [
        {
            "vendor": "example",
            "requested_url": URL,
            "selected_at": AT,
            "reason": "Synthetic reviewed selection",
            "views": [view],
        }
    ]
    api().partition(**partition_case)
    # A caller-supplied selected flag cannot authenticate another capture.
    partition_case["selection_context"]["selections"][0]["views"][0]["source_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="selected"):
        api().partition(**partition_case)


def test_report_real_two_million_byte_wire_boundary_includes_final_newline(partition_case):
    report = api().partition(**partition_case)["current_evidence"]
    original = report["decisions"][0]

    # Independent spec encoding/signing keeps the test from reusing production IDs.
    def encode(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

    def resign(decision):
        payload = {
            k: decision[k]
            for k in ("policy_id", "policy_version", "policy_fingerprint", "target_key", "proofs")
        }
        decision["decision_id"] = sha256(encode(payload)).hexdigest()

    def build(padding):
        rows = []
        for n in range(100):
            d = copy.deepcopy(original)
            d["target"]["revision_id"] = n + 1
            d["target_key"] = sha256(encode(d["target"])).hexdigest()
            d["proofs"] = sorted(
                [
                    dict(original["proofs"][0], source_url=URL + "/" + "x" * padding + "/" + str(p))
                    for p in range(20)
                ],
                key=encode,
            )
            resign(d)
            rows.append(d)
        return rows

    report["counts"] = {"current": 0, "retained_total": 100, "excluded": 100}
    report["decisions"] = build(0)
    base = len(encode(report)) + 1
    padding, remainder = divmod(2_000_000 - base, 2000)
    assert 0 < padding < 1000
    report["decisions"] = build(padding)
    # Each URL remains under the strict schema's 2048-character limit.
    for i, amount in enumerate((remainder // 2, remainder - remainder // 2)):
        report["decisions"][0]["proofs"][i]["source_url"] += "y" * amount
    report["decisions"][0]["proofs"].sort(key=encode)
    resign(report["decisions"][0])
    assert len(api().report_bytes(report)) == 2_000_000
    api().validate_report(report)
    report["decisions"][0]["proofs"][0]["source_url"] += "z"
    report["decisions"][0]["proofs"].sort(key=encode)
    resign(report["decisions"][0])
    with pytest.raises(ValueError, match="report"):
        api().validate_report(report)


def test_private_context_real_eight_million_serialized_boundary(partition_case):
    context = {
        "sources": [frame(b"x" * 1_999_000, evidence_id=n) for n in range(1, 4)],
        "selections": [],
    }
    view = {k: v for k, v in context["sources"][0].items() if k != "raw_b64"} | {"selected": True}
    context["selections"].append(
        {
            "vendor": "example",
            "requested_url": URL,
            "selected_at": AT,
            "reason": "x",
            "views": [view],
        }
    )
    size = len(identity().canonical_json(context))
    extra_raw_bytes = ((8_000_000 - size) // 4) * 3
    for i in range(3):
        addition = min(extra_raw_bytes, 999)
        context["sources"][i] = frame(b"x" * (1_999_000 + addition), evidence_id=i + 1)
        extra_raw_bytes -= addition
    context["selections"][0]["views"][0] = {
        k: v for k, v in context["sources"][0].items() if k != "raw_b64"
    } | {"selected": True}
    remaining = 8_000_000 - len(identity().canonical_json(context))
    assert 0 <= remaining < 4
    context["selections"][0]["reason"] += "y" * remaining
    assert len(identity().canonical_json(context)) == 8_000_000
    plugins = [partition_case["registry"].get("example")]
    api().validate_context(context, plugins)
    context["selections"][0]["reason"] += "z"
    with pytest.raises(ValueError, match="context"):
        api().validate_context(context, plugins)


def test_policy_fingerprint_binds_official_domain_perimeter():
    original = make_registry().get("example")
    registry = PluginRegistry()
    registry.register(replace(original, domains=("example.invalid", "also-official.invalid")))
    empty = {"selections": [], "sources": []}
    assert (
        registry.current_evidence_decisions("example", [], empty)["policy"]["fingerprint"]
        != make_registry().current_evidence_decisions("example", [], empty)["policy"]["fingerprint"]
    )


def test_policy_fingerprint_binds_official_route_filter_source(tmp_path, monkeypatch):
    import inspect

    def route_filter(url):
        return True

    source = tmp_path / "synthetic_official_route.py"
    source.write_text("def route_filter(url):\n    return True\n")
    original_source = inspect.getsourcefile
    monkeypatch.setattr(
        inspect,
        "getsourcefile",
        lambda callback: str(source) if callback is route_filter else original_source(callback),
    )
    registry = PluginRegistry()
    registry.register(replace(make_registry().get("example"), url_filter=route_filter))
    context = {"selections": [], "sources": []}
    before = registry.current_evidence_decisions("example", [], context)["policy"]["fingerprint"]
    source.write_text('def route_filter(url):\n    return url.startswith("https://")\n')
    assert (
        registry.current_evidence_decisions("example", [], context)["policy"]["fingerprint"]
        != before
    )
