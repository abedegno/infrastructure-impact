"""Synthetic invariants for call-local v2 runtime composition."""

import copy
from io import StringIO

import pytest
from test_switching_comparison import AT, claim, report

from infrastructure_impact.application import kev, publication, reporting
from infrastructure_impact.application import switching_comparison as comparison
from infrastructure_impact.application import switching_evidence as evidence
from infrastructure_impact.application.cohort import COHORT
from infrastructure_impact.application.comparison import compare


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("IMPACT_HOME", str(tmp_path))
    from infrastructure_impact.settings import PACKAGE

    monkeypatch.setenv("IMPACT_SOURCES", str(PACKAGE / "resources/sources.json"))


def test_reused_report_preserves_all_benchmark_bytes(tmp_path, monkeypatch):
    cid = next(iter(COHORT))
    records = [
        dict(
            vendor="arista",
            cves=[cid, "CVE-2099-98765"],
            document_status=status,
            assessments=[
                dict(cve_id=c, status="affected", scope="cve_specific", product="p")
                for c in (cid, "CVE-2099-98765")
            ],
        )
        for status in ("published", "draft")
    ]
    vendors = {"arista": "Arista", "cisco": "Cisco"}
    pairs = [
        dict(
            vendor=v,
            cve_id=c,
            component=COHORT.get(c),
            state="assessment_available",
            advisory_sources=["https://example.test/public"],
            checks=[dict(scope="synthetic")],
        )
        for v in vendors
        for c in (cid, "CVE-2099-98765")
    ]
    data = dict(
        records=records,
        coverage=pairs,
        vendors=vendors,
        comparison=compare(records, vendors=vendors),
    )
    cohort_data = {**data, "comparison": compare(records, COHORT, vendors=vendors)}
    monkeypatch.setattr(reporting, "connect", lambda **_: StringIO())
    monkeypatch.setattr(reporting, "state", lambda *args: cohort_data)
    monkeypatch.setattr(reporting, "now", lambda: AT)
    reporting.report()
    before = {p.name: p.read_bytes() for p in (tmp_path / "benchmark").iterdir()}
    assert len(before) == 3
    reporting._report_from_state(data)
    assert {p.name: p.read_bytes() for p in (tmp_path / "benchmark").iterdir()} == before


@pytest.mark.parametrize("fmt,expected", [("v1", []), ("v2", ["render"])])
def test_only_v2_build_reuses_its_single_native_query(tmp_path, monkeypatch, fmt, expected):
    from infrastructure_impact.collection import config

    calls = []
    data = dict(records=[], all_cves=[], coverage=[])
    generation = tmp_path / "generation"
    generation.mkdir()
    monkeypatch.setattr(publication, "connect", lambda **_: StringIO())
    monkeypatch.setattr(publication, "state", lambda db: calls.append("query") or data)
    monkeypatch.setattr(publication, "coverage", lambda *args: [])
    monkeypatch.setattr(config, "load_config", lambda: {})
    monkeypatch.setattr(
        reporting, "_report_from_state", lambda d: calls.append("render"), raising=False
    )
    monkeypatch.setattr(publication, "publish", lambda d, **kw: generation)
    publication.build(tmp_path / "out", publication_format=fmt)
    assert calls == ["query", *expected]


def inputs():
    return dict(claims=[claim()], coverage=[], issues=[])


def build_options():
    return dict(
        definition=evidence.definition(), publication=None, generated_at=AT, observation_end=AT[:10]
    )


def test_v2_projection_build_composes_one_evidence_validation(monkeypatch):
    raw = inputs()
    k = kev.build_report({}, [], publication=None, generated_at=AT)
    projected = evidence.project(raw, publication=None, generated_at=AT)
    expected = comparison.build_report(projected, k, **build_options())
    calls = []
    original = evidence._validate

    def measured(value, schema):
        calls.append((schema, isinstance(value, dict) and value.get("inputs") is not None))
        return original(value, schema)

    monkeypatch.setattr(evidence, "_validate", measured)
    actual_evidence, actual = comparison._project_comparison(raw, k, **build_options())
    assert evidence._json(actual_evidence) == evidence._json(projected)
    assert evidence._json(actual) == evidence._json(expected)
    assert calls.count(("switching-evidence-v1.json", False)) == 1
    assert ("switching-comparison-v1.json", True) not in calls
    evidence.validate_comparison(actual)


@pytest.mark.parametrize(
    "mutation",
    ["bool", "float", "tuple", "key", "nan", "surrogate", "publication", "time", "definition"],
)
def test_fresh_evidence_proof_rejects_changed_types_and_context(mutation):
    value = evidence.project(inputs(), publication=None, generated_at=AT)
    proof = evidence._ValidatedEvidence(value, publication=None, generated_at=AT)
    changed = copy.deepcopy(value)
    publication_id, at = None, AT
    if mutation == "bool":
        changed["schema_version"] = True
    elif mutation == "float":
        changed["schema_version"] = 1.0
    elif mutation == "tuple":
        changed["claims"] = tuple(changed["claims"])
    elif mutation == "key":
        changed[1] = "not a JSON key"
    elif mutation == "nan":
        changed["schema_version"] = float("nan")
    elif mutation == "surrogate":
        changed["issues"] = ["\ud800"]
    elif mutation == "publication":
        publication_id = {"id": "a" * 32, "advisory_schema_version": 2}
    elif mutation == "time":
        at = "2026-11-05T10:00:00Z"
    else:
        changed["definition_sha256"] = "0" * 64
    with pytest.raises((ValueError, TypeError)):
        proof.require(changed, publication=publication_id, generated_at=at)


def test_composed_build_rejects_mutation_in_deepcopy(monkeypatch):
    raw = inputs()
    k = kev.build_report({}, [], publication=None, generated_at=AT)
    original = copy._deepcopy_dispatch[dict]

    def corrupted(value, memo):
        result = original(value, memo)
        if "claims" in result and "definition_sha256" in result:
            result["schema_version"] = 1.0
        return result

    monkeypatch.setitem(copy._deepcopy_dispatch, dict, corrupted)
    with pytest.raises(ValueError, match="Retained comparison inputs changed"):
        comparison._project_comparison(raw, k, **build_options())


@pytest.mark.parametrize("mutation", ["bool", "float", "tuple", "key", "nan", "surrogate"])
def test_writer_composition_rejects_standalone_type_mismatch(mutation):
    full = report([claim()])
    standalone = copy.deepcopy(full["inputs"]["evidence"])
    if mutation == "bool":
        standalone["schema_version"] = True
    elif mutation == "float":
        standalone["schema_version"] = 1.0
    elif mutation == "tuple":
        standalone["claims"] = tuple(standalone["claims"])
    elif mutation == "key":
        standalone[1] = "bad"
    elif mutation == "nan":
        standalone["schema_version"] = float("nan")
    else:
        standalone["issues"] = ["\ud800"]
    with pytest.raises((ValueError, TypeError)):
        evidence._validate_comparison_evidence(full, standalone, publication=None, generated_at=AT)


@pytest.mark.parametrize("mutation", ["counts", "provenance", "identity", "definition"])
def test_writer_composition_fully_rejects_tampered_comparison(mutation):
    full = report([claim()])
    if mutation == "counts":
        full["rows"][0]["counts"]["advisories"] += 1
    elif mutation == "provenance":
        full["sources"] = []
    elif mutation == "identity":
        full["inputs"]["evidence"]["generated_at"] = "2026-11-05T10:00:00Z"
    else:
        full["definition"]["start_date"] = "2020-01-01"
    with pytest.raises(ValueError):
        evidence._validate_comparison_evidence(
            full, full["inputs"]["evidence"], publication=None, generated_at=AT
        )


def test_writer_composition_uses_fresh_full_comparison_not_a_standalone_revalidation(monkeypatch):
    full = report([claim()])
    calls = []
    original = evidence.validate_comparison

    def measured(*args, **kwargs):
        calls.append("complete")
        return original(*args, **kwargs)

    monkeypatch.setattr(evidence, "validate_comparison", measured)
    evidence._validate_comparison_evidence(
        full, copy.deepcopy(full["inputs"]["evidence"]), publication=None, generated_at=AT
    )
    assert calls == ["complete"]
    full["rows"][0]["counts"]["advisories"] += 1
    with pytest.raises(ValueError):
        evidence._validate_comparison_evidence(
            full, full["inputs"]["evidence"], publication=None, generated_at=AT
        )
    assert calls == ["complete", "complete"]


def test_native_batch_matches_separate_scopes_and_validates_once(monkeypatch):
    from infrastructure_impact.exports import switching_csv

    full = report([claim(), claim("B", cid="CVE-2025-67890")])
    scopes = [dict(scope_level=s) for s in ("os_family", "model_qualified")]
    expected = [
        comparison.summary(comparison.select_report(full, evaluated_at=AT, **s)) for s in scopes
    ]
    calls = []
    original = evidence.validate_comparison

    def measured(*args, **kwargs):
        calls.append("full")
        return original(*args, **kwargs)

    monkeypatch.setattr(evidence, "validate_comparison", measured)
    actual = comparison._select_summaries(full, scopes, evaluated_at=AT)
    assert evidence._json(actual) == evidence._json(expected)
    assert [switching_csv(r) for r in actual] == [switching_csv(r) for r in expected]
    assert calls == ["full"]
    full["rows"][0]["counts"]["advisories"] += 1
    with pytest.raises(ValueError):
        comparison._select_summaries(full, scopes, evaluated_at=AT)
    assert calls == ["full", "full"]


@pytest.mark.parametrize("field", ["inputs", "definition", "rows"])
def test_native_batch_rejects_source_mutation_during_selection(monkeypatch, field):
    full = report([claim()])
    original = comparison._select_summary

    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        if field == "inputs":
            full["inputs"]["evidence"]["schema_version"] = 1.0
        elif field == "definition":
            full["definition"]["start_date"] = "2020-01-01"
        else:
            full["rows"][0]["counts"]["advisories"] += 1
        return result

    monkeypatch.setattr(comparison, "_select_summary", changed)
    with pytest.raises(ValueError, match="source changed"):
        comparison._select_summaries(full, [dict(scope_level="os_family")], evaluated_at=AT)


def test_v2_public_projection_matches_v1_and_composes(monkeypatch):
    from test_static_delivery import dataset

    data = dataset()
    data["research"]["switching_input"] = inputs()
    expected = publication.public_projection(data)
    calls = []
    original = comparison._project_comparison

    def measured(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(comparison, "_project_comparison", measured)
    actual = publication.public_projection(data, publication_format="v2")
    assert evidence._json(actual) == evidence._json(expected)
    assert calls == [1]


@pytest.mark.parametrize("fmt", ["v1", "v2"])
@pytest.mark.parametrize("monitor_failure", [False, True])
def test_worker_checks_capacity_before_native_parity(tmp_path, monkeypatch, fmt, monitor_failure):
    import os

    from infrastructure_impact.application import import_candidate as worker
    from infrastructure_impact.application import publication_v2, query, source_audit
    from infrastructure_impact.collection import target_import_profiles
    from infrastructure_impact.storage import audit

    calls = []
    monkeypatch.setattr(
        worker, "_paths", lambda *args: (tmp_path / "db", tmp_path / "public", tmp_path)
    )
    monkeypatch.setattr(worker, "_base_path", lambda *args: "/")
    env = dict(os.environ)
    monkeypatch.setattr(worker, "_environment", lambda *args, **kwargs: env)
    monkeypatch.setattr(
        worker,
        "_read_json",
        lambda *args: dict(
            format="impact-target-import-worker",
            schema_version=2 if fmt == "v2" else 1,
            profile={},
            **({"publication_format": "v2"} if fmt == "v2" else {}),
        ),
    )
    monkeypatch.setattr(target_import_profiles, "from_manifest", lambda _: object())
    monkeypatch.setattr(worker, "_preserved", lambda *args, **kwargs: None)
    monkeypatch.setattr(worker, "_monitor_path", lambda: None)
    monkeypatch.setattr(audit, "audit", lambda: None)
    monkeypatch.setattr(reporting, "report", lambda: calls.append("report"))
    monkeypatch.setattr(publication, "build", lambda *args, **kw: calls.append("build"))
    monkeypatch.setattr(publication_v2, "inspect_bundle", lambda *args: object())
    monkeypatch.setattr(publication_v2, "native_parity", lambda *args: calls.append("native"))
    monkeypatch.setattr(worker, "_inspect_bundle", lambda *args: object())
    monkeypatch.setattr(worker, "_parity", lambda *args: calls.append("native"))

    def monitors(*args, **kwargs):
        calls.append("monitors")
        if monitor_failure:
            raise worker.CapacityFailure("monitor capacity")

    monkeypatch.setattr(worker, "_monitors", monitors)
    # Worker deliberately assigns these clock functions; restore them after this fixture.
    monkeypatch.setattr(query, "now", query.now)
    monkeypatch.setattr(source_audit, "now", source_audit.now)
    result = worker._worker(tmp_path / "db", tmp_path / "public", publication_format=fmt)
    prefix = ([] if fmt == "v2" else ["report"]) + ["build", "monitors"]
    if monitor_failure:
        assert calls == prefix
        assert result["candidate"]["outcome"] == "capacity_failed"
        assert result["candidate_validated"] is False
        assert result["capacity_passed"] is False
        assert result["candidate"]["parity_passed"] is None
    else:
        assert calls == prefix + ["native"]
        assert result["candidate"]["outcome"] == "passed"
        assert result["candidate_validated"] is True
        assert result["candidate"]["parity_passed"] is True


def test_v2_build_copies_identical_fresh_cohort_report_asset(tmp_path, monkeypatch):
    from test_static_delivery import dataset

    from infrastructure_impact.collection import config

    data = dataset()
    cohort = {**data, "comparison": compare(data["records"], COHORT, vendors=data["vendors"])}
    monkeypatch.setattr(reporting, "connect", lambda **kw: StringIO())
    monkeypatch.setattr(reporting, "state", lambda *args: cohort)
    monkeypatch.setattr(reporting, "now", lambda: AT)
    reporting.report()
    before = {p.name: p.read_bytes() for p in (tmp_path / "benchmark").iterdir()}
    monkeypatch.setattr(publication, "connect", lambda **kw: StringIO())
    monkeypatch.setattr(publication, "state", lambda *args: data)
    monkeypatch.setattr(publication, "coverage", lambda *args: data["coverage"])
    monkeypatch.setattr(config, "load_config", lambda: {})
    publication.build(tmp_path / "out", publication_format="v2")
    assert {p.name: p.read_bytes() for p in (tmp_path / "benchmark").iterdir()} == before
    assert (tmp_path / "out/research/cohort-report.txt").read_bytes() == before["cohort-report.txt"]


def test_composed_boundaries_keep_reviewed_cross_claim_link_validation(monkeypatch):
    from test_switching_evidence import reviewed_section_report

    projected = reviewed_section_report(monkeypatch)
    at = projected["generated_at"]
    options = {**build_options(), "generated_at": at}
    full = comparison.build_report(
        projected, kev.build_report({}, [], publication=None, generated_at=at), **options
    )
    fixed = next(c for c in projected["claims"] if c["status"] == "fixed")
    projected["claims"].remove(fixed)
    with pytest.raises(ValueError):
        evidence._ValidatedEvidence(projected, publication=None, generated_at=at)
    with pytest.raises(ValueError):
        comparison._project_comparison(projected, full["inputs"]["kev"], **options)
    full["inputs"]["evidence"] = projected
    with pytest.raises(ValueError):
        evidence._validate_comparison_evidence(full, projected, publication=None, generated_at=at)


def test_native_parity_queries_fresh_source_and_rejects_changed_native_fact(tmp_path, monkeypatch):
    from test_static_delivery import dataset

    from infrastructure_impact.application import publication_v2, query
    from infrastructure_impact.application.publication_reader import PublicationReader
    from infrastructure_impact.storage import repository

    native = dataset()
    out = publication.publish(native, tmp_path / "published", publication_format="v2")
    reads = []
    queried = []

    def connect(database, *, read_only):
        reads.append((database, read_only))
        return StringIO()

    def fresh(db):
        queried.append(1)
        return copy.deepcopy(native)

    monkeypatch.setattr(repository, "connect", connect)
    monkeypatch.setattr(query, "state", fresh)
    publication_v2.native_parity("synthetic-native-only", out, tmp_path, PublicationReader(out))
    assert reads == [("synthetic-native-only", True)]
    assert queried == [1]
    native["records"][0]["title"] = "Different native title"
    with pytest.raises(ValueError, match="native logical root mismatch"):
        publication_v2.native_parity("synthetic-native-only", out, tmp_path, PublicationReader(out))
    assert reads == [("synthetic-native-only", True)] * 2
    assert queried == [1, 1]


def test_native_subphases_cover_eager_expected_and_actual_reader_consumption(tmp_path, monkeypatch):
    from contextlib import contextmanager

    from test_static_delivery import dataset

    from infrastructure_impact.application import publication_v2, query
    from infrastructure_impact.application.publication_reader import PublicationReader
    from infrastructure_impact.storage import repository

    native = dataset()
    out = publication.publish(native, tmp_path / "published", publication_format="v2")
    active, observed = [], []

    @contextmanager
    def tracked_phase(label):
        active.append(label)
        try:
            yield
        finally:
            active.pop()

    select, reader_select = comparison._select_summaries, PublicationReader.switching_selections

    def expected(*args, **kwargs):
        observed.append("expected")
        assert active == ["publication.native_queries", "publication.native_expected"]
        return select(*args, **kwargs)

    def actual(self, *args, **kwargs):
        # Assertions execute on generator consumption, not generator creation.
        observed.append("reader")
        assert active == ["publication.native_queries", "publication.native_reader"]
        yield from reader_select(self, *args, **kwargs)

    monkeypatch.setattr(publication_v2, "phase", tracked_phase)
    monkeypatch.setattr(comparison, "_select_summaries", expected)
    monkeypatch.setattr(PublicationReader, "switching_selections", actual)
    monkeypatch.setattr(repository, "connect", lambda *args, **kwargs: StringIO())
    monkeypatch.setattr(query, "state", lambda db: copy.deepcopy(native))
    publication_v2.native_parity("synthetic-native-only", out, tmp_path, PublicationReader(out))
    assert observed == ["expected", "reader"]
