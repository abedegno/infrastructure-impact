"""Native summary work stays isolated, fresh, and proportional to retained sources."""

import copy
from collections import Counter

import pytest
from jsonschema import ValidationError
from test_switching_scaling import corrupt, sample

from infrastructure_impact.application import switching_comparison as comparison
from infrastructure_impact.application import switching_evidence as evidence
from infrastructure_impact.exports import switching_csv

SCOPES = [dict(scope_level=s) for s in ("os_family", "model_qualified")]


def batch(report, selections=SCOPES):
    return comparison._select_summaries(report, selections, evaluated_at=report["evaluated_at"])


def test_native_batch_avoids_whole_input_copy_and_proof_serialization(monkeypatch):
    report = sample(4)
    calls = Counter()
    validate, fingerprint, encode = (
        evidence.validate_comparison,
        evidence._fingerprint,
        evidence._json,
    )
    digest, row = evidence.definition_sha256, comparison._row
    deepcopy_dict = copy._deepcopy_dispatch[dict]

    def counted_validate(value):
        calls["validation"] += 1
        return validate(value)

    def counted_fingerprint(value):
        if value is report:
            calls["fingerprint"] += 1
        return fingerprint(value)

    def counted_json(value):
        if isinstance(value, dict) and set(value) == {"evidence", "kev"}:
            calls["input_json"] += 1
        if value is report:
            calls["source_json"] += 1
        return encode(value)

    def counted_digest(value):
        if isinstance(value, dict) and set(value) == set(evidence._SOURCE_FIELDS):
            calls["source_hash"] += 1
        return digest(value)

    def counted_row(*args, **kwargs):
        calls["row"] += 1
        return row(*args, **kwargs)

    def counted_copy(value, memo):
        if "claims" in value and "definition_sha256" in value:
            calls["evidence_copy"] += 1
        return deepcopy_dict(value, memo)

    monkeypatch.setattr(evidence, "validate_comparison", counted_validate)
    monkeypatch.setattr(evidence, "_fingerprint", counted_fingerprint)
    monkeypatch.setattr(evidence, "_json", counted_json)
    monkeypatch.setitem(copy._deepcopy_dispatch, dict, counted_copy)
    monkeypatch.setattr(evidence, "definition_sha256", counted_digest)
    monkeypatch.setattr(comparison, "_row", counted_row)
    assert len(batch(report)) == 2
    assert calls == {
        "validation": 1,
        "fingerprint": 5,
        "source_json": 6,
        "source_hash": 3,
        "row": 9,
    }


@pytest.mark.parametrize("typed", [False, True])
def test_source_dedup_hashes_only_unique_closed_sources_and_preserves_charges(monkeypatch, typed):
    source = sample()["sources"][0]
    unique = [source]
    alternatives = {
        "source_url": source["source_url"] + "?variant=1",
        "source_sha256": "b" * 64,
        "retrieved_at": "2026-11-04T11:00:00Z",
        "source_locator": source["source_locator"] + "/different",
    }
    for field in evidence._SOURCE_FIELDS:
        unique.append({**source, field: alternatives[field]})
    repeated = [dict(reversed(list(s.items()))) for _ in range(10) for s in unique]
    claims = (
        [comparison.ReducerClaim({"claim_id": "used"}, repeated)]
        if typed
        else [{"claim_id": "used", "nested": repeated}]
    )
    calls, charged = [], []
    digest = evidence.definition_sha256

    def counted(value):
        calls.append(value)
        return digest(value)

    class Charges(comparison._Construction):
        def value(self, value):
            charged.append(value)

    monkeypatch.setattr(evidence, "definition_sha256", counted)
    actual = comparison._selected_sources(
        {"claims": claims}, [{"claim_ids": ["used"], "events": []}], build=Charges()
    )
    assert evidence._json(actual) == evidence._json(sorted(unique, key=evidence._json))
    assert len(calls) == len(unique)
    assert charged == ["used"] + [v for s in repeated[:5] for v in (digest(s), s)]


@pytest.mark.parametrize("bad", [[], {}, 1, True, None, ("unexpected",)])
def test_source_dedup_rejects_non_string_source_values(bad):
    source = {**sample()["sources"][0], "source_locator": bad}
    with pytest.raises((ValueError, TypeError, ValidationError)):
        comparison._selected_sources(
            {"claims": [{"claim_id": "used", "source": source}]},
            [{"claim_ids": ["used"], "events": []}],
        )


@pytest.mark.parametrize(
    "options",
    SCOPES
    + [
        dict(vendor="arista", window="pre", cve_ids=[]),
        dict(vendor="cisco", window="2025", cve_ids=["CVE-2025-12345"]),
        dict(vendor="aruba", window="post"),
    ],
)
def test_native_summary_matches_full_selection(options):
    report = sample()
    expected = comparison.summary(
        comparison.select_report(report, evaluated_at=report["evaluated_at"], **options)
    )
    (actual,) = batch(report, [options])
    assert evidence._json(actual) == evidence._json(expected)
    assert switching_csv(actual) == switching_csv(expected)


def test_native_summaries_isolate_every_nested_output():
    report = sample()
    # Bind the otherwise nullable publication to exercise its isolation too.
    publication = {"id": "a" * 32, "advisory_schema_version": 2}
    for value in (report, report["inputs"]["evidence"], report["inputs"]["kev"]):
        value["publication"] = copy.deepcopy(publication)
    before = evidence._json(report)
    first, sibling = batch(report)
    sibling_before = evidence._json(sibling)
    first["sources"][0]["source_locator"] = "changed"
    observed_row = next(row for row in first["rows"] if row["events"])
    observed_row["events"][0]["claim_ids"].clear()
    observed_row["events"].clear()
    first["selection"]["effective_vendors"].clear()
    first["definition"]["targets"].clear()
    first["publication"]["id"] = "b" * 32
    assert evidence._json(report) == before
    assert evidence._json(sibling) == sibling_before
    first_before = evidence._json(first)
    report["definition"]["targets"].clear()
    report["inputs"]["evidence"]["claims"][0]["source"]["source_locator"] = "caller mutation"
    assert evidence._json(first) == first_before
    assert evidence._json(sibling) == sibling_before


@pytest.mark.parametrize(
    "fault",
    [
        "source_shape",
        "source_property",
        "source_duplicate",
        "claim_hash",
        "claim_identity",
        "generation",
        "publication",
        "definition",
        "counts",
        "source_membership",
        "binding_semantics",
        "nonfinite",
        "python_value",
    ],
)
def test_native_batch_revalidates_after_prior_success(fault):
    report = sample()
    batch(report)
    corrupt(report, fault)
    with pytest.raises((ValidationError, ValueError, TypeError)):
        batch(report)


def test_native_batch_validates_generated_summary(monkeypatch):
    report = sample()
    row = comparison._row

    def invalid(*args, **kwargs):
        result = row(*args, **kwargs)
        result["counts"]["claims"] = "forged"
        return result

    select = comparison._select_summary

    def inject(*args, **kwargs):
        with monkeypatch.context() as patch:
            patch.setattr(comparison, "_row", invalid)
            return select(*args, **kwargs)

    monkeypatch.setattr(comparison, "_select_summary", inject)
    with pytest.raises(ValidationError):
        batch(report)


@pytest.mark.parametrize("field", ["revision", "source"])
def test_native_batch_catches_borrowed_input_mutation_on_second_scope(monkeypatch, field):
    report = sample()
    select, row = comparison._select_summary, comparison._row
    calls = []

    def mutate(*args, **kwargs):
        result = row(*args, **kwargs)
        claim = report["inputs"]["evidence"]["claims"][0]
        if field == "revision":
            claim["revision"] = "unused-context-mutation"
        else:
            claim["source"]["source_locator"] = "borrowed-source-mutation"
        return result

    def inject(*args, **kwargs):
        calls.append(1)
        with monkeypatch.context() as patch:
            if len(calls) == 2:
                patch.setattr(comparison, "_row", mutate)
            return select(*args, **kwargs)

    monkeypatch.setattr(comparison, "_select_summary", inject)
    with pytest.raises(ValueError, match="source changed"):
        batch(report)
    assert len(calls) == 2


@pytest.mark.parametrize("kind", ["empty", "unavailable"])
def test_native_summary_matches_empty_and_unavailable_selection(kind):
    from test_switching_comparison import AT
    from test_switching_comparison import report as build

    report = (
        build([])
        if kind == "empty"
        else comparison.select_report(None, generated_at=AT, evaluated_at=AT)
    )
    if kind == "unavailable":
        # Full selection regenerates unavailable context from its generation.
        report["observation_end"] = "2026-11-03"
    expected = comparison.summary(comparison.select_report(report, evaluated_at=AT))
    (actual,) = batch(report, [{}])
    assert evidence._json(actual) == evidence._json(expected)
    assert switching_csv(actual) == switching_csv(expected)


@pytest.mark.parametrize(
    "options",
    [
        dict(vendor="unknown"),
        dict(scope_level="unknown"),
        dict(window="unknown"),
        dict(cve_ids=("CVE-2025-12345",)),
        dict(cve_ids=["not-a-cve"]),
    ],
)
def test_native_and_full_selections_reject_same_invalid_options(options):
    report = sample()
    with pytest.raises(ValueError):
        comparison.select_report(report, **options)
    with pytest.raises(ValueError):
        batch(report, [options])


def test_source_budget_charges_before_retention_and_deduplicates_at_exact_limit():
    from infrastructure_impact.publication_codec import Budget

    source = sample()["sources"][0]
    values = {"claims": [{"claim_id": "used", "nested": [copy.deepcopy(source)] * 20}]}
    rows = [{"claim_ids": ["used"], "events": []}]
    # Existing construction charge: used ID, canonical 64-byte identity, source.
    charged = ["used", evidence.definition_sha256(source), source]
    exact = sum(len(evidence._json(v)) for v in charged)
    assert comparison._selected_sources(
        values, rows, build=comparison._Construction(Budget(exact))
    ) == [source]
    for limit in (0, 1, exact - 1):
        with pytest.raises(ValueError, match="budget"):
            comparison._selected_sources(
                values, rows, build=comparison._Construction(Budget(limit))
            )
