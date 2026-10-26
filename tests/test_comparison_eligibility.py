"""Evidence-policy boundaries and exact Python/static-report parity."""

import json
import shutil
import subprocess
from urllib.parse import urlencode

import pytest

from infrastructure_impact.adapters.common import assessment, base
from infrastructure_impact.application.eligibility import eligibility, report_validator
from infrastructure_impact.application.publication import publish
from infrastructure_impact.application.query import state
from infrastructure_impact.exports import select
from infrastructure_impact.http import Application
from infrastructure_impact.settings import PACKAGE
from infrastructure_impact.storage.repository import connect, ingest

CID = "CVE-2025-12345"
OTHER = "CVE-2025-54321"
URL = "https://www.arista.com/synthetic-advisory"


def record(
    cid=CID,
    published="2025-02-01T12:00:00Z",
    status="affected",
    scope="cve_specific",
    product="Router",
):
    r = base("arista", URL, "SYNTHETIC-" + cid, "Synthetic scope example", published)
    r.update(document_status="final", cves=[cid], sha256="a" * 64)
    r["assessments"] = [assessment(cid, product, status, "synthetic", scope=scope)]
    return r


def dataset(records=None):
    return dict(
        generated_at="2025-06-01T12:00:00Z",
        vendors={"arista": "Arista", "missing": "Missing"},
        records=[record()] if records is None else records,
        all_cves=[CID, OTHER],
        upstream={
            CID: dict(
                published_at="2025-01-01T12:00:00Z",
                source_url="https://www.cve.org/synthetic",
                sha256="b" * 64,
            )
        },
        catalogue={
            "vendors": [
                dict(
                    vendor="arista",
                    sources=[dict(url=URL)],
                    product_families=["Declared router context"],
                    known_gaps=["Bounded sample"],
                )
            ]
        },
        source_audit={
            "vendors": [
                dict(
                    vendor="arista",
                    archives=[
                        dict(
                            source_url=URL + "/archive",
                            kind="listing",
                            pages=dict(done=1, pending=1, error=0),
                            documents=dict(done=1, pending=10, error=0),
                            known_queue_exhausted=False,
                            discovery_link_gaps=0,
                            observed_scopes=["Reviewed filter"],
                        )
                    ],
                )
            ]
        },
        health=[
            dict(
                vendor="arista",
                source_url=URL,
                outcome="error",
                checked_at="2025-01-01T00:00:00Z",
                error_code="access_denied",
            )
        ],
    )


def report(data=None, **kw):
    return eligibility(data or dataset(), [CID, OTHER], start="2025-01-01", end="2025-05-31", **kw)


def test_missing_evidence_is_not_unaffected_and_source_success_cannot_unlock_rates():
    d = dataset()
    rows = report(d)["vendors"]
    assert rows[0]["counts"]["explicit_affected"] == 1
    assert rows[0]["counts"]["no_statement"] == 1
    assert rows[1]["counts"]["unaffected"] == 0
    assert rows[1]["counts"]["no_statement"] == 2
    assert not rows[1]["eligibility"]["descriptive_counts_usable"]
    assert rows[0]["source_coverage"]["backfill_pending"] == 11
    assert rows[0]["source_coverage"]["stale_or_unchecked_urls"] == 1
    assert len(rows[0]["source_coverage"]["errors"]) == 1
    # Exhausting a known queue is not proof of equivalent portfolios or CVE dating.
    d["health"][0].update(outcome="ok", checked_at=d["generated_at"])
    archive = d["source_audit"]["vendors"][0]["archives"][0]
    archive["pages"]["pending"] = archive["documents"]["pending"] = 0
    archive["known_queue_exhausted"] = True
    row = report(d)["vendors"][0]
    assert row["eligibility"]["rate_comparison"] == "suppressed"
    assert "portfolio_denominator_missing" in row["eligibility"]["reason_codes"]
    assert row["source_coverage"]["portfolio_completeness"] == "not_established"


def test_status_scope_does_not_transfer_between_products_or_cves():
    records = [
        record(status="fixed"),
        record(status="affected", scope="bulletin_shared", product="Other Router"),
        record(OTHER, status="unaffected"),
        record(status="unknown", product="Unresolved"),
    ]
    row = report(dataset(records))["vendors"][0]
    assert row["counts"]["explicit_affected"] == 0
    assert row["counts"]["shared_affected"] == 1
    assert row["counts"]["fixed"] == 1
    assert row["counts"]["explicit_unaffected"] == 1
    assert row["counts"]["unknown"] == 1
    assert row["counts"]["no_cve_specific_exposure_assessment"] == 1
    assert row["cases"][0]["statuses"] == ["affected", "fixed", "unknown"]
    assert row["cases"][1]["statuses"] == ["unaffected"]
    scoped = report(dataset(records), products={"arista": ["Router"]})["vendors"][0]
    assert scoped["counts"]["shared_affected"] == 0
    assert scoped["counts"]["unknown"] == 0
    assert scoped["counts"]["explicit_affected"] == 0
    assert scoped["counts"]["fixed"] == 1
    empty = report(dataset(records), products={"arista": []})["vendors"][0]
    assert not empty["eligibility"]["descriptive_counts_usable"]
    assert empty["counts"]["unaffected"] == 0
    assert empty["counts"]["no_statement"] == 2


def test_initial_publication_window_is_not_update_date_or_historical_reconstruction():
    old = record(published="2024-12-31T23:59:59Z")
    old["updated_at"] = "2025-05-01T00:00:00Z"
    # UTC date, not publisher-local date: this lies in January 1 UTC.
    boundary = record(published="2024-12-31T23:30:00-01:00")
    date_only = record(published="2025-05-31")
    naive = record(published="2025-02-01T12:00:00")
    missing = record(published=None)
    draft = record(product="Draft-only label")
    draft["document_status"] = "draft"
    d = dataset([old, boundary, date_only, naive, missing, draft])
    row = report(d)["vendors"][0]
    assert row["excluded_advisories"] == dict(
        draft=1, outside_period=1, unusable_publication_date=2, future_timestamp=0
    )
    assert row["cases"][0]["statement_count"] == 2
    assert "not an as-of reconstruction" in report(d)["method"]
    assert "vendor_timestamp_not_precise" in row["cases"][0]["timing_reasons"]
    assert "undated_statement_excluded" in row["cases"][0]["timing_reasons"]


def test_full_timestamp_pairs_never_become_disclosure_or_fix_delays():
    d = dataset()
    d["records"][0]["reported_fix_date"] = "2024-01-01"
    d["research"] = {"fix_candidates": [{"verified": True, "private_note": "PRIVATE_FIX_NOTE"}]}
    case = report(d)["vendors"][0]["cases"][0]
    assert case["publication_observations"][0]["offset_seconds"] == 31 * 86400
    assert case["first_disclosure_days"] is None
    assert case["verified_fix_delay_days"] is None
    assert "PRIVATE_FIX_NOTE" not in json.dumps(report(d))
    # A negative document-metadata offset is preserved without inferring response time.
    d["upstream"][CID]["published_at"] = "2025-03-01T12:00:00Z"
    assert report(d)["vendors"][0]["cases"][0]["publication_observations"][0]["offset_seconds"] < 0


@pytest.mark.parametrize(
    "published",
    [
        "2025-02-01",
        "2025-02-01T00:00:00",
        None,
        "2025-02-30T00:00:00Z",
        "2025-02-01T24:00:00Z",
        "2025-02-01T00:00:00+01:99",
    ],
)
def test_inadequate_vendor_timestamps_cannot_produce_numeric_offsets(published):
    d = dataset([record(published=published)])
    assert report(d)["vendors"][0]["cases"][0]["publication_observations"] == []


def test_draft_shared_conflicting_and_future_evidence_are_not_timing_shortcuts():
    shared = record(scope="bulletin_shared")
    conflict = record(status="conflicting")
    draft = record()
    draft["document_status"] = "draft"
    future = record(published="2025-06-01T13:00:00Z")
    for r in [shared, conflict, draft]:
        assert report(dataset([r]))["vendors"][0]["cases"][0]["publication_observations"] == []
    row = eligibility(dataset([future]), [CID], start="2025-06-01", end="2025-06-01")["vendors"][0]
    assert row["excluded_advisories"]["future_timestamp"] == 1
    assert not row["eligibility"]["descriptive_counts_usable"]


@pytest.mark.parametrize(
    "options",
    [
        dict(start="2025-02-30"),
        dict(start="2025-06-01", end="2025-05-01"),
        dict(end="2025-06-02"),
        dict(products={"missing": ["Router"]}),
        dict(products={"arista": ["Invented product"]}),
        dict(products=[]),
        dict(products={"arista": "Router"}),
    ],
)
def test_invalid_selection_is_rejected_instead_of_silently_widened(options):
    with pytest.raises(ValueError):
        eligibility(dataset(), [CID], **options)


@pytest.mark.skipif(shutil.which("node") is None, reason="Static Python parity needs Node")
def test_python_and_static_policy_match_across_periods_scopes_and_date_boundaries():
    records = [
        record(),
        record(OTHER, published="2025-05-31", status="fixed"),
        record(published="2025-02-01T00:00:00", status="unknown", product="Other"),
        record(published="2025-02-30T00:00:00Z", product="Other"),
        record(scope="bulletin_shared", product="Shared"),
    ]
    d = dataset(records)
    variants = [
        dict(start="2025-01-01", end="2025-05-31"),
        dict(start="2025-02-01", end="2025-02-01", products={"arista": ["Router"]}),
        dict(start="2025-01-01", end="2025-05-31", products={"arista": []}),
        {},
    ]
    script = """const fs=require('fs'),vm=require('vm');const c={window:{},Set,URL,Response,Blob};vm.createContext(c);vm.runInContext(fs.readFileSync('infrastructure_impact/web/snapshot.js','utf8'),c);const i=JSON.parse(fs.readFileSync(0,'utf8'));process.stdout.write(JSON.stringify(i.options.map(o=>c.comparisonEligibility(i.data,i.ids,o))));"""
    actual = json.loads(
        subprocess.run(
            ["node", "-e", script],
            input=json.dumps(dict(data=d, ids=[CID, OTHER], options=variants)),
            text=True,
            capture_output=True,
            check=True,
            cwd=PACKAGE.parent,
        ).stdout
    )
    assert actual == [eligibility(d, [CID, OTHER], **options) for options in variants]


def request(app, query):
    status = []
    body = b"".join(
        app(
            dict(
                REQUEST_METHOD="GET", PATH_INFO="/api/v1/comparison-eligibility", QUERY_STRING=query
            ),
            lambda code, headers: status.append(int(code[:3])),
        )
    )
    return status[0], json.loads(body)


def test_publication_api_and_custom_selection_recompute_after_private_overrides(tmp_path):
    r = record()
    for key in ("sha256",):
        r.pop(key)
    with connect(":memory:") as db:
        ingest(db, b"synthetic", URL, lambda *_: r, "arista")
        data = state(db, [CID, OTHER])
    data["comparison_eligibility"] = {
        "private_note": "PRIVATE_ELIGIBILITY_OVERRIDE",
        "first_disclosure_days": 0,
    }
    data["delays"] = [{"private_note": "PRIVATE_UNSCOPED_DELAY"}]
    generation = publish(data, root=tmp_path)
    assert "PRIVATE_ELIGIBILITY_OVERRIDE" not in (generation / "snapshot.json").read_text()
    assert "PRIVATE_UNSCOPED_DELAY" not in (generation / "snapshot.json").read_text()
    public = json.loads((generation / "snapshot.json").read_text())
    expected = eligibility(
        public, [CID], start="2025-01-01", end="2025-05-31", products={"arista": ["Router"]}
    )
    code, result = request(
        Application(tmp_path),
        urlencode(
            dict(
                cves=CID,
                start="2025-01-01",
                end="2025-05-31",
                products=json.dumps({"arista": ["Router"]}),
            )
        ),
    )
    assert code == 200
    assert result["vendors"] == expected["vendors"]
    assert result["cohort"] == [CID]
    assert (generation / "comparison-eligibility.json").exists()
    assert select(public, [CID], start="2025-01-01", end="2025-05-31")["delays"] == []
    for invalid in [
        "start=2025-02-30",
        "end=2999-01-01",
        "products=%5B%5D",
        "start=2025-01-01&start=2024-01-01",
    ]:
        assert request(Application(tmp_path), invalid)[0] == 400


@pytest.mark.parametrize("side", ["advisory", "upstream"])
def test_exact_dates_without_retained_source_fingerprints_do_not_enable_offsets(side):
    d = dataset()
    if side == "advisory":
        d["records"][0].pop("sha256")
    else:
        d["upstream"][CID].pop("sha256")
    case = report(d)["vendors"][0]["cases"][0]
    assert case["publication_observations"] == []
    assert (
        "vendor_provenance_missing" if side == "advisory" else "upstream_provenance_missing"
    ) in case["timing_reasons"]


def test_report_schema_rejects_an_invented_timing_conclusion():
    from jsonschema import ValidationError

    result = report()
    report_validator().validate(result)
    result["vendors"][0]["cases"][0]["first_disclosure_days"] = 0
    with pytest.raises(ValidationError):
        report_validator().validate(result)
