"""Read-only dataset queries used to assemble a publication."""

import json
import os

from ..phase_events import phase
from ..plugins.registry import default_registry
from ..settings import Paths
from ..storage.repository import VENDORS, health, history, latest, now
from .catalogue import catalogue
from .cohort import COHORT, coverage
from .comparison import compare
from .disclosure import latest_documents, signals
from .evaluation import evaluate
from .extraction_validation import definition as review_definition
from .extraction_validation import review_packet, validation_report
from .fix_leads import evidence_inputs
from .kev import build_report
from .publisher_history import publisher_history
from .release_assets import listings
from .scorecards import scorecards
from .source_audit import source_audit
from .source_scope import retained_scopes
from .timeline import evidence_timeline

ROOT = Paths.from_env().home


def current_partition(db, records=None, *, generated_at=None):
    """Return (partition, private context) from retained local evidence; no writes or HTTP."""
    from .current_evidence import collect_policy_input, partition

    records = latest(db) if records is None else records
    context = collect_policy_input(db, records, registry=default_registry())
    return partition(
        records,
        context,
        registry=default_registry(),
        publication=None,
        generated_at=generated_at or now(),
    ), context


@phase("publication.query")
def state(db, cohort=None):
    retained = latest(db)
    scopes = retained_scopes(db, retained, review_definition())
    generated = now()
    partition_result, context = current_partition(db, retained, generated_at=generated)
    records = partition_result["records"]
    upstream = {
        r["cve_id"]: dict(r)
        for r in db.execute(
            "SELECT v.*, e.sha256 FROM vulnerabilities v LEFT JOIN evidence e ON e.id=v.evidence_id"
        )
    }
    comparison = compare(records, cohort)
    all_scope = sorted(
        set(COHORT) | {c for r in records for c in r["cves"]} | set(comparison["cohort"])
    )
    all_coverage = coverage(db, records, all_scope)
    profiles = catalogue(db, records)
    checks = health(db)
    review_signals = signals(db)
    from ..collection.config import load_config
    from ..references.storage import enrichment_input
    from ..references.storage import latest as reference_inputs
    from .switching_evidence import inputs as switching_inputs
    from .switching_evidence import score_inputs

    research = {
        "switching_input": switching_inputs(db, records),
        "score_input": score_inputs(db, retained),
        "study_inputs": reference_inputs(db, purpose="component_study"),
        "kev_input": enrichment_input(db, load_config(), "cisa-kev"),
        "release_assets": listings(db),
        "release_documents": [
            {k: r[k] for k in ("vendor", "product", "source_url", "published_at", "evidence_id")}
            for r in latest_documents(db)
        ],
        "lead_inputs": evidence_inputs(db),
        "fix_candidates": [
            dict(r) for r in db.execute("SELECT * FROM fix_evidence ORDER BY id DESC")
        ],
    }
    from ..collection.switching_backfill import manifest
    from .switching_evidence import definition

    merge_switching_manifest(research["switching_input"], manifest(db, study_id=definition()["id"]))
    run = None
    if db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pipeline_runs'"
    ).fetchone():
        row = db.execute("SELECT * FROM pipeline_runs ORDER BY id DESC LIMIT 1").fetchone()
        if row:
            run = dict(row)
    schedule_path = Paths.from_env().home / "ops/schedule-status.json"
    schedule = (
        json.loads(schedule_path.read_text()) if schedule_path.exists() else {"installed": False}
    )
    result = {
        "generated_at": generated,
        "vendors": dict(VENDORS),
        "plugins": [
            {
                "id": p.id,
                "name": p.name,
                "version": p.version,
                "capabilities": p.capabilities,
                "normalizer_fingerprint_scheme": default_registry().fingerprint_scheme(p.id),
                "current_normalizer_fingerprint": default_registry().fingerprint(p.id),
            }
            for p in default_registry().all()
        ],
        "records": records,
        "comparison": comparison,
        "collector": {
            "last_run": run,
            "schedule": schedule,
            "hosted_auto_publication": os.environ.get("IMPACT_DELIVERY_MODE")
            in ("live_reader", "scheduled_static"),
        },
        "benchmark_cohort": COHORT,
        "catalogue": profiles,
        "scorecards": scorecards(
            records, all_coverage, profiles, checks, all_scope, dict(VENDORS), generated
        ),
        "timeline": evidence_timeline(db),
        "source_audit": source_audit(db, retained),
        "benchmark": evaluate(records, retained_advisories=partition_result["retained_advisories"]),
        "extraction_validation": validation_report(
            records, scopes=scopes, retained_advisories=partition_result["retained_advisories"]
        ),
        "reviewed_source_scopes": scopes,
        "review_packet": review_packet(retained),
        "publisher_history": publisher_history(db),
        "coverage": all_coverage,
        "changes": history(db, full=False),
        "signals": review_signals,
        "research": research,
        "health": checks,
        "upstream": upstream,
        "delays": [],  # Deprecated unscoped aggregate; use eligible paired metadata instead.
        "all_cves": sorted({c for r in records for c in r["cves"]}),
        "counts": {
            "advisories": len(records),
            "evidence_snapshots": db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0],
        },
    }

    result["kev"] = build_report(
        research["kev_input"],
        sorted(set(all_scope) | {c for r in retained for c in r["cves"]}),
        publication=result.get("publication"),
        generated_at=generated,
    )

    from .current_views import rebuild

    result = rebuild(result, partition_result)
    result["research"]["current_evidence_input"] = context
    return result


def merge_switching_manifest(inputs, manifest):
    """Join actual source-window facts, never infer historical period coverage."""
    from .switching_evidence import definition, definition_sha256

    fingerprint = definition_sha256(definition())
    counters = (
        "expected_total",
        "discovered_unique_identities",
        "duplicate_entries",
        "withdrawn_entries",
        "retrieved",
        "parsed",
        "parse_failed",
        "retrieval_failed",
        "classified",
        "classification_pending",
        "unknown_dates",
        "unknown_models",
        "exhausted_errors",
    )
    for entry in manifest["entries"]:
        if entry["definition_sha256"] != fingerprint:
            continue
        if not entry.get("source_url"):
            inputs["issues"].append("enumeration_source_unavailable")
            continue
        enumeration = {key: entry.get(key) for key in counters}
        enumeration.update(
            {
                key: entry[key]
                for key in (
                    "definition_sha256",
                    "source_kind",
                    "window",
                    "coverage_state",
                    "portfolio_completeness",
                )
            }
        )
        enumeration["gaps"] = sorted(set(entry["gaps"] + entry.get("errors", [])))
        from .switching_comparison import day

        dates = sorted(
            {
                day(p["retrieved_at"])
                for p in entry.get("page_evidence", [])
                if p.get("retrieved_at")
            }
        )
        missing = [] if dates else ["observation_start_unknown", "observation_end_unknown"]
        # Repeated runs/windows remain separate facts; they are never summed.
        inputs["coverage"].append(
            dict(
                vendor=entry["vendor"],
                source_url=entry["source_url"],
                state="unstable"
                if entry["coverage_state"] == "unstable"
                else "unavailable"
                if entry["coverage_state"] in ("not_configured", "blocked")
                else "partial",
                observed_start=dates[0] if dates else None,
                observed_end=dates[-1] if dates else None,
                total=None,
                issues=missing
                + ["publisher_total_unknown", "source_window_not_period_completeness"],
                enumeration=enumeration,
            )
        )
