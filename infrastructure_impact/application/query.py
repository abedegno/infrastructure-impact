"""Read-only dataset queries used to assemble a publication."""

import json
import os

from ..plugins.registry import default_registry
from ..settings import Paths
from ..storage.repository import VENDORS, health, history, latest, now
from .casefiles import casefiles
from .catalogue import catalogue
from .cohort import COHORT, coverage
from .comparison import compare
from .disclosure import latest_documents, signals
from .eligibility import eligibility
from .evaluation import evaluate
from .extraction_validation import definition as review_definition
from .extraction_validation import review_packet, validation_report
from .product_groups import product_groups
from .publisher_history import publisher_history
from .release_assets import listings
from .scorecards import scorecards
from .source_audit import source_audit
from .source_scope import retained_scopes
from .timeline import evidence_timeline

ROOT = Paths.from_env().home


def state(db, cohort=None):
    records = latest(db)
    scopes = retained_scopes(db, records, review_definition())
    upstream = {
        r["cve_id"]: dict(r)
        for r in db.execute(
            "SELECT v.*, e.sha256 FROM vulnerabilities v LEFT JOIN evidence e ON e.id=v.evidence_id"
        )
    }
    generated = now()
    comparison = compare(records, cohort)
    all_scope = sorted(
        set(COHORT) | {c for r in records for c in r["cves"]} | set(comparison["cohort"])
    )
    all_coverage = coverage(db, records, all_scope)
    profiles = catalogue(db, records)
    checks = health(db)
    review_signals = signals(db)
    research = {
        "release_assets": listings(db),
        "release_documents": [
            {k: r[k] for k in ("vendor", "product", "source_url", "published_at", "evidence_id")}
            for r in latest_documents(db)
        ],
        "fix_candidates": [
            dict(r) for r in db.execute("SELECT * FROM fix_evidence ORDER BY id DESC")
        ],
    }
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
            {"id": p.id, "name": p.name, "version": p.version, "capabilities": p.capabilities}
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
        "source_audit": source_audit(db, records),
        "benchmark": evaluate(records),
        "extraction_validation": validation_report(records, scopes=scopes),
        "reviewed_source_scopes": scopes,
        "review_packet": review_packet(records),
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

    result["casefiles"] = casefiles(result)
    result["product_groups"] = product_groups(result)
    result["comparison_eligibility"] = eligibility(result, comparison["cohort"])
    return result
