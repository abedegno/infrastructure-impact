"""One scheduled collection pass with process exclusion and a durable run receipt.

Collects public evidence and rebuilds the local snapshot. Deployment is separate
from this durable collection receipt; deployment credentials are not stored here.
"""

from contextlib import closing

from ..settings import Paths
from ..storage.repository import connect, now

ROOT = Paths.from_env().home


def ensure_runs(db):
    db.execute("SELECT id FROM pipeline_runs LIMIT 0")


def execute(sync_fn, cohort_fn, report_fn, build_fn, db_path=None, status_fn=None):
    with closing(connect(db_path) if db_path else connect()) as db:
        ensure_runs(db)
        # A previous running record under the exclusive process lock represents an
        # interrupted process, not evidence of a successful collection.
        with db:
            db.execute(
                "UPDATE pipeline_runs SET outcome='interrupted',finished_at=?,details='Previous process ended before recording completion' WHERE outcome='running'",
                (now(),),
            )
            started = now()
            run_id = db.execute(
                "INSERT INTO pipeline_runs(started_at,outcome) VALUES(?,'running')", (started,)
            ).lastrowid
        imported = failures = 0
        try:
            for collect in (sync_fn, cohort_fn):
                added, failed = collect()
                imported += added
                failures += failed
            report_fn()
            outcome = "partial" if failures else "ok"
            checks = list(
                db.execute("SELECT outcome FROM collection_runs WHERE checked_at>=?", (started,))
            )
            all_failed = (
                bool(checks)
                and failures
                and not any(
                    r["outcome"] in ("ok", "partial", "not_applicable", "reprocessed")
                    for r in checks
                )
            )
            if all_failed:
                outcome = "error"
            with db:
                db.execute(
                    "UPDATE pipeline_runs SET finished_at=?,outcome=?,imported=?,failures=?,details=? WHERE id=?",
                    (
                        now(),
                        outcome,
                        imported,
                        failures,
                        "No successful source checks; previous publication retained."
                        if all_failed
                        else "Collection finished; source gaps remain visible. Data publication is distinct from code deployment.",
                        run_id,
                    ),
                )
            if not all_failed:
                build_fn()
        except Exception as e:
            with db:
                db.execute(
                    "UPDATE pipeline_runs SET finished_at=?,outcome='error',imported=?,failures=?,details=? WHERE id=?",
                    (now(), imported, failures + 1, str(e)[:2000], run_id),
                )
            if status_fn:
                status_fn(
                    dict(
                        db.execute(
                            "SELECT id,started_at,finished_at,outcome,imported,failures FROM pipeline_runs WHERE id=?",
                            (run_id,),
                        ).fetchone()
                    )
                )
            raise
        if status_fn:
            status_fn(
                dict(
                    db.execute(
                        "SELECT id,started_at,finished_at,outcome,imported,failures FROM pipeline_runs WHERE id=?",
                        (run_id,),
                    ).fetchone()
                )
            )
        return {"id": run_id, "outcome": outcome, "imported": imported, "failures": failures}
