"""Isolated exact-target ingestion. Candidate acceptance is a separate boundary."""

import json
import shutil
import sqlite3
import time
from contextlib import closing
from hashlib import sha256
from pathlib import Path

from ..collection import transport
from ..collection.transport_budget import TransportBudget
from ..domain import validate_advisory
from ..plugins.registry import default_registry
from ..storage.checkpoint_copy import stable_checkpoint
from ..storage.locking import writer_lock
from ..storage.repository import ingest
from . import target_import
from .evidence_identity import canonical_json, record_key
from .target_import_contracts import BINDING_FIELDS, result_bytes, validate_preview


class StageFailure(ValueError):
    """Only locally assigned, closed receipt codes cross this boundary."""


def verify(database, public, profile):
    from .import_candidate import verify as verify_candidate

    return verify_candidate(database, public, profile)


class PacedBudget(TransportBudget):
    def __init__(self, profile):
        super().__init__(profile.max_http_attempts, profile.max_received_bytes)
        self.interval = profile.min_request_interval_seconds
        self.last_attempt = None

    def start_attempt(self):
        if self.last_attempt is not None:
            delay = self.interval - (time.monotonic() - self.last_attempt)
            if delay > 0:
                time.sleep(delay)
        super().start_attempt()
        self.last_attempt = time.monotonic()


def _file_state(database):
    """No SQLite access to the source, including its sidecars."""
    state = {}
    for suffix in ("", "-wal", "-shm", "-journal"):
        path = Path(str(database) + suffix)
        if path.is_symlink():
            raise StageFailure("storage")
        try:
            st = path.stat()
        except FileNotFoundError:
            state[suffix] = None
            continue
        digest = sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        after = path.stat()
        keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(st, k) != getattr(after, k) for k in keys):
            raise StageFailure("stale_preview")
        state[suffix] = {**{k: getattr(st, k) for k in keys}, "sha256": digest.hexdigest()}
    return state


def _quoted(name):
    return '"' + name.replace('"', '""') + '"'


def _retained_rows(db, selected, baseline=None):
    """Hash existing row prefixes; only exact-target HTTP cache rows may change.

    sqlite_sequence tracks permitted appends. Every other preexisting row,
    including exclusions, review state, source selections and failures, is fixed.
    """
    tables = baseline or {
        row[0]: None
        for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    result = {}
    for table, prior in tables.items():
        quoted = _quoted(table)
        maximum = (
            prior["max_rowid"]
            if prior
            else db.execute(f"SELECT COALESCE(MAX(rowid),0) FROM {quoted}").fetchone()[0]
        )
        digest = sha256()
        count = 0
        for row in db.execute(
            f"SELECT rowid AS _rowid_,* FROM {quoted} WHERE rowid<=? ORDER BY rowid", (maximum,)
        ):
            if table == "http_cache" and row["url"] in selected.allowed_urls:
                continue
            values = [
                {"bytes_sha256": sha256(v).hexdigest(), "size": len(v)}
                if isinstance(v, bytes)
                else v
                for v in row
            ]
            digest.update(canonical_json(values) + b"\n")
            count += 1
        result[table] = {"max_rowid": maximum, "count": count, "sha256": digest.hexdigest()}
    return result


def _initial_result(selected, accepted):
    return {
        "format": "impact-target-import-result",
        "schema_version": 1,
        "profile_id": selected.profile_id,
        "profile_version": selected.version,
        **{k: accepted[k] for k in (*BINDING_FIELDS, "fingerprint")},
        "observed_at": target_import.now(),
        "outcome": "failed",
        "failure_code": "storage",
        "targets": [
            {
                **{
                    k: t.metadata()[k]
                    for k in ("vendor", "advisory_id", "fetch_url", "source_sha256")
                },
                "status": "not_attempted",
                "failure_code": None,
                "before_keys": prior["before_keys"],
                "after_keys": [],
            }
            for t, prior in zip(selected.targets, accepted["targets"])
        ],
        "counters": dict.fromkeys(
            ("http_attempts", "received_bytes", "input_bytes", "imported", "unchanged"), 0
        ),
        "checks": dict.fromkeys(("audit_passed", "candidate_validated", "capacity_passed")),
        "candidate": None,
        "staged_database": None,
        "public_directory": None,
    }


def _paths(database, output, home):
    for path in (database, output, home / "data/collector.lock"):
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise StageFailure("storage")
    if output.exists() or output.resolve() in database.resolve().parents:
        raise StageFailure("storage")
    if output.resolve().is_relative_to(home.resolve()):
        raise StageFailure("storage")
    if any(
        output.resolve() == Path(str(database.resolve()) + s)
        for s in ("", "-wal", "-shm", "-journal")
    ):
        raise StageFailure("storage")
    target_import.validate_lock_scope(home, database)


def _keys(db):
    return {
        (r["vendor"], r["advisory_id"]): record_key(r) for r in target_import._latest_records(db)
    }


def _preflight_existing(db, selected, result):
    keys = _keys(db)
    for target, status in zip(selected.targets, result["targets"]):
        key = keys.get((target.vendor, target.advisory_id))
        status["before_keys"] = [key] if key else []
        row = db.execute(
            "SELECT r.*,e.sha256,e.source_url AS capture_url FROM revisions r "
            "JOIN evidence e ON e.id=r.evidence_id WHERE r.vendor=? AND r.advisory_id=? "
            "ORDER BY r.id DESC LIMIT 1",
            (target.vendor, target.advisory_id),
        ).fetchone()
        for requested_url in {target.fetch_url, target.discovery_url}:
            selection = db.execute(
                "SELECT s.selected_evidence_id,e.source_url,e.sha256 FROM source_selections s "
                "LEFT JOIN evidence e ON e.id=s.selected_evidence_id "
                "WHERE s.vendor=? AND s.requested_url=? ORDER BY s.id DESC LIMIT 1",
                (target.vendor, requested_url),
            ).fetchone()
            if (
                selection
                and selection["selected_evidence_id"] is not None
                and (
                    selection["source_url"] != target.fetch_url
                    or selection["sha256"] != target.source_sha256
                )
            ):
                status.update(status="failed", failure_code="existing_identity_conflict")
                raise StageFailure("existing_identity_conflict")
        if row and (
            row["source_url"] != target.fetch_url
            or row["capture_url"] != target.fetch_url
            or row["sha256"] != target.source_sha256
            or sorted(json.loads(row["normalized"]).get("cves", [])) != list(target.cve_ids)
        ):
            status.update(status="failed", failure_code="existing_identity_conflict")
            raise StageFailure("existing_identity_conflict")


def _fetch(db, target, selected, budget):
    try:
        return transport.fetch(
            db,
            target.fetch_url,
            target.vendor,
            max_bytes=selected.max_document_bytes,
            allowed_urls=selected.allowed_urls,
            budget=budget,
            forbid_redirects=True,
        )
    except sqlite3.Error:
        raise StageFailure("storage") from None
    except Exception as error:
        code = {
            "HTTP attempt budget exhausted": "attempt_budget",
            "HTTP received body budget exhausted": "received_budget",
            "HTTP received body budget exhausted before EOF": "received_budget",
        }.get(str(error), "source_access")
        raise StageFailure(code) from None


def _preflight(db, selected, result, budget):
    ready, seen = [], set()
    for target, status in zip(selected.targets, result["targets"]):
        try:
            raw = _fetch(db, target, selected, budget)
            digest = sha256(raw).hexdigest()
            if digest not in seen:
                size = result["counters"]["input_bytes"] + len(raw)
                if size > selected.max_input_bytes:
                    raise StageFailure("input_budget")
                result["counters"]["input_bytes"] = size
                seen.add(digest)
            if digest != target.source_sha256:
                raise StageFailure("source_drift")
            try:
                normalized = default_registry().normalize(raw, target.fetch_url, target.vendor)
                validate_advisory(normalized, vendor=target.vendor, source_url=target.fetch_url)
            except Exception:
                raise StageFailure("normalization") from None
            if normalized["advisory_id"] != target.advisory_id or sorted(
                normalized["cves"]
            ) != list(target.cve_ids):
                raise StageFailure("identity")
            ready.append((target, raw, normalized))
            status["status"] = "validated"
        except StageFailure as error:
            status.update(status="failed", failure_code=str(error))
            raise
    return ready


def stage(
    database: Path,
    profile,
    expected_fingerprint: str,
    output: Path,
    *,
    lock_home: Path,
    accepted_preview: dict,
) -> dict:
    """Hold one collector lock, validate all targets, then ingest only a private copy.

    Result binding identities describe the accepted request on every outcome.
    The copied baseline is independently rechecked under the lock. Invalid request
    receipts raise before filesystem access. Source paths never enter receipts.
    """
    database, output, home = Path(database), Path(output), Path(lock_home)
    accepted = validate_preview(accepted_preview, profile)
    result = _initial_result(profile, accepted)
    budget = PacedBudget(profile)
    source_before = None
    try:
        if expected_fingerprint != accepted["fingerprint"]:
            raise StageFailure("stale_preview")
        _paths(database, output, home)
        with writer_lock(home=home) as acquired:
            if not acquired:
                result["outcome"] = "skipped_writer_lock"
                raise StageFailure("writer_lock")
            source_before = _file_state(database)
            with stable_checkpoint(database, error_prefix="target_import") as checkpoint:
                output.mkdir(mode=0o700)
                staged = output / "private/data/intel.sqlite3"
                staged.parent.mkdir(parents=True, mode=0o700)
                stage_home = output / "private/home"
                stage_home.mkdir(mode=0o700)
                shutil.copyfile(checkpoint, staged)
            with closing(sqlite3.connect(staged)) as db:
                db.row_factory = sqlite3.Row
                db.execute("PRAGMA foreign_keys=ON")
                db.execute("BEGIN")
                observed_binding = target_import.binding(db, profile)
                if observed_binding["fingerprint"] != expected_fingerprint:
                    raise StageFailure("stale_preview")
                baseline = _retained_rows(db, profile)
                _preflight_existing(db, profile, result)
                db.commit()
                ready = _preflight(db, profile, result, budget)
                for (target, raw, normalized), status in zip(ready, result["targets"]):
                    changed = ingest(
                        db, raw, target.fetch_url, lambda *a: normalized, target.vendor
                    )
                    status["status"] = "imported" if changed else "unchanged"
                    current = db.execute(
                        "SELECT r.id AS revision_id,r.vendor,r.advisory_id,r.source_url,e.sha256 "
                        "FROM revisions r JOIN evidence e ON e.id=r.evidence_id "
                        "WHERE r.vendor=? AND r.advisory_id=? ORDER BY r.id DESC LIMIT 1",
                        (target.vendor, target.advisory_id),
                    ).fetchone()
                    status["after_keys"] = [record_key(dict(current))]
                preserved = _retained_rows(db, profile, baseline) == baseline
                source_after = _file_state(database)
                source_unchanged = source_after == source_before
                if not preserved or not source_unchanged:
                    raise StageFailure("storage")
                context = {
                    "format": "impact-target-import-context",
                    "schema_version": 1,
                    "binding": {k: result[k] for k in (*BINDING_FIELDS, "fingerprint")},
                    "observed_binding": observed_binding,
                    "targets": result["targets"],
                    "preservation": {
                        "source_unchanged": source_unchanged,
                        "source_before": source_before,
                        "source_after": source_after,
                        "existing_rows_unchanged": preserved,
                        "baseline_tables": baseline,
                        "allowed_cache_urls": sorted(profile.allowed_urls),
                    },
                }
                (stage_home / "target-import-context.json").write_bytes(
                    canonical_json(context) + b"\n"
                )
            checked = verify(staged, output / "public", profile)
            if "candidate" in checked or all(checked.get(k) is True for k in result["checks"]):
                from .import_candidate import validate_result

                try:
                    validate_result(checked)
                except Exception:
                    raise StageFailure("candidate_validation") from None
                result["candidate"] = checked["candidate"]
            result["checks"] = {
                k: checked.get(k) if type(checked.get(k)) is bool else None
                for k in result["checks"]
            }
            for check, failure in (
                ("audit_passed", "audit"),
                ("capacity_passed", "candidate_capacity"),
                ("candidate_validated", "candidate_validation"),
            ):
                if result["checks"][check] is False:
                    raise StageFailure(failure)
            if not all(v is True for v in result["checks"].values()):
                raise StageFailure("candidate_validation")
            with closing(sqlite3.connect(staged.resolve().as_uri() + "?mode=ro", uri=True)) as db:
                db.row_factory = sqlite3.Row
                if _retained_rows(db, profile, baseline) != baseline:
                    raise StageFailure("storage")
            if _file_state(database) != source_before:
                raise StageFailure("storage")
            result.update(
                outcome="completed",
                failure_code=None,
                staged_database="private/data/intel.sqlite3",
                public_directory="public/",
            )
    except StageFailure as error:
        result["failure_code"] = str(error)
    except Exception:
        result["failure_code"] = "storage"
    finally:
        if source_before is not None:
            try:
                if _file_state(database) != source_before:
                    result.update(
                        outcome="failed",
                        failure_code="storage",
                        staged_database=None,
                        public_directory=None,
                    )
            except Exception:
                result.update(
                    outcome="failed",
                    failure_code="storage",
                    staged_database=None,
                    public_directory=None,
                )
    result["counters"].update(http_attempts=budget.attempts, received_bytes=budget.received_bytes)
    for status in ("imported", "unchanged"):
        result["counters"][status] = sum(t["status"] == status for t in result["targets"])
    result_bytes(result, selected=profile)
    return result
