"""Read-only exact-target inventory previews, independent of ambient application state."""

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from ..collection.target_import_profiles import TargetImportProfile
from ..collection.target_import_profiles import profile as registered_profile
from ..plugins.registry import default_registry
from ..settings import PACKAGE
from ..storage.checkpoint_copy import stable_checkpoint
from .evidence_identity import canonical_json, record_key
from .target_import_contracts import binding_fingerprint, preview_bytes


def now():
    return datetime.now(timezone.utc).isoformat()


def source_config_fingerprint() -> str:
    """Identify the installed build input, never native/root/operator sources.json."""
    digest = sha256()
    with (PACKAGE / "resources/sources.json").open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _latest_records(db):
    # Match repository.latest's logical records, streaming rather than materializing
    # the complete corpus. Raw evidence is never selected, parsed or serialized.
    for row in db.execute(
        "SELECT r.*,e.sha256,e.observed_at AS source_observed_at "
        "FROM revisions r JOIN evidence e ON e.id=r.evidence_id "
        "WHERE r.id IN (SELECT MAX(id) FROM revisions GROUP BY vendor,advisory_id) "
        "ORDER BY r.vendor,r.advisory_id"
    ):
        yield {
            **json.loads(row["normalized"]),
            "revision_id": row["id"],
            "evidence_id": row["evidence_id"],
            "sha256": row["sha256"],
            "source_observed_at": row["source_observed_at"],
            "observed_at": row["observed_at"],
        }


def binding(db, profile: TargetImportProfile) -> dict:
    """Bind complete latest candidate inputs and exact-target retrieval state.

    The caller supplies a consistent database transaction and validated profile.
    Latest selections cover every vendor: another vendor's proof can change the
    complete candidate partition without producing a new normalized revision.
    """
    inventory = sha256()

    def add(kind, facts):
        inventory.update(canonical_json({"kind": kind, "facts": facts}))
        inventory.update(b"\n")

    for record in _latest_records(db):
        add(
            "record",
            {
                "record_key": record_key(record),
                "payload_sha256": sha256(canonical_json(record)).hexdigest(),
            },
        )
    for row in db.execute(
        "SELECT s.*,e.source_url AS selected_source_url,e.sha256 AS selected_sha256 "
        "FROM source_selections s LEFT JOIN evidence e ON e.id=s.selected_evidence_id "
        "WHERE s.id IN (SELECT MAX(id) FROM source_selections GROUP BY vendor,requested_url) "
        "ORDER BY s.vendor,s.requested_url"
    ):
        add("selection", dict(row))
        for view in db.execute(
            "SELECT v.*,e.source_url,e.sha256,e.observed_at FROM source_selection_views v "
            "LEFT JOIN evidence e ON e.id=v.evidence_id WHERE v.selection_id=? ORDER BY v.id",
            (row["id"],),
        ):
            add("selection_view", dict(view))
        for issue in db.execute(
            "SELECT * FROM source_selection_issues WHERE selection_id=? ORDER BY id", (row["id"],)
        ):
            add("selection_issue", dict(issue))
    for target in profile.targets:
        observation = db.execute(
            "SELECT o.*,e.source_url AS evidence_url,e.sha256,e.observed_at "
            "FROM source_observations o LEFT JOIN evidence e ON e.id=o.evidence_id "
            "WHERE o.vendor=? AND o.source_url=? ORDER BY o.id DESC LIMIT 1",
            (target.vendor, target.fetch_url),
        ).fetchone()
        cached = db.execute(
            "SELECT c.*,e.source_url AS evidence_url,e.sha256,e.observed_at,e.media_type "
            "FROM http_cache c LEFT JOIN evidence e ON e.id=c.evidence_id WHERE c.url=?",
            (target.fetch_url,),
        ).fetchone()
        add(
            "target_http",
            {
                "vendor": target.vendor,
                "url": target.fetch_url,
                "observation": dict(observation) if observation else None,
                "cache": dict(cached) if cached else None,
            },
        )
    identities = {
        "baseline_fingerprint": inventory.hexdigest(),
        "manifest_fingerprint": profile.fingerprint,
        "source_config_fingerprint": source_config_fingerprint(),
        "normalizer_fingerprints": {
            vendor: default_registry().fingerprint(vendor)
            for vendor in sorted({target.vendor for target in profile.targets})
        },
    }
    return {**identities, "fingerprint": binding_fingerprint(identities)}


def preview(database: Path, profile_id: str) -> dict:
    """Preview one stable checkpoint copy, with no source SQLite or writer access."""
    selected = registered_profile(profile_id)
    supplied = Path(database)
    if any(path.is_symlink() for path in (supplied, *supplied.parents)):
        raise ValueError("unsafe_input_path")
    with stable_checkpoint(supplied, error_prefix="target_import") as copy:
        with closing(sqlite3.connect(copy.resolve().as_uri() + "?mode=ro", uri=True)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            before = {(target.vendor, target.advisory_id): [] for target in selected.targets}
            for record in _latest_records(db):
                identity = (record["vendor"], record["advisory_id"])
                if identity in before:
                    before[identity].append(record_key(record))
            receipt = {
                "format": "impact-target-import-preview",
                "schema_version": 1,
                "profile_id": selected.profile_id,
                "profile_version": selected.version,
                **binding(db, selected),
                "targets": [
                    target.metadata() | {"before_keys": before[(target.vendor, target.advisory_id)]}
                    for target in selected.targets
                ],
                "observed_at": now(),
            }
            preview_bytes(receipt, selected=selected)
            return receipt


def validate_lock_scope(home: Path, database: Path) -> None:
    """Require a canonical vault or an explicitly matching custom collector pair."""
    home = Path(home).resolve()
    database = Path(database).resolve()
    if database == (home / "data/intel.sqlite3").resolve():
        return
    configured_home = os.environ.get("IMPACT_HOME")
    configured_database = os.environ.get("IMPACT_DATABASE")
    if (
        not configured_home
        or not configured_database
        or Path(configured_home).resolve() != home
        or Path(configured_database).resolve() != database
    ):
        raise ValueError("ambiguous_target_import_lock_scope")
