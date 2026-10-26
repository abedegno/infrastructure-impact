"""Separate release metadata from vulnerability and availability assertions."""

import inspect
import json
from functools import lru_cache
from hashlib import sha256
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

from ..collection.transport import allowed
from ..domain import NormalizationError, validator
from ..plugins.registry import default_registry
from ..settings import PACKAGE
from ..storage.repository import evidence, now


@lru_cache(maxsize=1)
def asset_validator():
    schema = json.loads((PACKAGE / "schemas/release-asset-v1.json").read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=validator().format_checker)


def validate_asset(record):
    try:
        asset_validator().validate(record)
    except ValidationError as error:
        raise NormalizationError("Invalid release-listing metadata: " + error.message) from error
    if not allowed(record["source_url"], record["vendor"]):
        raise NormalizationError("Release listing must use an official allowed HTTPS source")
    return record


def ingest_listing(db, raw, url, vendor):
    plugin = default_registry().get(vendor)
    if not plugin.parse_release:
        raise ValueError("No reviewed release-listing parser installed for this vendor")
    record = plugin.parse_release(raw, url, vendor)
    code = Path(inspect.getsourcefile(plugin.parse_release)).read_bytes()
    record["adapter_version"] = sha256(code + plugin.version.encode()).hexdigest()[:16]
    validate_asset(record)
    if record["vendor"] != vendor or record["source_url"] != url:
        raise NormalizationError("Release parser changed vendor or source identity")
    normalized = json.dumps(record, sort_keys=True)
    with db:
        ev = evidence(db, raw, url, "release_listing")
        db.execute(
            "INSERT OR IGNORE INTO release_assets(evidence_id,vendor,source_url,published_at,normalized) VALUES(?,?,?,?,?)",
            (ev["id"], vendor, url, record["reported_published_at"], normalized),
        )
        current = db.execute(
            "SELECT id FROM release_assets WHERE evidence_id=? AND vendor=? AND source_url=? AND normalized=?",
            (ev["id"], vendor, url, normalized),
        ).fetchone()["id"]
        previous = db.execute(
            "SELECT o.release_asset_id FROM release_asset_observations o JOIN release_assets a ON a.id=o.release_asset_id WHERE a.vendor=? AND a.source_url=? ORDER BY o.id DESC LIMIT 1",
            (vendor, url),
        ).fetchone()
        if not previous or previous["release_asset_id"] != current:
            db.execute(
                "INSERT INTO release_asset_observations(release_asset_id,observed_at) VALUES(?,?)",
                (current, now()),
            )
    return record


def listings(db):
    rows = db.execute(
        "SELECT a.normalized,a.evidence_id,e.sha256,e.observed_at FROM release_assets a JOIN evidence e ON e.id=a.evidence_id JOIN release_asset_observations o ON o.release_asset_id=a.id WHERE o.id IN (SELECT MAX(o.id) FROM release_asset_observations o JOIN release_assets a ON a.id=o.release_asset_id GROUP BY a.vendor,a.source_url) ORDER BY a.vendor,a.source_url"
    )
    return [
        {
            **validate_asset(json.loads(r["normalized"])),
            "evidence_id": r["evidence_id"],
            "source_sha256": r["sha256"],
            "observed_at": r["observed_at"],
        }
        for r in rows
    ]
