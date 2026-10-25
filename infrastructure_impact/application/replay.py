"""Offline re-normalization from retained evidence, never invented source changes."""

from contextlib import closing

from ..plugins.registry import default_registry
from ..storage.repository import connect, ingest, latest
from .cohort import COHORT


def replay():
    registry = default_registry()
    changed = 0
    with closing(connect()) as db:
        for record in latest(db):
            raw = db.execute(
                "SELECT raw FROM evidence WHERE id=?", (record["evidence_id"],)
            ).fetchone()[0]
            vendor, url = record["vendor"], record["source_url"]
            plugin = registry.get(vendor)
            if record["source_format"] in (
                "RSS discovery metadata",
                "Check Point public advisory JSON",
            ):
                batch = plugin.parse_feed(raw, url, 100000, frozenset(COHORT))
                document = next(
                    r for r in batch.records if r["advisory_id"] == record["advisory_id"]
                )
                document = registry.finalize(document, url, vendor)
            else:
                document = registry.normalize(raw, url, vendor)
            changed += ingest(db, raw, url, lambda *args, document=document: document, vendor)
    return changed
