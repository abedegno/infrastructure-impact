"""Source coverage profiles combined with observed collection freshness."""

import json
from datetime import datetime, timezone

from ..collection.config import load_config
from ..plugins.registry import default_registry
from ..settings import PACKAGE
from ..storage.repository import health
from .comparison import parse_date


def catalogue(db, records, config=None, at=None):
    config = config if config is not None else load_config()
    definition = json.loads((PACKAGE / "resources/coverage-catalogue.json").read_text())
    at = at or datetime.now(timezone.utc)
    checks = health(db)
    rows = []
    for plugin in default_registry().all():
        profile = definition["vendors"].get(
            plugin.id,
            {
                "product_families": [],
                "history_scope": "External plugin; coverage profile not declared",
                "known_gaps": [
                    "No reviewed coverage profile is bundled for this installed plugin."
                ],
            },
        )
        sources = [
            dict(item, role=section)
            for section in ("vendors", "pinned", "release_documents", "archives")
            for item in config.get(section, [])
            if item["vendor"] == plugin.id
        ]
        observed = [c for c in checks if c["vendor"] == plugin.id]
        successful = [c for c in observed if c["outcome"] in ("ok", "partial", "not_applicable")]
        last = max((c["checked_at"] for c in successful), default=None)
        age = (at - parse_date(last)).total_seconds() / 3600 if last else None
        rows.append(
            {
                "vendor": plugin.id,
                "name": plugin.name,
                **profile,
                "sources": sources,
                "capabilities": plugin.capabilities,
                "last_successful_check": last,
                "freshness": "not_checked"
                if age is None
                else "stale"
                if age > definition["policy"]["stale_after_hours"]
                else "fresh",
                "current_source_errors": sum(c["outcome"] == "error" for c in observed),
                "advisories": sum(r["vendor"] == plugin.id for r in records),
                "cadence_hours": definition["policy"]["cadence_hours"],
                "stale_after_hours": definition["policy"]["stale_after_hours"],
            }
        )
    return {"schema_version": 1, "policy": definition["policy"], "vendors": rows}
