"""Audit current source windows and durable historical collection progress."""

import json
from xml.etree.ElementTree import ParseError

from ..collection.config import load_config
from ..collection.discovery import inventory
from ..collection.errors import check_access_response
from ..collection.transport import allowed
from ..plugins.registry import default_registry
from ..settings import PACKAGE
from ..storage.repository import health, now


def source_audit(db, records, config=None):
    config = config if config is not None else load_config()
    checks = {(r["vendor"], r["source_url"]): r for r in health(db)}
    profiles = json.loads((PACKAGE / "resources/coverage-catalogue.json").read_text())["vendors"]
    from ..collection.archive import progress

    archives = progress(db, records, config)
    reviews = json.loads((PACKAGE / "resources/archive-source-review.json").read_text())["vendors"]
    audits = []
    for vendor, name in default_registry().names().items():
        feeds = []
        for feed in config.get("vendors", []):
            if feed["vendor"] != vendor:
                continue
            row = db.execute(
                "SELECT e.* FROM http_cache h JOIN evidence e ON e.id=h.evidence_id WHERE h.url=?",
                (feed["url"],),
            ).fetchone()
            result = dict(
                source_url=feed["url"],
                kind=feed["kind"],
                configured_limit=feed.get("limit", 4),
                index_benchmark_limit=200 if feed["kind"] == "index" else None,
                recorded_search_scopes=sorted(
                    {
                        r["scope"]
                        for r in db.execute(
                            "SELECT scope FROM coverage_checks WHERE vendor=? AND source_url=?",
                            (vendor, feed["url"]),
                        )
                    }
                ),
                pagination_followed=False,
                archive_enumerated=False,
                evidence_state="not_retained",
                source_sha256=None,
                source_observed_at=None,
                entry_count=None,
                unique_links=None,
                entries_without_links=None,
                raw_documents_retained=None,
                product_advisories_current=None,
                next_pages=[],
                latest_check_outcome=checks.get((vendor, feed["url"]), {}).get(
                    "outcome", "not_checked"
                ),
            )
            if row:
                result.update(source_sha256=row["sha256"], source_observed_at=row["observed_at"])
                try:
                    check_access_response(row["raw"])
                    if feed["kind"] in ("checkpoint", "advisory_index"):
                        document = json.loads(row["raw"])
                        if not isinstance(document, list):
                            raise ValueError("Expected reviewed active-index array")
                        result.update(
                            evidence_state="retained_active_response", entry_count=len(document)
                        )
                    else:
                        found = inventory(row["raw"], feed["url"], feed["kind"])
                        links = set(found.pop("urls"))
                        found["next_pages"] = [u for u in found["next_pages"] if allowed(u, vendor)]
                        retained = {
                            r["source_url"]
                            for r in db.execute("SELECT DISTINCT source_url FROM evidence")
                        }
                        result.update(
                            **found,
                            unique_links=len(links),
                            raw_documents_retained=len(links & retained),
                            product_advisories_current=sum(
                                r["vendor"] == vendor
                                and r["source_url"] in links
                                and bool(r["assessments"])
                                and r.get("document_status") != "draft"
                                for r in records
                            ),
                            evidence_state="retained_window"
                            if feed["kind"] == "rss"
                            else "retained_index",
                        )
                except (ValueError, KeyError, TypeError, ParseError) as error:
                    result.update(
                        evidence_state="unusable_retained_response", diagnostic=type(error).__name__
                    )
            matching = [
                a for a in archives if a["vendor"] == vendor and a["source_url"] == feed["url"]
            ]
            result["pagination_followed"] = any(a["pages"]["done"] > 1 for a in matching)
            result["archive_enumerated"] = any(
                a["kind"] == "index" and a["known_queue_exhausted"] for a in matching
            )
            feeds.append(result)
        audits.append(
            dict(
                vendor=vendor,
                name=name,
                feeds=feeds,
                declared_product_families=profiles.get(vendor, {}).get("product_families", []),
                observed_product_labels_count=len(
                    {
                        a["product"]
                        for r in records
                        if r["vendor"] == vendor
                        for a in r["assessments"]
                    }
                ),
                source_errors=[
                    {
                        "source_url": h["source_url"],
                        "error_code": h.get("error_code"),
                        "checked_at": h["checked_at"],
                    }
                    for h in checks.values()
                    if h["vendor"] == vendor and h["outcome"] == "error"
                ],
                pinned_documents=sum(p["vendor"] == vendor for p in config.get("pinned", [])),
                release_documents=sum(
                    p["vendor"] == vendor for p in config.get("release_documents", [])
                ),
                archive_source_review={
                    **reviews[vendor],
                    "configured": any(
                        a["vendor"] == vendor and a["source_url"] == reviews[vendor]["source_url"]
                        for a in archives
                    ),
                }
                if vendor in reviews
                else None,
                archives=[a for a in archives if a["vendor"] == vendor],
                enumeration="bounded_feeds_and_pins" if feeds else "pinned_only",
                archive_enumerated=any(
                    a["vendor"] == vendor and a["kind"] == "index" and a["known_queue_exhausted"]
                    for a in archives
                ),
                pagination_followed=any(
                    a["vendor"] == vendor and a["pages"]["done"] > 1 for a in archives
                ),
                portfolio_completeness="not_established",
            )
        )
    return dict(
        schema_version=1,
        audited_at=now(),
        vendors=audits,
        method="Code/configuration and retained primary-response audit. Counts describe the retained response, not the full publisher archive. Raw retention is not successful extraction or affectedness. Configured archive queues follow official advertised next links within per-pass budgets. Known queue exhaustion is not portfolio completeness. Publisher date ranges do not establish historical availability. The benchmark index cap is the bundled default; retained checks record actual pass scope.",
    )
