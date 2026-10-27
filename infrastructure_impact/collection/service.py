"""Vendor-independent collection orchestration."""

import json
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from xml.etree import ElementTree as ET

from ..adapters.compat import HTML, auto, cves
from ..application.cohort import COHORT
from ..collection.errors import failure_code
from ..plugins.contracts import SourceNotApplicable, SourceSelection
from ..plugins.registry import default_registry
from ..storage.repository import collection_result, connect, evidence, ingest, now
from .discovery import discovery
from .transport import allowed, fetch

__all__ = ["fetch", "allowed", "discovery", "resolve_document", "run"]


def record_checks(db, raw, feed, present, scope):
    ev = evidence(db, raw, feed["url"])
    for cid in COHORT:
        db.execute(
            "INSERT OR REPLACE INTO coverage_checks VALUES(?,?,?,?,?,?,?)",
            (
                feed["vendor"],
                cid,
                now(),
                feed["url"],
                scope,
                "match" if cid in present else "no_match",
                ev["id"],
            ),
        )


def index_checks(db, raw, feed):
    if feed["kind"] != "rss":
        return
    items = ET.fromstring(raw).findall(".//item")
    present = {c for item in items for c in cves(" ".join(item.itertext()))}
    record_checks(
        db,
        raw,
        feed,
        present,
        f"Current RSS window ({len(items)} entries); historical coverage not implied",
    )


class ResolvedSource(tuple):
    """Two-item tuple compatible with older callers, plus alternate failure count."""

    def __new__(cls, url, raw, source_failures=0):
        value = super().__new__(cls, (url, raw))
        value.source_failures = source_failures
        return value


def resolve_document(db, url, vendor, *, fetcher=None):
    retrieve = fetcher or fetch
    registry = default_registry()
    plugin = registry.get(vendor)
    u = urlsplit(url)
    params = [(k, v) for k, v in parse_qsl(u.query) if not k.startswith(("utm_", "vs_"))]
    url = plugin.canonicalize(urlunsplit((u.scheme, u.netloc, u.path, urlencode(params), "")))
    raw = retrieve(db, url, vendor)
    if plugin.resolve:
        resolved = plugin.resolve(raw, url, lambda target: retrieve(db, target, vendor))
        if isinstance(resolved, SourceSelection):
            from ..storage.source_selections import retain

            retain(db, vendor, url, resolved)
            return ResolvedSource(
                resolved.selected.url, resolved.selected.raw, len(resolved.unavailable)
            )
        url, raw = resolved
        if not allowed(url, vendor):
            raise ValueError("Resolved source outside reviewed vendor routes")
    if raw.lstrip().startswith(b"{"):
        return url, raw
    for link in HTML(raw).root.find({"a"}):
        href = link.attrs.get("href", "")
        if "csaf" in href.lower() and href.lower().endswith(".json"):
            target = plugin.canonicalize(urljoin(url, href))
            structured = retrieve(db, target, vendor)
            parsed = json.loads(structured)
            if not any(v.get("product_status") for v in parsed.get("vulnerabilities", [])):
                try:
                    fallback = registry.normalize(raw, url, vendor)
                    if fallback["assessments"] or (
                        not fallback["cves"] and plugin.retain_unlinked_notice(fallback)
                    ):
                        return url, raw
                except (ValueError, KeyError):
                    pass
            return target, structured
    return url, raw


def run(config, limit=None, db_path=None, upstream_limit=0):
    from .config import validate_config

    validate_config(config)
    registry = default_registry()
    imported = failed = 0
    db = connect(db_path) if db_path else connect()
    with db:
        targets = list(config.get("pinned", []))
        for feed in config["vendors"]:
            count = feed.get("limit", 4) if limit is None else limit
            if not count:
                continue
            try:
                raw = fetch(db, feed["url"], feed["vendor"])
                plugin = registry.get(feed["vendor"])
                if plugin.parse_feed:
                    batch = plugin.parse_feed(raw, feed["url"], count, frozenset(COHORT))
                    if any(not allowed(u, feed["vendor"]) for u in batch.document_urls):
                        raise ValueError("Feed target outside reviewed vendor routes")
                    targets += [{"vendor": feed["vendor"], "url": u} for u in batch.document_urls]
                    record_checks(db, raw, feed, batch.referenced_cves, batch.scope)
                    for record in batch.records:
                        previous = db.execute(
                            "SELECT normalized FROM revisions WHERE vendor=? AND advisory_id=? ORDER BY id DESC LIMIT 1",
                            (feed["vendor"], record["advisory_id"]),
                        ).fetchone()
                        if previous and plugin.prefer_existing(
                            json.loads(previous["normalized"]), record
                        ):
                            continue
                        record = registry.finalize(record, feed["url"], feed["vendor"])
                        imported += ingest(
                            db,
                            raw,
                            feed["url"],
                            lambda *args, record=record: record,
                            feed["vendor"],
                        )
                    collection_result(db, feed["vendor"], feed["url"], batch.outcome, batch.scope)
                    continue
                index_checks(db, raw, feed)
                urls = discovery(
                    raw, feed["url"], feed["kind"], count, feed.get("order", "oldest_first")
                )
                if not urls:
                    raise ValueError("No advisory links discovered; check feed layout")
                targets += [{"vendor": feed["vendor"], "url": u} for u in urls]
                collection_result(
                    db,
                    feed["vendor"],
                    feed["url"],
                    "ok",
                    f"Discovered {len(urls)} documents from a bounded sample; full portfolio not enumerated.",
                )
            except Exception as e:
                failed += 1
                collection_result(db, feed["vendor"], feed["url"], "error", str(e), failure_code(e))
                print(f"ERROR {feed['vendor']} feed: {e}", flush=True)
        seen = set()
        for target in targets:
            key = (target["vendor"], target["url"])
            if key in seen:
                continue
            seen.add(key)
            try:
                resolved = resolve_document(db, target["url"], target["vendor"])
                url, raw = resolved
                alternate_failures = getattr(resolved, "source_failures", 0)
                failed += alternate_failures
                parsed = auto(raw, url, target["vendor"])
                if registry.get(target["vendor"]).non_cve_notice(parsed):
                    collection_result(
                        db,
                        target["vendor"],
                        target["url"],
                        "not_applicable",
                        "Recognised non-CVE notice; source retained, excluded from CVE assessments.",
                    )
                    continue
                changed = ingest(db, raw, url, lambda *args: parsed, target["vendor"])
                from .archive import acknowledge_retained

                acknowledge_retained(
                    db, target["vendor"], target["url"], url, evidence(db, raw, url)["id"]
                )
                imported += changed
                collection_result(
                    db,
                    target["vendor"],
                    target["url"],
                    "partial" if alternate_failures else "ok",
                    f"{'New revision' if changed else 'Unchanged'}; resolved source {url}",
                )
                print(
                    f"{'IMPORTED' if changed else 'UNCHANGED'} {target['vendor']} {url}", flush=True
                )
            except SourceNotApplicable as e:
                collection_result(db, target["vendor"], target["url"], "not_applicable", str(e))
                print(f"OUTSIDE VENDOR SCOPE {target['vendor']} {target['url']}", flush=True)
            except Exception as e:
                failed += 1
                collection_result(
                    db, target["vendor"], target["url"], "error", str(e), failure_code(e)
                )
                print(f"ERROR {target['vendor']} {target['url']}: {e}", flush=True)
        for doc in config.get("release_documents", []):
            try:
                from ..application.disclosure import import_release_note

                raw = fetch(db, doc["url"], doc["vendor"])
                if doc.get("kind") == "release_listing":
                    from ..application.release_assets import ingest_listing

                    ingest_listing(db, raw, doc["url"], doc["vendor"])
                else:
                    if doc.get("kind") == "component_inventory":
                        inventory = registry.get(doc["vendor"]).parse_component_inventory(
                            raw, doc["url"], doc["vendor"]
                        )
                        if inventory is None:
                            raise ValueError("Unreviewed component inventory source")
                    import_release_note(
                        db, raw, doc["url"], doc["vendor"], doc["product"], doc.get("published_at")
                    )
                collection_result(
                    db, doc["vendor"], doc["url"], "ok", "Configured release evidence collected"
                )
            except Exception as e:
                failed += 1
                collection_result(db, doc["vendor"], doc["url"], "error", str(e), failure_code(e))
        for ref in config.get("reference_sources", []):
            try:
                from ..references.storage import ingest as ingest_reference

                raw = fetch(db, ref["url"], "upstream")
                changed = ingest_reference(db, raw, ref["source_id"])
                collection_result(
                    db,
                    "upstream",
                    ref["url"],
                    "ok",
                    "Reference source retained; not a vendor product assessment",
                )
                print(
                    f"REFERENCE {ref['source_id']} {'changed' if changed else 'unchanged'}",
                    flush=True,
                )
            except Exception as e:
                failed += 1
                collection_result(db, "upstream", ref["url"], "error", str(e), failure_code(e))
                print(f"ERROR reference {ref['source_id']}: {e}", flush=True)
    if upstream_limit:
        from ..storage.repository import latest

        ids = sorted({c for r in latest(db) for c in r["cves"]})
        for cid in ids[:upstream_limit]:
            url = "https://cveawg.mitre.org/api/cve/" + cid
            try:
                raw = fetch(db, url, "upstream")
                metadata = json.loads(raw)["cveMetadata"]
                with db:
                    ev = evidence(db, raw, url)
                    db.execute(
                        "INSERT OR REPLACE INTO vulnerabilities VALUES(?,?,?,?,?)",
                        (
                            cid,
                            metadata.get("datePublished"),
                            metadata.get("dateUpdated"),
                            url,
                            ev["id"],
                        ),
                    )
                collection_result(
                    db, "upstream", url, "ok", "Upstream CVE publication metadata collected"
                )
            except Exception as e:
                failed += 1
                collection_result(db, "upstream", url, "error", str(e), failure_code(e))
                print(f"ERROR upstream {cid}: {e}", flush=True)
    db.close()
    return imported, failed
