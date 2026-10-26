"""Systematic, bounded benchmark collection from upstream references and Aruba CSAF.

Only allowlisted vendor sources are fetched. Index no-match statements describe
the searched source, never the vendor's entire product portfolio.
"""

import json
from urllib.parse import urlsplit

from ..adapters.compat import auto
from ..collection.config import load_config
from ..collection.errors import failure_code
from ..collection.service import allowed, fetch, resolve_document
from ..plugins.registry import default_registry
from ..settings import Paths
from ..storage.repository import collection_result, connect, evidence, ingest, latest, now
from .cohort import COHORT, coverage


def canonical(url, vendor):
    return default_registry().get(vendor).canonicalize(url)


def run(aruba_limit=200):
    db = connect()
    coverage(db, [], [])
    targets = {}
    failures = imported = 0
    for cid in COHORT:
        url = "https://cveawg.mitre.org/api/cve/" + cid
        try:
            raw = fetch(db, url, "upstream")
            doc = json.loads(raw)
            meta = doc["cveMetadata"]
            refs = [
                r.get("url", "")
                for c in [
                    doc.get("containers", {}).get("cna", {}),
                    *doc.get("containers", {}).get("adp", []),
                ]
                for r in c.get("references", [])
            ]
            with db:
                ev = evidence(db, raw, url)
                db.execute(
                    "INSERT OR REPLACE INTO vulnerabilities VALUES(?,?,?,?,?)",
                    (cid, meta.get("datePublished"), meta.get("dateUpdated"), url, ev["id"]),
                )
                for plugin in default_registry().all():
                    vendor = plugin.id
                    matches = [
                        canonical(u, vendor)
                        for u in refs
                        if allowed(u, vendor) and plugin.reference_filter(u)
                    ]
                    # Exclude protection signatures and general library URLs as product claims.
                    matches = [
                        u for u in matches if urlsplit(u).hostname != "advisories.checkpoint.com"
                    ]
                    for u in matches:
                        targets[(vendor, u)] = True
                    db.execute(
                        "INSERT OR REPLACE INTO coverage_checks VALUES(?,?,?,?,?,?,?)",
                        (
                            vendor,
                            cid,
                            now(),
                            url,
                            "Vendor URLs in upstream CVE CNA/ADP references; not a vendor portfolio search",
                            "match" if matches else "no_match",
                            ev["id"],
                        ),
                    )
            print("UPSTREAM", cid, len(refs), "references", flush=True)
        except Exception as e:
            failures += 1
            collection_result(db, "upstream", url, "error", str(e), failure_code(e))
            print("ERROR", cid, str(e), flush=True)
    # Official index filenames are not CVE-searchable; inspect each document within
    # a declared cap and preserve the inspected count so a partial scan is explicit.
    for feed in load_config()["vendors"]:
        if feed["kind"] != "index":
            continue
        url = feed["url"]
        vendor = feed["vendor"]
        try:
            from urllib.parse import urljoin

            raw = fetch(db, url, vendor)
            urls = [
                urljoin(url, line.strip())
                for line in raw.decode().splitlines()
                if line.strip().endswith(".json")
            ]
            inspected = 0
            found = set()
            errors = 0
            for source in urls[:aruba_limit]:
                try:
                    body = fetch(db, source, vendor)
                    parsed = json.loads(body)
                    ids = {
                        v.get("cve", "").upper() for v in parsed.get("vulnerabilities", [])
                    } & set(COHORT)
                    inspected += 1
                    found |= ids
                    if ids:
                        imported += ingest(db, body, source, auto, vendor)
                        collection_result(
                            db,
                            vendor,
                            source,
                            "ok",
                            "Benchmark CVE match in official CSAF index scan",
                        )
                        print(vendor.upper() + " MATCH", ",".join(sorted(ids)), source, flush=True)
                except Exception as e:
                    errors += 1
                    failures += 1
                    collection_result(db, vendor, source, "error", str(e), failure_code(e))
            with db:
                ev = evidence(db, raw, url)
                for cid in COHORT:
                    db.execute(
                        "INSERT OR REPLACE INTO coverage_checks VALUES(?,?,?,?,?,?,?)",
                        (
                            vendor,
                            cid,
                            now(),
                            url,
                            f"Inspected {inspected} of {len(urls)} listed CSAF documents, cap {aruba_limit}; {errors} errors; index snapshot as observed",
                            "match"
                            if cid in found
                            else "no_match"
                            if inspected == len(urls) and not errors
                            else "partial_no_match",
                            ev["id"],
                        ),
                    )
            print(vendor.upper() + " SCAN", inspected, "/", len(urls), "errors", errors, flush=True)
        except Exception as e:
            failures += 1
            collection_result(db, vendor, url, "error", str(e), failure_code(e))
            print(vendor.upper() + " ERROR", str(e), flush=True)
    # Explicit curated historical cases supplement current feed windows.
    for vendor, url in list(targets)[:60]:
        try:
            resolved, raw = resolve_document(db, url, vendor)
            imported += ingest(db, raw, resolved, auto, vendor)
            collection_result(db, vendor, url, "ok", "Benchmark reference document imported")
            print("IMPORTED", vendor, resolved, flush=True)
        except Exception as e:
            failures += 1
            collection_result(db, vendor, url, "error", str(e), failure_code(e))
            print("ERROR", vendor, url, str(e), flush=True)
    with db:
        result = coverage(db, latest(db))
    (Paths.from_env().home / "benchmark").mkdir(parents=True, exist_ok=True)
    (Paths.from_env().home / "benchmark/cohort-coverage.json").write_text(
        json.dumps({"generated_at": now(), "cohort": COHORT, "pairs": result}, indent=2) + "\n"
    )
    db.close()
    return imported, failures
