"""Evidence-preserving vendor impact importer. Python 3.11+, no dependencies."""
import argparse
import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB = Path(__file__).parent / "data/impact.sqlite3"


def connect(path=DEFAULT_DB):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY, source_url TEXT NOT NULL,
            sha256 TEXT NOT NULL, observed_at TEXT NOT NULL,
            raw_json TEXT NOT NULL, UNIQUE(source_url, sha256)
        );
        CREATE TABLE IF NOT EXISTS assessments (
            snapshot_id INTEGER PRIMARY KEY REFERENCES snapshots(id),
            cve_id TEXT NOT NULL, vendor TEXT NOT NULL, normalized_json TEXT NOT NULL
        );
    """)
    return db


def normalize(record, source_url, observed_at):
    """Retain vendor version expressions; never infer release availability."""
    cna = record["containers"]["cna"]
    products = []
    for item in cna.get("affected", []):
        versions = item.get("versions", [])
        statuses = {v.get("status", "unknown") for v in versions}
        # Explicit version statements take precedence over contradictory defaults.
        status = next(iter(statuses)) if len(statuses) == 1 else "mixed" if statuses else "unknown"
        products.append({
            "vendor": item["vendor"], "product": item["product"].strip(),
            "status": status, "versions": versions,
            "default_status": item.get("defaultStatus", "unknown"),
            "patch_availability": "not_evaluated",
        })
    metrics = []
    for metric in cna.get("metrics", []):
        for key, score in metric.items():
            if key.startswith("cvssV"):
                metrics.append({"score": score.get("baseScore"),
                                "severity": score.get("baseSeverity"),
                                "version": score.get("version"),
                                "vector": score.get("vectorString"),
                                "scenarios": metric.get("scenarios", [])})
    timeline = cna.get("timeline", [])
    return {
        "cve_id": record["cveMetadata"]["cveId"],
        "title": cna.get("title", "").strip(),
        "related_cves": sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", cna.get("title", "")))),
        "vendor": ", ".join(sorted({p["vendor"] for p in products})),
        "published_at": cna.get("datePublic"),
        "updated_at": max((t["time"] for t in timeline), default=cna.get("datePublic")),
        "observed_at": observed_at, "source_url": source_url,
        "products": products, "metrics": metrics, "timeline": timeline,
        **{key: cna.get(key, []) for key in ("descriptions", "solutions", "workarounds", "exploits", "references")},
    }


def ingest(db, raw, source_url):
    record = json.loads(raw)
    observed = datetime.now(timezone.utc).isoformat()
    normalized = normalize(record, source_url, observed)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    with db:
        cursor = db.execute("INSERT OR IGNORE INTO snapshots(source_url,sha256,observed_at,raw_json) VALUES(?,?,?,?)",
                            (source_url, digest, observed, raw))
        if not cursor.rowcount:
            return False
        db.execute("INSERT INTO assessments VALUES(?,?,?,?)", (cursor.lastrowid, normalized["cve_id"],
                   normalized["vendor"], json.dumps(normalized)))
    return True


def latest(db):
    rows = db.execute("""SELECT a.normalized_json, s.sha256 FROM assessments a
        JOIN snapshots s ON s.id=a.snapshot_id WHERE a.snapshot_id IN
        (SELECT MAX(snapshot_id) FROM assessments GROUP BY cve_id, vendor)
        ORDER BY a.snapshot_id DESC""")
    return [{**json.loads(r["normalized_json"]), "sha256": r["sha256"]} for r in rows]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--source", required=True, help="Canonical vendor JSON URL")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    args = parser.parse_args()
    with connect(args.db) as database:
        added = ingest(database, args.file.read_text(), args.source)
    print("Imported new snapshot" if added else "Snapshot already imported")
