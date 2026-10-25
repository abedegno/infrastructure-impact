
      PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY, source_url TEXT NOT NULL, sha256 TEXT NOT NULL,
        observed_at TEXT NOT NULL, raw BLOB NOT NULL, media_type TEXT,
        UNIQUE(source_url, sha256));
      CREATE TABLE IF NOT EXISTS revisions (
        id INTEGER PRIMARY KEY, evidence_id INTEGER NOT NULL REFERENCES evidence(id),
        vendor TEXT NOT NULL, advisory_id TEXT NOT NULL, source_url TEXT NOT NULL,
        observed_at TEXT NOT NULL, normalized TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS revision_lookup ON revisions(vendor, advisory_id, id);
      CREATE TABLE IF NOT EXISTS changes (
        id INTEGER PRIMARY KEY, revision_id INTEGER REFERENCES revisions(id),
        observed_at TEXT NOT NULL, vendor TEXT NOT NULL, advisory_id TEXT NOT NULL,
        kind TEXT NOT NULL, details TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS collection_runs (
        id INTEGER PRIMARY KEY, vendor TEXT NOT NULL, source_url TEXT NOT NULL,
        checked_at TEXT NOT NULL, outcome TEXT NOT NULL, details TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY, evidence_id INTEGER NOT NULL REFERENCES evidence(id),
        vendor TEXT NOT NULL, product TEXT NOT NULL, document_type TEXT NOT NULL,
        published_at TEXT, source_url TEXT NOT NULL, text TEXT NOT NULL,
        UNIQUE(evidence_id, vendor, product, document_type));
      CREATE TABLE IF NOT EXISTS vulnerabilities (
        cve_id TEXT PRIMARY KEY, published_at TEXT, updated_at TEXT,
        source_url TEXT NOT NULL, evidence_id INTEGER REFERENCES evidence(id));
    
CREATE TABLE IF NOT EXISTS http_cache(url TEXT PRIMARY KEY,etag TEXT,modified TEXT,evidence_id INTEGER REFERENCES evidence(id));
CREATE TABLE IF NOT EXISTS coverage_checks(vendor TEXT,cve_id TEXT,checked_at TEXT,source_url TEXT,scope TEXT,outcome TEXT,evidence_id INTEGER,PRIMARY KEY(vendor,cve_id,source_url));
CREATE TABLE IF NOT EXISTS fix_evidence(id INTEGER PRIMARY KEY,vendor TEXT,product TEXT,cve_id TEXT,version TEXT,released_at TEXT,release_evidence_id INTEGER REFERENCES evidence(id),link_evidence_id INTEGER REFERENCES evidence(id),basis TEXT,review_status TEXT DEFAULT 'unreviewed');
CREATE TABLE IF NOT EXISTS pipeline_runs(id INTEGER PRIMARY KEY,started_at TEXT NOT NULL,finished_at TEXT,outcome TEXT NOT NULL,imported INTEGER DEFAULT 0,failures INTEGER DEFAULT 0,details TEXT);
CREATE TABLE IF NOT EXISTS research_reviews(id INTEGER PRIMARY KEY,fix_id INTEGER,note TEXT,status TEXT,reviewed_at TEXT);
CREATE TABLE IF NOT EXISTS correction_proposals(id INTEGER PRIMARY KEY,sha256 TEXT UNIQUE,received_at TEXT,proposal TEXT,review_status TEXT DEFAULT 'pending');
