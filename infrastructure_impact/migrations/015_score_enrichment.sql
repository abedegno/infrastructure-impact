CREATE TABLE score_documents (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL CHECK(source IN ('cve_record','nvd')),
    cve_id TEXT NOT NULL,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id),
    checked_at TEXT NOT NULL,
    normalized TEXT NOT NULL
);
CREATE INDEX score_document_identity ON score_documents(source,cve_id,id);
CREATE TABLE score_attempts (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL CHECK(source IN ('cve_record','nvd')),
    cve_id TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    state TEXT NOT NULL,
    retry_at TEXT
);
CREATE TABLE score_service_state (
    source TEXT PRIMARY KEY CHECK(source IN ('cve_record','nvd')),
    next_at REAL NOT NULL DEFAULT 0,
    failures INTEGER NOT NULL DEFAULT 0,
    pending INTEGER NOT NULL DEFAULT 0
);
-- Successful parsed API listing representations; no invented HTTP status/history.
CREATE TABLE score_vendor_observations (
    id INTEGER PRIMARY KEY,
    source_url TEXT NOT NULL,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id),
    observed_at TEXT NOT NULL
);
CREATE INDEX score_vendor_source ON score_vendor_observations(source_url,id);
