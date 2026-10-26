CREATE TABLE browser_captures (
  id INTEGER PRIMARY KEY,
  evidence_id INTEGER NOT NULL REFERENCES evidence(id),
  vendor TEXT NOT NULL,
  source_url TEXT NOT NULL,
  captured_at TEXT NOT NULL,
  imported_at TEXT NOT NULL,
  adapter_version TEXT NOT NULL,
  expected_version TEXT NOT NULL,
  normalized TEXT NOT NULL,
  UNIQUE(evidence_id, adapter_version, expected_version)
);
