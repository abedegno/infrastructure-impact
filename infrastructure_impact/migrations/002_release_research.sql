CREATE TABLE IF NOT EXISTS document_changes (
  id INTEGER PRIMARY KEY, document_id INTEGER NOT NULL REFERENCES documents(id),
  previous_document_id INTEGER NOT NULL REFERENCES documents(id),
  observed_at TEXT NOT NULL, cves_added TEXT NOT NULL, cves_removed TEXT NOT NULL,
  security_language_added INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS release_observations (
  id INTEGER PRIMARY KEY, evidence_id INTEGER NOT NULL REFERENCES evidence(id),
  vendor TEXT NOT NULL, product TEXT NOT NULL, version TEXT NOT NULL,
  released_at TEXT NOT NULL, observation_type TEXT NOT NULL,
  locator TEXT NOT NULL, recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fix_review_checks (
  id INTEGER PRIMARY KEY, fix_id INTEGER NOT NULL REFERENCES fix_evidence(id),
  observation_id INTEGER NOT NULL REFERENCES release_observations(id),
  earlier_disclosure_search TEXT NOT NULL, reviewer_note TEXT NOT NULL,
  reviewed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS document_observations (
  id INTEGER PRIMARY KEY, document_id INTEGER NOT NULL REFERENCES documents(id),
  observed_at TEXT NOT NULL
);
