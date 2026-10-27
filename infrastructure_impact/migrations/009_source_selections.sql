CREATE TABLE source_selections (
  id INTEGER PRIMARY KEY,
  vendor TEXT NOT NULL,
  requested_url TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  reason TEXT NOT NULL,
  selected_evidence_id INTEGER NOT NULL REFERENCES evidence(id)
);
CREATE TABLE source_selection_views (
  id INTEGER PRIMARY KEY,
  selection_id INTEGER NOT NULL REFERENCES source_selections(id),
  evidence_id INTEGER NOT NULL REFERENCES evidence(id),
  source_format TEXT NOT NULL,
  adapter_version TEXT NOT NULL,
  assessments INTEGER NOT NULL CHECK (assessments >= 0),
  UNIQUE(selection_id, evidence_id)
);
CREATE INDEX source_selection_lookup ON source_selections(vendor, requested_url, id);
CREATE TABLE source_selection_issues (
  id INTEGER PRIMARY KEY,
  selection_id INTEGER NOT NULL REFERENCES source_selections(id),
  source_url TEXT NOT NULL,
  error_code TEXT NOT NULL,
  UNIQUE(selection_id, source_url)
);
