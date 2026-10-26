CREATE TABLE reference_documents (
  id INTEGER PRIMARY KEY,
  source_id TEXT NOT NULL,
  source_url TEXT NOT NULL,
  evidence_id INTEGER NOT NULL REFERENCES evidence(id),
  observed_at TEXT NOT NULL,
  normalized TEXT NOT NULL
);
CREATE INDEX reference_document_lookup ON reference_documents(source_id, id);
