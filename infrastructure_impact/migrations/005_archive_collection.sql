CREATE TABLE archive_sources (
  id INTEGER PRIMARY KEY,
  vendor TEXT NOT NULL,
  source_url TEXT NOT NULL,
  kind TEXT NOT NULL,
  started_at TEXT NOT NULL,
  checked_at TEXT,
  UNIQUE(vendor, source_url, kind)
);
CREATE TABLE archive_items (
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES archive_sources(id),
  kind TEXT NOT NULL CHECK(kind IN ('page','document')),
  url TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','done','not_applicable','error')),
  discovered_at TEXT NOT NULL,
  checked_at TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  retry_after TEXT,
  evidence_id INTEGER REFERENCES evidence(id),
  resolved_url TEXT,
  entry_count INTEGER,
  missing_links INTEGER NOT NULL DEFAULT 0,
  rejected_links INTEGER NOT NULL DEFAULT 0,
  error_code TEXT,
  UNIQUE(source_id, kind, url)
);
CREATE INDEX archive_queue ON archive_items(source_id,kind,state,retry_after);
CREATE TABLE archive_links (
  item_id INTEGER NOT NULL REFERENCES archive_items(id),
  page_evidence_id INTEGER NOT NULL REFERENCES evidence(id),
  PRIMARY KEY(item_id,page_evidence_id)
);
