-- Study/window metadata references the existing additive archive queue.
CREATE TABLE switching_backfills (
  id TEXT PRIMARY KEY,
  study_id TEXT NOT NULL,
  definition_sha256 TEXT NOT NULL,
  vendor TEXT NOT NULL,
  source_id INTEGER REFERENCES archive_sources(id),
  source_url TEXT,
  kind TEXT,
  start_date TEXT NOT NULL,
  end_date TEXT NOT NULL,
  enumeration_revision TEXT NOT NULL,
  next_page INTEGER NOT NULL DEFAULT 1,
  enumerated INTEGER NOT NULL DEFAULT 0,
  unstable INTEGER NOT NULL DEFAULT 0,
  expected_total INTEGER,
  duplicate_entries INTEGER NOT NULL DEFAULT 0,
  error_code TEXT,
  retry_at TEXT,
  started_at TEXT NOT NULL,
  checked_at TEXT NOT NULL
);
CREATE TABLE switching_backfill_pages (
  run_id TEXT NOT NULL REFERENCES switching_backfills(id),
  item_id INTEGER NOT NULL REFERENCES archive_items(id),
  ordinal INTEGER NOT NULL,
  evidence_id INTEGER REFERENCES evidence(id),
  PRIMARY KEY(run_id,item_id)
);
CREATE TABLE switching_backfill_entries (
  run_id TEXT NOT NULL REFERENCES switching_backfills(id),
  identity TEXT NOT NULL,
  item_id INTEGER REFERENCES archive_items(id),
  evidence_id INTEGER NOT NULL REFERENCES evidence(id),
  source_locator TEXT NOT NULL,
  published_at TEXT,
  publisher_status TEXT,
  publisher_revision TEXT,
  alternate_urls TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY(run_id,identity)
);
CREATE TABLE switching_backfill_issues (
  run_id TEXT NOT NULL REFERENCES switching_backfills(id),
  code TEXT NOT NULL,
  PRIMARY KEY(run_id,code)
);
CREATE INDEX switching_backfill_study ON switching_backfills(study_id,started_at);
-- Every occurrence survives identity deduplication, including revisions/withdrawals.
CREATE TABLE switching_backfill_observations (
  run_id TEXT NOT NULL REFERENCES switching_backfills(id),
  identity TEXT NOT NULL,
  evidence_id INTEGER NOT NULL REFERENCES evidence(id),
  source_locator TEXT NOT NULL,
  published_at TEXT,
  publisher_status TEXT,
  publisher_revision TEXT,
  alternate_urls TEXT NOT NULL,
  PRIMARY KEY(run_id,identity,evidence_id,source_locator)
);
