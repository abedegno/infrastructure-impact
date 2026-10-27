ALTER TABLE archive_items ADD COLUMN parser_version TEXT;
CREATE TABLE archive_parser_replays (
  id INTEGER PRIMARY KEY,
  item_id INTEGER NOT NULL REFERENCES archive_items(id),
  parser_version TEXT NOT NULL,
  checked_at TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('recovered','not_applicable','still_unsupported','not_retained')),
  evidence_id INTEGER REFERENCES evidence(id),
  error_code TEXT,
  alternate_issues INTEGER NOT NULL DEFAULT 0 CHECK (alternate_issues BETWEEN 0 AND 4),
  UNIQUE(item_id, parser_version)
);
CREATE INDEX archive_parser_replay_lookup ON archive_parser_replays(item_id, id);
