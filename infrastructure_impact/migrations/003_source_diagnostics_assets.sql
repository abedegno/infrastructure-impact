ALTER TABLE collection_runs ADD COLUMN error_code TEXT;
CREATE TABLE IF NOT EXISTS release_assets (
  id INTEGER PRIMARY KEY,
  evidence_id INTEGER NOT NULL REFERENCES evidence(id),
  vendor TEXT NOT NULL, source_url TEXT NOT NULL, published_at TEXT NOT NULL,
  normalized TEXT NOT NULL,
  UNIQUE(evidence_id, vendor, source_url, normalized)
);
CREATE TABLE IF NOT EXISTS release_asset_observations (
  id INTEGER PRIMARY KEY, release_asset_id INTEGER NOT NULL REFERENCES release_assets(id),
  observed_at TEXT NOT NULL
);
