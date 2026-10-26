CREATE TABLE source_observations (
  id INTEGER PRIMARY KEY,
  vendor TEXT NOT NULL,
  source_url TEXT NOT NULL,
  checked_at TEXT NOT NULL,
  evidence_id INTEGER NOT NULL REFERENCES evidence(id),
  http_status INTEGER NOT NULL CHECK ((http_status BETWEEN 200 AND 299) OR http_status = 304)
);
CREATE INDEX source_observation_lookup ON source_observations(vendor, source_url, id);
