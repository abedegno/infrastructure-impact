-- Explicit local enrichment only; no credentials or copied response bodies.
CREATE TABLE cisco_first_fixed_queries (
  url TEXT PRIMARY KEY,
  os_type TEXT NOT NULL CHECK (os_type = 'iosxe'),
  query_release TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','success','deferred','error','auth_not_configured')),
  started INTEGER NOT NULL DEFAULT 0 CHECK (started IN (0,1)),
  error_code TEXT,
  retry_at TEXT,
  evidence_id INTEGER REFERENCES evidence(id),
  parser_revision TEXT,
  result_json TEXT,
  UNIQUE(os_type,query_release)
);
