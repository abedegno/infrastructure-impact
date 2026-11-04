-- Operational state only: never authentication material or API response blobs.
CREATE TABLE switching_requests (
  id INTEGER PRIMARY KEY,
  service TEXT NOT NULL CHECK (service = 'cisco_openvuln'),
  reserved_at REAL NOT NULL
);
CREATE INDEX switching_requests_window ON switching_requests(service, reserved_at);
CREATE TABLE switching_service_state (
  service TEXT PRIMARY KEY CHECK (service = 'cisco_openvuln'),
  cooldown_until REAL NOT NULL DEFAULT 0,
  failures INTEGER NOT NULL DEFAULT 0 CHECK (failures >= 0)
);
CREATE TABLE switching_cursors (
  service TEXT NOT NULL CHECK (service = 'cisco_openvuln'),
  window_start TEXT NOT NULL,
  window_end TEXT NOT NULL,
  definition_fingerprint TEXT NOT NULL DEFAULT '',
  page_index INTEGER NOT NULL CHECK (page_index BETWEEN 1 AND 100),
  PRIMARY KEY(service, window_start, window_end, definition_fingerprint)
);
