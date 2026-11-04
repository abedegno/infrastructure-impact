-- A committed marker predates network I/O. Unknown completion never expires.
-- Never reuse a completion ID after pruning; a delayed old process must not
-- resolve a newer request. Adopt existing quota rows within the migration txn.
CREATE TABLE switching_requests_pending_upgrade (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  service TEXT NOT NULL CHECK (service = 'cisco_openvuln'),
  reserved_at REAL NOT NULL,
  pending INTEGER NOT NULL DEFAULT 0 CHECK (pending IN (0,1))
);
INSERT INTO switching_requests_pending_upgrade(id,service,reserved_at)
  SELECT id,service,reserved_at FROM switching_requests;
DROP TABLE switching_requests;
ALTER TABLE switching_requests_pending_upgrade RENAME TO switching_requests;
CREATE INDEX switching_requests_window ON switching_requests(service, reserved_at);
CREATE INDEX switching_requests_pending ON switching_requests(service, pending);
