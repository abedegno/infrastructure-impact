-- Raw evidence persistence is not proof that a transport call completed.
-- A generation-bound acknowledgement is committed only after get_json returns.
ALTER TABLE cisco_first_fixed_queries ADD COLUMN attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0);
ALTER TABLE cisco_first_fixed_queries ADD COLUMN response_attempt INTEGER;
ALTER TABLE cisco_first_fixed_queries ADD COLUMN response_evidence_id INTEGER REFERENCES evidence(id);
ALTER TABLE cisco_first_fixed_queries ADD COLUMN response_acknowledged_at TEXT;
-- Pre-receipt successes cannot establish which attempt completed. Fail closed;
-- preserve the evidence/result for operational inspection, never invent an ack.
UPDATE cisco_first_fixed_queries
SET state='pending',started=1,error_code='request_state_unresolved'
WHERE state='success';
