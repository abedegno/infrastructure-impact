-- Every discovery occurrence can refer to multiple document representations.
CREATE TABLE switching_backfill_documents (
  run_id TEXT NOT NULL,
  identity TEXT NOT NULL,
  item_id INTEGER NOT NULL REFERENCES archive_items(id),
  PRIMARY KEY(run_id,identity,item_id),
  FOREIGN KEY(run_id,identity) REFERENCES switching_backfill_entries(run_id,identity)
);
-- Adopt original pointers, including retained/exhausted documents.
INSERT OR IGNORE INTO switching_backfill_documents
SELECT run_id,identity,item_id FROM switching_backfill_entries WHERE item_id IS NOT NULL;
-- Repair already retained duplicate observations, including previously orphaned
-- items and alternate locators which were retained but not yet queued.
INSERT OR IGNORE INTO archive_items(source_id,kind,url,discovered_at)
SELECT b.source_id,'document',j.value,b.started_at
FROM switching_backfill_observations o
JOIN switching_backfills b ON b.id=o.run_id
JOIN json_each(o.alternate_urls) j
WHERE b.source_id IS NOT NULL AND j.type='text';
INSERT OR IGNORE INTO switching_backfill_documents
SELECT o.run_id,o.identity,i.id
FROM switching_backfill_observations o
JOIN switching_backfills b ON b.id=o.run_id
JOIN json_each(o.alternate_urls) j
JOIN archive_items i ON i.source_id=b.source_id AND i.kind='document' AND i.url=j.value;
INSERT OR IGNORE INTO archive_links
SELECT i.id,o.evidence_id
FROM switching_backfill_observations o
JOIN switching_backfills b ON b.id=o.run_id
JOIN json_each(o.alternate_urls) j
JOIN archive_items i ON i.source_id=b.source_id AND i.kind='document' AND i.url=j.value;
