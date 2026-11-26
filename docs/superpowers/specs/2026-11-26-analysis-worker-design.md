# Responsive precomputed analysis delivery

## Intent and authority

User approved moving decoding/validation into a Web Worker, reducing copies and
export allocations, repeating browser checks, then certifying eight-view and
retained-history size. Standing opt-out permits implementation without another
design/permission loop; existing subagent-driven preference persists. This is a
continuation of disabled PR91 on its existing isolated branch. No hosted
activation or merge is authorized by this milestone.

## Approach

Use a dedicated, same-origin classic worker built from the existing exact JSON,
contract, switching, KEV, customer-comparison, analysis and selected validators.
The writer assembles a standalone immutable fingerprinted worker asset; no blob,
data URL, dynamic third-party import, new dependency or CSP relaxation. A small
client script captures its worker URL from its immutable script element metadata.

Alternatives considered: yielding around synchronous validation cannot interrupt
the expensive parser/checks; returning large raw JSON for main-thread reparse
moves the freeze instead of removing it. SharedArrayBuffer introduces isolation
requirements. None is necessary. Worker use and byte-transfer exports are the
controller's implementation choices, under the user's approved worker direction.

The existing v2 raw loader remains the only physical-part fetch owner: cache,
six-request pool, hashes, wire caps and cancellation stay enforced. Copy at most
one bounded physical chunk before transferring so the raw LRU is never detached.
Parse, normalize, validate and retain the prepared view in the worker. Do not
repeat full selected validation on the main thread. Each result is a fresh
structured clone delivered from the trusted worker, preserving BigInt, ordering,
mutable-result independence and complete JSON/CSV bytes.

Retain at most one prepared selection per reader; concurrent callers, queued
views and exports must pin their owning view until their delivery completes.
Eviction cannot invalidate an already accepted read or export. Shared preparation
must survive one caller's cancellation/cap failure, stop when its last interested
caller departs, and recover cleanly after worker error or termination. Serialize
cold preparations, reject stale/foreign replies, and bound all outstanding RPCs
by existing operation deadlines. Workers must have explicit disposal/idle cleanup
and must not accumulate across application publication changes.

Add an asynchronous selected-export method on the reader, taking accepted study,
format json/csv/upgrades-csv and existing consumption options. It exports the
source-owned selected value in the worker and transfers encoded bytes. The UI
uses it for eligible views, pins the clicked accepted study/publication through
the await, and retains the existing export fallback for other views. Errors are
visible and no corrupt advertised view silently falls back. No arbitrary function,
URL or executable content crosses the worker protocol.

Change analysis CSV row assembly to a generator consumed by the existing bounded
CSV encoder. Keep serialization, field order, escaping, precision and byte caps
exactly the same. Do not memoize giant serialized downloads or retain both worker
and main prepared copies. Caller-owned results may still be large; report memory
honestly rather than claim a total-memory bound from wire byte caps.

## Compatibility and limits

No scientific, advisory schema, source membership, native wire/format, inference,
dependency, budget, schedule, permissions, secrets or hosted activation changes.
Use public cached/synthetic inputs only; no .env, private artifacts or vendor
contact. PR90 stays unmerged. Physical parts stay <=8,000,000 bytes; selected and
export bytes <=128,000,000; raw cache <=16,000,000; site <=1,000,000,000. Existing
per-caller smaller limits, cancellation, deadlines and reliable retry apply.
Worker/gzip unsupported environments keep the existing documented behavior;
configured worker startup/runtime or corrupt advertised-data failure is explicit.
Unmatched custom/model/CVE selections retain the compiled reader.

## Evidence and acceptance

RED/GREEN tests must use real worker_threads behind a Web Worker shim as well as
focused protocol faults. Pin independent results, caller caps, definition checks,
large exact IDs, fractional CVSS, invalid wire/data, shared cancellation, eviction
races, raw-cache non-detachment, worker startup/runtime failure, retry, nested base
paths, immutable asset binding and all three export bytes. Integrate through pytest.

Real-browser gate: same pinned generation and four contexts, actual Cisco/2025
Load/Refresh and export actions, observer long tasks/heartbeat, response bytes,
heap samples and exact four-view JSON/twoCSV hashes. Distinguish structured-clone
and DOM costs from worker compute. No claim of low-memory/browser-wide guarantee
without evidence. A useful early real-browser gate precedes expensive full native
publication.

After a useful gate, generate one full eight-view preview from cached public
projection through existing fresh authority and independent native regeneration,
without changing budgets. Inventory all regular files, archive references and
shared members. Inspect accepted hosted artifact inventory only if available
without vendor download or credentials beyond existing GitHub auth; otherwise
mark aggregate historical capacity unknown. Preserve caveats and review-pending
status. Publish reviewable commits/updated draftPR91, not hosted activation.
