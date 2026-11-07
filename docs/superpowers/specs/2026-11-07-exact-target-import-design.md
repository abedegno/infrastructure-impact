# Bounded Cisco/Aruba target import design

Date: 2026-11-07. Status: design for approval; product implementation and hosted
activation have not started.

## Intent and approved direction

Close the specific public Cisco and Aruba evidence gaps established by the
[174-target proposal](../../research/2026-11-07-coverage-publication-proposal.md).
The user selected proceeding with a bounded one-off importer. The result must
preserve raw evidence, vendor/CVE/version/configuration boundaries, revision
identity, source disagreements, frozen studies and pending human review.

The selected population is 173 Cisco documents and one Aruba bulletin, not a
complete history or a list of 174 advisories affecting campus switches. Expected
membership improvements remain IOS XE vendor 0→201 and family 0→200; AOS-CX
67→70 for both. EOS is unchanged. These are candidate-presence projections,
including all statuses, not exposure, patch burden or a security ranking.

## Approaches

The preceding proposal considered:

1. **Bounded one-off import — selected direction.** An installed reviewed manifest,
   an inventory-bound preview, explicit staging and separately approved hosted
   apply. It costs more implementation work but avoids recurring historical
   fetches and preserves real hosted IDs and provenance.
2. Permanent source pins — rejected: the scheduled collector would repeatedly
   fetch 174 old targets and require a second configuration change to stop.
3. Transplanting normalized rows or a research database — rejected: local IDs,
   unrelated inputs and capture/observation history are not hosted identities.

The design below is the proposed implementation of option 1. Engineering choices
are proposals by the implementer, not additional user decisions already made.

## Existing boundaries

`collection/maintenance_profiles.py` installs one Arista-only cleanup profile.
`application/maintenance.py` binds a read-only checkpoint inventory and validates
that specific conflict proof. `ops/hosted_job.py` supports authenticated restore,
explicit preview/apply, shared writer exclusion, verified recovery and separate
Pages effects. Existing workflow inputs already select profile/mode/fingerprint.
Preview grants only `preview_ready`; successful apply requires both recovery and
publication readiness. None of those Arista semantics may be silently generalized.

`collection/transport.py` normally allows reviewed vendor-domain redirects,
15 MB documents, a 25-second transport timeout and two attempts. The new batch
needs stricter per-operation bounds, with existing callers' defaults unchanged.
Normalization and schema validation remain in the installed vendor registry.

## Capacity discovery changes the release gate

The 174 retained documents total 32,176,699 raw bytes; the largest is 2,734,353
bytes. Their retained normalized JSON is approximately 77.38 MB when serialized
compactly, of which about 75.51 MB is assessments. This measurement concerns
normalized records, not a complete public projection under current code.

The current full snapshot is 64,021,028 bytes. Straight addition of those record
payloads suggests a snapshot around 141 MB, before new derived outputs, beyond
the existing monitor's 128,000,000-byte expanded-archive limit. This is a capacity
warning, **not a measured complete candidate**: public projection may change
payloads and derived views. Do not claim the batch fits based on compression or
membership arithmetic.

The importer must build and measure a complete candidate before any recovery
promotion or public readiness. Failure must leave the accepted recovery vault
unchanged, so the next scheduled ordinary run is not forced to consume an
oversized imported vault. No monitor/transport/delivery budgets are raised. If the
full candidate fails, publication-size work needs its own reviewed design; this
milestone can deliver a tested importer and a failing capacity receipt, but must
not call the coverage gap closed. No selective evidence removal or narrower
unannounced study is an acceptable shortcut.

## Closed manifest

Add a versioned installed resource and registry, separate from the Arista profile,
initially containing exactly `campus-switching-public-gap-2026-11-07-v1`.

Each of the 174 entries contains vendor, stable advisory ID, exact expected CVE
set, reviewed resolved fetch URL, expected source SHA-256 and original discovery
URL as provenance. The historical observation date is evidence metadata only.
No body, local path, credentials, customer data or database ID is installed.
Manifest ordering is canonical. Its SHA-256 covers every entry and all limits.

Fetch the reviewed resolved documents directly: 173 Cisco CSAF JSON documents and
one Aruba text bulletin. Original article URLs are discovery provenance, not new
fetch targets or proof of a current HTML/CSAF comparison. The importer must not
create a source-selection comparison it did not perform. All URLs still pass the
installed vendor policy. No arbitrary operator-supplied URL manifest, discovery,
feed enumeration, reference crawling, OAuth, CVE API or KEV acquisition is added.
Unknown profile names fail before database or key access.

This first manifest deliberately pins **exact source bytes**, stable identity and
CVE scope. A changed live SHA, additional CVE, missing CVE, foreign identity or
unsupported layout fails visibly. Even an apparently harmless publisher edit
requires a separately reviewed manifest version; neither preview nor apply
rewrites expected values from live content. Normalizer fingerprints are also
bound to the accepted preview. Future less restrictive policies are out of scope.

## Operations and data ownership

### Local preview

Proposed CLI: `impact target-import preview --database PATH --profile ID --output FILE`.

Use a stable checkpoint copy without opening the source SQLite file, following
the existing stat/journal-before-and-after copy pattern. Reject nonempty WAL or
rollback journals and concurrent changes. Open only the disposable copy read-only.
Preview performs no HTTP, migrations, input writes, writer lock, recovery or
publication. Output must be a new safe destination outside the input/sidecars.

The strict bounded receipt includes a distinct format discriminator, profile and
manifest identity, both installed normalizer identities, and a logical binding of
the complete latest advisory inventory/payloads, source-selection facts relevant
to the targets and latest target HTTP observation/cache facts. Binding must not
omit other-vendor changes that could affect a complete candidate. Use shared
canonical identity primitives; do not include source bodies or private text.
Unknown target identities are expected additions, not preview failure.

The preview is a consistency receipt, not cryptographic authorization or a
single-use secret. A different accepted inventory, target observation/selection,
manifest or normalizer requires another preview. Preview observation time is not
part of the fingerprint. Successful import changes the bound state; a failed
isolated stage need not change it. Operators must not automatically retry apply.

### Local stage

Proposed CLI: `impact target-import stage --home LOCK_HOME --database PATH --profile ID --preview FILE --output DIRECTORY`.

`--home` explicitly identifies the collector lock namespace. Reject ambiguous or
incompatible database/lock ownership before opening the input; no root/native
source configuration is read. The implementation may settle the precise path
validation rule, but it must demonstrably use the same lock as collection for the
explicitly selected vault, with tests for custom database paths. The caller owns
one lock; core routines do not nest it.

Validate manifest, receipt, paths and exact expected fingerprint before HTTP.
Under the shared lock, take a stable checkpoint copy and recompute the binding.
All mutations occur in a new isolated operator stage. The input vault remains
unchanged on both success and failure. Never copy local research IDs into it.
Keep private staged database/captures separate from sanitized public candidate
files; the whole stage directory is never a publication root.

Fetch every target under the bounds below, verify exact raw SHA, normalize using
the vendor registry and validate schema, vendor, identity and exact CVE set.
Preflight every target before adding normalized revisions. Existing transport may
retain bytes/HTTP observations in the **isolated stage** during preflight; that
does not authorize source health or record changes in the accepted input vault.

After successful preflight, ingest using existing evidence/revision functions.
Repeated identical evidence under identical code must not create duplicate
normalization revisions. Preserve original bytes, actual fresh retrieval/check
metadata and historical publisher dates. Do not manufacture a new publisher
security alert from an old disclosure. No current or excluded record may be
removed by this additive import. Importing previously unseen IDs allocates real
stage/vault IDs, not IDs copied from the research proposal.

Create a correctly scoped pipeline record: only exact-target work was run;
benchmark/feeds/archive/CVE/KEV acquisition was not run. Do not borrow the Arista
path's unconditional `partial`/one expected conflict outcome. A new batch is
completed only if all targets validate and import or are unchanged, audit and
complete candidate checks pass, and there are no unresolved batch failures.
Old unrelated collection errors and review-pending states stay visible.

Audit the staged database, build the full existing publication, validate archive
sizes and the default monitor path, export/compare native/static content and CSV,
and check switching/current-evidence/KEV scope. Do not remove validators or widen
limits. Generate a bounded result even when capacity fails. For a failed stage,
never label the staged database accepted or provide it to ordinary recovery.
Local private failure evidence may remain at the explicit operator destination;
public artifacts must not expose captures, raw exceptions or private paths.

### Hosted preview/apply

Reuse the existing workflow's profile/mode/fingerprint inputs and `effects-v1`
contract. Extend helper dispatch through an explicit closed operation-kind
boundary. Arista still uses its current functions, receipt formats and cleanup
proofs. New target-import profiles use their own preview/stage validators. Local
`target-import stage` has no hosted effects; hosted `apply` is its controlled
recovery/publication wrapper.

Hosted preview authenticates the existing disposable recovery checkpoint and
writes only the distinct bounded receipt to the current preview artifact path.
It performs no target HTTP, backup, persistent mutation or Pages action. Hosted
apply obtains the one writer lock, rechecks the accepted inventory, then creates
the isolated stage and complete candidate. On any preflight/audit/build/capacity
failure, leave the accepted recovery pointer and vault untouched and grant
neither `recovery_ready` nor `publish_ready`. Do not reuse Arista's finally-backup
path, which is intentionally allowed to retain its failed evidence mutations.

Only after the candidate passes can the wrapper encrypt, back up and authenticate
read back the **staged** vault through the existing verified-backup helper. It
then exposes the sanitized candidate and corresponding workflow effects in the
existing order. A backup failure blocks publication. A later state-branch push or
Pages failure remains subject to the existing workflow gates and operator
investigation. Do not promise an atomic transaction across GitHub recovery and
Pages. No new GitHub permissions, schedule, secrets, repository variables, recovery
backend or source-pin change is implemented by this design.

A merge or release alone does not authorize any hosted dispatch. Actual preview,
accepted fingerprint, apply, recovery access and activation remain separately
approved operations. The current public-only proposal is not that fingerprint.

## Bounds and failure semantics

Initial installed limits, chosen from observed public inputs:

- Exactly 174 entries, 174 unique vendor/advisory identities and fetch URLs.
- At most 3,000,000 bytes per document (below the ordinary 15 MB default), at most
  40,000,000 distinct normalized-input raw bytes including cached responses.
- At most two attempts per URL and 348 HTTP request attempts per invocation.
  All redirects are refused for this profile, including redirects to another
  approved target or the same URL. Discovery URLs are not fallbacks.
- At most 80,000,000 received body bytes across attempts, including bounded error
  bodies/partial reads. Enforce the shared operation budget during chunk reads,
  not only after complete responses. A 304 revalidates an exact reviewed cached
  capture and still consumes a request; cached content obeys all input limits.
- The existing 25-second transport timeout and retry classification remain;
  sequential requests have at least a one-second spacing. No unbounded retries,
  concurrency or claim of a strict local wall-clock deadline is introduced. The
  existing hosted 40-minute job timeout remains a separate outer bound.
- Preview and final receipts stay at most 2,000,000 serialized bytes, with all
  174 targets accounted for. Oversized receipts fail, not silently truncate.
- Existing vault, delivery, archive, default-monitor and public compressed/
  expanded-size bounds all remain unchanged.

Transport changes must be optional per-invocation restrictions and preserve the
ordinary collector's defaults. Body accounting must handle error/partial reads
and cache paths rather than just successful 200 responses. Each target appears
once in normalized accounting. Failure codes distinguish source drift/access,
normalization/identity, stale preview, lock contention, storage, audit, candidate
capacity/validation and backup. Raw bodies and raw exception strings do not enter
operational/public receipts.

## Testing and acceptance

Use small authored fixtures, never full vendor captures, in committed tests.
The existing public-only stage and raw inputs remain outside Git.

Tests must cover closed profile validation, manifest identity/duplicate rules,
both vendors' schema boundaries, multi-CVE/unaltered version ownership, raw SHA
and CVE/identity drift, disallowed redirects, response/retry/aggregate budgets,
304s, transient failures, unchanged imports, all-target preflight, and isolated
stage failure. Verify source input byte/stat/journal preservation on successful
and failed stages; actual input must not acquire SQLite sidecars.

Preview tests cover all inventory/normalizer/selection/observation drift and
safe paths. Hosted tests use only test-owned encrypted recovery and keys: unknown
controls rejected before key access, correct effect combinations, old Arista and
ordinary behavior unchanged, no backup on failed batch/capacity, and verified
staged-vault backup before Pages readiness. Test backup/push/publication failures
without claiming rollback across external systems.

Capacity tests use authored oversized candidates to prove rejection before
recovery mutation. Real-data acceptance must measure a full 174-target candidate
against all current limits, plus exact existing-record/exclusion preservation,
source/family/version boundaries and native/static exports. If it fails, publish
the measured reason and keep activation blocked. Passing unit tests or a
partial batch does not satisfy complete-corpus publication acceptance.

Run appropriate focused tests and existing full quality/release checks for any
production changes, then independent review. Keep commits small: closed manifest
and contracts, transport restrictions, preview/stage core, hosted dispatch, and
operational documentation/acceptance. Schema v2 remains unchanged; no storage
migration is presently required because the isolated stage uses existing tables.

## Explicitly deferred

Publication payload restructuring if needed to fit the unchanged budgets;
unsupported CVE formats and upstream component discovery; full vendor archives;
model/version inventory matching; independent human adjudication; comparative
patch rates, vendor quality rankings, equivalence, concealment and Glasswing
causal claims. This feature supplies bounded acquisition and safe candidate
construction, not those research conclusions.
