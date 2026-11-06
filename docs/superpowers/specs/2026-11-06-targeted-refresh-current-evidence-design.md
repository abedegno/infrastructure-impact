# Exact-target refresh and current-evidence dispositions

Date: 6 November 2026. Status: design for approval, not implemented or activated.
Base: merged PR #32, `a9014f01a697c98103e908a9941a91f62417d890`.

## Intent and approved direction

The maintainer asked to merge #32, implement exact-target maintenance, preserve
history while visibly excluding unsupported interpretations from current counts,
and prepare a separately approved release/deployment preview. The first motivating
case is Arista SA-0103: the reviewed HTML names CVE-2024-6858, while its advertised
CSAF capture names CVE-2023-5501. The current research hook rejects that CSAF scope,
but its old normalized record still enters catalogue and other current views.

The two-source preview also corrects SA-0099's CVE/version grouping. It demonstrated
two imports plus an expected alternate conflict, while preserving every original
evidence/revision row. A vendor-scoped replay budget cannot select precisely these
two advisories and cannot replace the required live representation selection.

Success means an exact, bounded writer operation, a transparent current-evidence
decision, and consistent current counts across every reader/export. History and
source capture facts remain available. No statement of unaffectedness, a CVE alias,
verified fix availability, vendor completeness, comparative quality or concealment
is created by a disposition.

### Approaches

The chosen direction follows the requested exclusion-and-history behavior:

1. **Shared current-evidence partition plus an exact-target profile:** recommended.
   One registered, source-led policy partitions supported current records from
   retained exclusions. Every consumer uses the partition. A separately selected
   maintenance profile refreshes only its two fixed primary targets.
2. Warning-only changes would preserve misleading current counts. They do not
   satisfy the requested count/export behavior.
3. Deleting or renaming the old CSAF identity would destroy provenance or invent
   a CVE equivalence. Reprocessing the first two Arista records is not targeting.

The contract names and bounds below are implementation proposals, not statements
that the maintainer previously selected those details.

## Constraints and non-goals

- Preserve advisory schema v2 and immutable evidence/revision history. Add
  publication/report contracts without rewriting stored advisory payloads.
- Preserve default sources, frozen study/review definitions, human-review status,
  schedules, permissions, recovery backend/keys, capacity and delivery limits.
- No customer data, private native vault, firmware artifact, auth credential or
  raw source body enters Git or a public report.
- No arbitrary-URL maintenance endpoint, generic model/version matching, backfill,
  Cisco model-pilot enrolment or unrelated parser changes in this milestone.
- No publication triggered by merging implementation. Source release, runtime pin
  and controlled maintenance dispatch remain explicit later approval steps.

## 1. Exact-target maintenance

### Registered profile and bounds

Add a closed, versioned profile registry. The first profile is
`arista-reviewed-2024-0099-0103-v1`, with exactly these primary targets:

- `https://www.arista.com/en/support/advisories-notices/security-advisory/19862-security-advisory-0099`
- `https://www.arista.com/en/support/advisories-notices/security-advisory/19917-security-advisory-0103`

Only SA-0103's already reviewed advertised alternate may also be retrieved:
`https://www.arista.com/assets/data/SecurityAdvisories/CSAF/arista_networks_security_advisory_103.json`.
Allow at most three distinct retrieval URLs, with a lower per-profile two-million-
byte cap per document and the existing transport retry bound. Redirects outside
this exact reviewed set fail, including redirects elsewhere on an allowed vendor
host. No feed, archive, upstream registry, release-source or KEV fetch is part of
this profile. An unknown profile fails before recovery assets are opened.

The public profile specifies identities, expected primary scope and policy version;
it contains no local paths, secret values or embedded captured source documents.
There is no arbitrary URL or user-provided JSON profile input on the hosted path.

### Preview and application

Provide a local read-only preview command with explicit database/profile/output
arguments. Preview performs no migration, HTTP, writer-lock acquisition or writes
to the input vault. It reports the exact targets, matching retained identities,
expected disposition predicates, missing captures, current parser fingerprints
and a canonical fingerprint of the latest-record baseline. Missing inputs remain
unknown; preview does not fabricate an expected import count.

Application requires the named profile and an accepted preview fingerprint. The
local apply path accepts an explicit preview file. The hosted single-run input
accepts the expected baseline fingerprint alongside the profile name; its matching
preview is produced by a separate read-only run against the runner's own public
vault if that fingerprint cannot be established from existing public metadata.
No local stage is substituted for a hosted preview. State changes since preview
refuse application; a new preview is required.

Use the existing process writer lock once for the entire operation. Refactor a
shared writer core if needed; do not nest `collect_once()`'s lock or call an
ordinary collection as a side effect. Check the baseline after acquiring the lock.
Fetch and validate both selected primaries before appending normalized revisions.
Source captures/check observations can remain after an unsuccessful attempt, but
a failed primary must not publish a partially accepted current-evidence generation.

The reviewed alternate CVE conflict is an explicit partial outcome only after its
actual literal identity/CVE discrepancy is validated. Do not classify arbitrary
alternate transport/layout failures as this expected conflict. Preserve current
source-selection receipts, alternate issue visibility and all raw fingerprints.
Never relabel CVE-2023-5501 as CVE-2024-6858.

Rebuild reports and a candidate publication from retained data, run audit, and
perform the existing authenticated backup/readback before Pages publication can
proceed. Do not call the benchmark acquisition routine: it can fetch additional
sources. Source-led benchmark evaluation/report rebuilding remains read-only.
Reuse the existing recovery path and private staging; no new recovery backend.

### Hosted dispatch

Add optional `maintenance_profile` and `maintenance_preview_fingerprint` inputs
to the existing manual workflow and helper. Defaults remain empty. A profile is
mutually exclusive with positive generic reparse controls and ordinary acquisition.
The one-run branch must be visibly distinct from the ordinary incremental path.
Synchronize the reusable deployment template. Do not add recurring maintenance
variables or change cron, permissions, cadence anchors or environments.

A read-only hosted preview mode must not back up, commit recovery state or upload
Pages. It may retain a bounded, sanitized preview receipt as an Actions artifact.
It uses the same validated profile and authenticated restore boundary, without
opening raw evidence to the agent or the public. Encrypted state/key access remains
inside the existing runner helper. Manual preview/apply dispatches need rollout
approval; implementation of the opt-in controls does not authorize them.

Receipts distinguish attempted primary targets, selected representations, alternate
checks/conflicts, imports/unchanged records, exclusions, remaining gaps, baseline,
policy fingerprint, audit and recovery outcomes. Expected conflict is never shown
as all-sources success. Retry/idempotence tests use identical retained bytes; a
fresh HTTP capture with changed bytes remains a new capture.

## 2. Current-evidence policy

### Shared pure partition

Introduce one vendor-neutral application service that takes retained latest
advisories plus validated source-selection context and registered vendor policies.
It returns current records, retained excluded records and strict decision metadata.
The default preserves existing records: a stale parser fingerprint, missing metric,
access error, draft or unknown model is not by itself evidence of a wrong claim.
Do not build a heuristic global invalidation mechanism.
Current-view inclusion is not independent impact certification; it only means no
applicable registered exclusion decision removes that record from this view.

Policies are optional plugin hooks/resources with explicit version/fingerprint,
validated output and bounded reasons. An external plugin without this capability
continues unchanged. The registry isolates hook inputs and rejects unsupported
statuses, unknown record references, non-official proof URLs and unbounded output.
Limit the new decision report to 1,000 decisions and two million serialized bytes;
exceeding a bound fails publication rather than silently dropping exclusions.

The first Arista policy requires all of:

- Exact target vendor, source URL, literal CSAF advisory identity
  `Arista Networks Security Advisory 103`, and CVE set `{CVE-2023-5501}`.
- Target capture SHA-256
  `3491af5ed3486c8e74fd04cd432a5072bf0938733cd059d9d24e7f3f2355ef74`.
- A retained, independently validated SA-0103 HTML primary naming only
  CVE-2024-6858, selected through the reviewed policy, with matching record/view
  source fingerprints and the corresponding explicit alternate conflict.

This is a rule about that exact retained interpretation, not about every Arista
CVE-2023-5501 record. No source-URL-only exclusion, ID prefix match, broad CVE filter
or future-hash inheritance is allowed. Changed/missing/conflicting supporting proof
must produce an unresolved decision and block acceptance of the targeted cleanup.
It must not silently authorize current-count removal or claim a completed repair.

Use `excluded_from_current` with reason `reviewed_representation_scope_conflict`.
Each decision binds the vendor/advisory/revision, original source URL/hash, policy
identity/fingerprint, supporting primary source URL/hash/locator, and analysis time.
The primary is a representation-selection reference, never a CVE alias or renamed
revision. Analysis time is neither a publisher change nor a new retrieval time.

Derive decisions from immutable retained evidence/selection facts and the registered
policy at generation time. No database migration or mutable override table is
needed in this milestone. Keep the resulting decisions frozen in each publication
so readers never apply today's rule to an older immutable generation. Future
operator adjudication or reversal workflows require their own design.

### Public contracts and current/historical semantics

Keep `records` as the default current advisory list, partitioned before any current
analytics. Excluded records remain available in a separate generation-bound
`retained_advisories` collection; do not add disposition fields to schema-v2 records.
Publish `current-evidence.json` with a new strict v1 report schema and decisions.
Add current, retained and excluded advisory totals, clearly labelled in the UI.

Use a separate GET/HEAD retained-advisory API with the existing vendor/CVE/pagination
limits, returning record plus decision reference in an envelope. Provide equivalent
static fragments and explicit historical JSON/CSV downloads. Historical assessment
exports must label every row `excluded_from_current` with decision/policy references
and must not look like the default current assessment export. Include both current
and retained collections in the hash-verified full public snapshot/archive.

Default `/api/v1/advisories`, `/api/v1/assessments`, catalogue, comparisons, coverage,
scorecards, families/groups, eligibility/readiness, current dossiers/claims,
`all_cves`, assessment exports and dashboard filtering consume current records.
An excluded record is not an unaffected product, a patch event or evidence of an
unaffected CVE. CVE-level KEV remains independent: retain available KEV context for
historical CVEs without restoring unsupported vendor product claims.

History/change/source-health views and source-audit provenance retain the complete
retained record context, labelled as such. Frozen study/review resources, original
blind packets and stored historical generations are not rewritten. The first
policy must be tested against the actual frozen cases: if a case is supported only
by excluded current scope, its current evaluation cannot be advertised as a valid
current pass. Preserve its expectation and historical result, and expose a distinct
excluded-current-scope outcome/reason in current validation metadata rather than
silently treating retained evidence as absent or altering the expectation.

The shared partition must run in `application.query.state`, reporting, and the
publication privacy boundary. At the boundary, reconstruct the retained union and
recompute decisions from registered policies and source-bound context; never trust
a caller-supplied exclusion flag/report. Regenerate all affected current reports,
not just catalogue numbers. Strict validation checks partition disjointness, union
completeness, decision references, source identities and all current/retained totals.

Python and browser selectors/exports use the same published partition and decisions.
The browser validates the contract and never performs source-policy inference.
Maintain the existing manifest, index, part and monitor limits. Retained pages use
bounded parts rather than inflating the default page or duplicating full records
in the decision report. Include schema/assets in packaging and `openapi.json`.

### Older publications

An older generation without the new report remains readable under its original
published semantics. Display dispositions as unavailable/not reported, rather than
claiming zero exclusions or applying later evidence to it. New writers require the
new report and consistent partition; missing/corrupt new-generation metadata fails
validation and retains the previous public generation. Readers must never mix an
old generation's records with a current generation's decision report.

## 3. Rollout and rollback

Implementation and review happen locally with synthetic fixtures and separate
public-only stages. No native/customer vault or recovery material is inspected by
the agent. Complete source/wheel/plugin/privacy/CI and deployed-reader parity gates
before proposing any release or hosted operation.

After separate approval, publish the exact source release, activate its reviewed
pin, obtain a read-only hosted preview and review its bound fingerprint/delta.
Then approve one profile apply. Accept only after exact targets, history retention,
current-view exclusion, all report/export counts, explicit partial alternate status,
audit, authenticated recovery, manifest/archive integrity and monitor results agree.
No automatic retry or broad maintenance fallback after a failed primary.

The old runtime can read the SQLite format because no migration is proposed, but
it does not understand the new current-evidence policy and can reintroduce the old
unsupported current claim. Therefore a code-pin downgrade plus another collection
is not a safe semantic rollback. Preserve the previous immutable generation and
checkpoints; choose a policy-aware helper or explicitly reviewed recovery/publication
procedure before rollback. A source-pin change never undoes appended evidence or
restores Pages by itself. Do not change scheduling to manufacture a safe rollback.

## 4. Verification and acceptance

1. Named profile selection, unknown/malformed inputs, pre-recovery validation,
   baseline drift, mutual exclusion, lock contention, three-URL and byte bounds,
   hostile redirects, missing primaries and unexpected alternate errors.
2. Both exact reviewed source replays, identical-byte idempotence, preserved first
   capture times and every old revision/evidence row. No CVE alias/deletion.
3. Positive conflict decision plus hash/identity/CVE/primary-proof mutations;
   unrelated vendors/records, matching later representations and missing hooks.
4. Current/retained partition invariants and full native/static/JSON/CSV parity,
   including explicit historical selections, zero matches, missing metadata,
   same-generation downloads and older generation compatibility.
5. All current reducers and validation displays, KEV/vendor affectedness separation,
   frozen-resource byte equality and no fabricated human review/disclosure events.
6. Installed wheel/external-plugin capability, new schemas/OpenAPI/resources,
   source/privacy export, frozen dependency exports, supported Python versions,
   container and a fresh whole-branch review. No new runtime dependency is proposed.

The review must cover the whole data path: filtering one UI table while leaving
CSV, scorecards or static endpoints unfiltered does not satisfy acceptance.
