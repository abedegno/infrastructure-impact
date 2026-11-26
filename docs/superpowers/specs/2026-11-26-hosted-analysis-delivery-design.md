# Named hosted precomputed delivery profile

## Intent and authority

User approved implementing the next hosted-profile wiring step. Standing opt-out
of repeated brainstorming gates and subagent-driven execution preference persist.
Create tested, reviewable code and an activation proposal. Actual source-pin or
repository-variable changes, workflow dispatch, collection, deployment, schedules,
permissions and secrets are not authorized here. PR90 remains unmerged.

## Approach

Keep delivery independent of the scientific switching-analysis input profile.
Use installed hash-pinned resource bytes, not operator paths/JSON/URLs. New
`analysis_delivery_profiles.py` resolves only `campus-switching-common-views-v1`
(or blank for disabled), with its JSON under `resources/analysis-delivery/`.
Resource options are the exact eight normalized dictionaries:
All/Cisco/Aruba/Arista × all/2025, scope_level=os_family, cve_ids=null, in that
order. The year2025 is fixed, not a rolling previous-year policy. Resource
identity uses profile_id and input_sha256. Each caller receives a fresh copy.

Alternatives: ad hoc hosted JSON/paths weaken the existing closed operator
boundary; enabling the low-level default flag hides the independently chosen
expected views. The installed named profile fits the current scientific profile
and subprocess verification pattern. These implementation choices are the
controller's decisions under the approved wiring request.

The delivery profile never turns on or changes scientific analysis itself. Hosted
use requires v2 and an explicitly selected, valid scientific analysis profile.
Snapshot/publish use requires explicit include_switching_analysis=True. Reject
unknown IDs/types, v1, absent analysis and incompatible recovery-only modes before
state/recovery/collector effects. Blank defaults omit new kwargs/metadata/CLI
arguments and preserve the legacy path. No hosted setting is installed or enabled.

## End-to-end paths

Expose named `analysis_delivery_profile=''` at build/publish, worker.collect_once,
ops/hosted_job CLI (`--analysis-delivery-profile`), relevant existing snapshot and
target-import-stage CLI boundaries, and independent native verification. Public
low-level writer raw options remain available as before; hosted operators get only
the installed ID. Compose low-level analysis_precomputed_delivery=True and fresh
analysis_precomputed_options from the named resource at the writer boundary.
Resolve it independently at verification. Never learn expected options from the
advertised manifest or trust a supplied list. Reject conflicting named/raw
verification choices without weakening existing raw prototype APIs.

Ordinary, generic maintenance apply and target-import candidate/publication
verification carry the same selection. Preview performs validation but does not
publish or acquire a new effect. Bind delivery identity in target-import private
context and request exactly as scientific identity is bound, including the
independent isolated-worker command-line selector. Validate missing/injected/null,
wrong ID/hash and paired request/context tampering. The isolated worker reloads
installed bytes and the caller's explicit selector; no artifact can grant opt-in.
Preserve old positional argv combinations; reject invalid new combinations.
Operator verification must reject missing or unexpected delivery roots for its
explicit mode; this must not silently change low-level prototype verification.

Workflow input `analysis_delivery_profile` and repository-variable fallback
`IMPACT_ANALYSIS_DELIVERY_PROFILE` default blank. Both preflight and invocation
validate the closed ID and scientific/v2 prerequisites and prove the pinned helper
supports the new flag. A configured unsupported old helper fails before any
private collector, recovery/key access or publication step. Keep the existing
helper protocol and all schedules/permissions/secrets unchanged. Moving capability
preflight ahead of the existing private collector is allowed to enforce that
ordering; ordinary blank configuration keeps its existing arguments/effects.

## Tests and evidence

Use synthetic/public inputs only, no .env, vault/private artifacts or new vendor
fetches. Do not run hosted collection or dispatch. No dependencies or scientific,
advisory schema, source membership, native wire, inference or budgets change.
Keep part8MB, selected/export128MB, rawcache16MB and site1GB limits.

RED/GREEN tests cover resource hash/type/shape/order and immutable options; default
opt-out and early rejection; actual publication and fresh native-query verification;
worker/build forwarding; ordinary/maintenance/preview paths; isolated metadata/CLI
tampering; old-helper workflow rejection and blank compatibility; packaged resource.
Use the current test patterns, real synthetic database/staging and actual extracted
workflow scripts. No fake success or self-hashed manifest as authority.

The PR91 pinned generation already passed complete native eight-view generation,
independent regeneration, all12 browser download hashes and capacity940258473B
(conservative accepted-artifact union941172658B). Prove this installed profile's
normalized options equal that independent receipt; use fixture-based real operator
rehearsal for the new routing. Do not repeat the same 12-minute large publication
or old browser benchmark when no writer wire/scientific/frontend behavior changed.
If a material change invalidates that proof, run the relevant fresh gate and say
why. Retain all existing caveats, low-memory limits and human review pending.

## Integration and activation

Small reviewable commits, tests, independent task/final reviews and a PR. Default
configuration remains blank. Prepare exact current/proposed profile/pin settings,
capability/preflight/rollback instructions and outstanding limitations. Obtain
separate approval before applying hosted settings or dispatching a publish.
