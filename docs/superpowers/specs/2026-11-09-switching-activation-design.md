# One-off switching evidence activation

The maintainer approved merge, activation of the reviewed code, retention of
Cisco ERP-75056 and import of Aruba 2021-019, followed by publication and a new
comparison brief. PR45 is merged as 4f8f78baf1a327866d67c10f5bbedfec1ddf9041.
Routine questions were previously waived. This is bounded operational glue, not
a new collector or a change to scheduled collection, workflow permissions or data limits.

Use the existing main-branch collect workflow with a temporarily pinned, reviewed
operations source commit. Its stock main entry remains unchanged unless exactly
the closed switching activation profile is requested. A separate package module
handles that profile using existing restore, writer, target-import staging,
full-candidate validation, remote backup/readback and publication effects.
After success, pin ordinary runtime back to merged PR45. Leave the operation
branch auditable; do not merge its temporary hook into main.

Preview restores accepted recovery only on the GitHub runner and emits bounded
public metadata plus a fingerprint binding accepted recovery, current records,
normalizers, reviewed inputs and operations source commit. It does not retrieve,
modify recovery or publish. Apply requires that exact fresh preview fingerprint.

Apply modifies only the disposable restored database: reparse the two reviewed
Arista HTML identities from their retained bytes (same identity and CVE sets),
retain verified ERP-75056 as source-only evidence, and use the stock exact-target
stage for Aruba 2021-019 plus a mandatory cache-only revalidation of the retained
Cisco DHCP bundle member. The latter supplies the two-vendor fingerprint set
required by existing schemas; it creates no new factual claim or vendor request. Original revisions/captures stay intact. Full stock
candidate checks remain mandatory. Promote encrypted recovery only after they
pass, authenticate/read it back, then expose only the validated public directory.
Errors emit closed metadata, never raw worker logs, keys, private paths or records.
The original/private vault and key must never leave the runner.

Unknown sources, mismatched hashes/CVEs, stale previews, absent expected Arista
records, malformed/duplicate controls, unsupported modes and failed candidate
checks fail without accepted recovery promotion or publication. No arbitrary URL,
SQL or shell inputs; no generic policy/validator bypass. A local profile-registration
adapter may supply the one validated custom TargetImportProfile to stock preview,
restoring the original lookup afterward. Fresh worker from_manifest validation
must remain untouched.

Use existing publication/recovery directories, profiles and limits, source-only
ERP evidence rather than a fake advisory, and no unrelated sync or full backfill.
