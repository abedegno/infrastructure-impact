# Manual Arista evidence repair

The finite profile `arista-reviewed-sa0137-chronology-0165-0198-v1` repairs
SA137 source selection and the initial publication chronology of 33 other
advisories. It uses the existing maintenance preview/apply path on the full
runner-owned recovery database. It does not enable a new schedule, accept an
operator manifest or change permissions, secrets or capacity limits.

## Scope and evidence

The installed metadata in `resources/arista-hosted-batch.json` names 34 normalized
primaries, 68 required captures and one optional pinned RSS capture. It contains
source URLs, exact hashes and byte counts; no raw document bodies or local paths.
Reference capture timestamps do not become new hosted retrieval timestamps.

Current CSAF owners must match the exact source and CVE identities. Required
structured captures must already be retained. Missing supporting HTML may be
fetched only through the bounded vendor allowlist, with exact size/hash checks.
RSS is retained-only: absence remains visible, and a refreshed rolling feed is
not silently substituted. Changed source ownership requires a reviewed pin update.

SA137 retains the literal draft identity as evidence and selects its verified HTML
view with the existing policy proof. The HTML reports mitigation and no planned
software upgrade, so this repair must not create a patch event. Chronology is
attached before claim identity generation; current dates, version facts and the
SA178 current/revision conflict remain intact. Independent human review stays
pending. SA184 has no paired CSAF in this batch and is excluded.

## Activation

After review and CI, pin `IMPACT_SOURCE_COMMIT` to the merged source containing
this profile. Retain publication format `v2`, the explicitly selected `extended`
recovery profile, and analysis profile `campus-switching-openvuln-2026-11-14-v1`.
No additional credentials are needed.

Run a nonpublishing preview:

```sh
gh workflow run collect.yaml --repo abedegno/infrastructure-impact --ref main \
  -f maintenance_profile=arista-reviewed-sa0137-chronology-0165-0198-v1 \
  -f maintenance_mode=preview \
  -f switching_analysis_profile=campus-switching-openvuln-2026-11-14-v1
```

Review its bounded `maintenance-preview.json`. Missing or changed required owners
block apply. Missing HTML is a bounded retrieval prerequisite, not permission to
replace a changed primary. Optional RSS absence is nonblocking. The fingerprint
binds source inventory, selection policy, normalizers and capture identities or
absence; apply rechecks it under the writer lock.

Apply only the accepted preview fingerprint:

```sh
gh workflow run collect.yaml --repo abedegno/infrastructure-impact --ref main \
  -f maintenance_profile=arista-reviewed-sa0137-chronology-0165-0198-v1 \
  -f maintenance_mode=apply \
  -f maintenance_preview_fingerprint=ACCEPTED_PREVIEW_FINGERPRINT \
  -f switching_analysis_profile=campus-switching-openvuln-2026-11-14-v1
```

## Acceptance and failure

A completed receipt accounts for all 34 primaries as imported or unchanged and
validates every required supporting capture and the exact draft-selection proof.
Inspect the full-source report, audit, build, recovery readback and Pages result.
Verify the live publication identity, optional analysis presence, corrected initial
dates and KEV reconciliation; preserve the API profile and explicit unknowns.

A repeated apply may report all 34 unchanged. A failed apply does not grant Pages
readiness. Existing authenticated recovery behavior may retain captures or earlier
revisions on a failed isolated run; it is not a promise of rollback. The previous
Pages publication remains active. Do not publish a partial local database, raise
limits, bypass owner checks or rebuild repeatedly without diagnosing a failure.

The cached public acceptance test proves these source transformations, not actual
hosted readiness. A real preview and full-source apply are still required.
