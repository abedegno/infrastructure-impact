# Read-only hosted candidate certification — 8 November 2026

The maintainer approved merging PR #42, installing the prepared manual read-only
certification workflow and running it against the full hosted baseline. PR #42
merged as `1c5657821d50022fa9d5ae8944c02d30dc13e26d`; its reviewed source is
`3c6652a7d5eedfb9292f1a701938677054dbec6e`.

The installed workflow is `.github/workflows/candidate-certification.yaml`, kept
byte-identical to `deploy/github-candidate-certification.yaml`. It has only
`contents: read` and `actions: read`, runs manually, and cannot advance accepted
recovery or deploy Pages. Its restore inherits the existing
`IMPACT_VAULT_PROFILE=large` setting: the approved 1 GiB profile, rather than the
512 MiB default that cannot restore the current 704,847,872-byte database. No
limit was raised and no live source setting changed.

Certification selects the reviewed source above, explicit v2 format and the fixed
174-document `campus-switching-public-gap-2026-11-07-v1` profile. It restores and
stages only on the GitHub runner. No actual vault, ciphertext or recovery key is
downloaded to the operator's local machine. Only allowlisted result metadata is
read locally; encrypted capture artifacts can be reused inside subsequent runs.

## Baseline recorded before dispatch

- Accepted source: `cedc552479ff2d7467388d434ae5ea961abc82b2`.
- Accepted encrypted archive SHA-256:
  `3ae5233e97e562731448f611aac96d8ac20aeca36ad661ad88efd5dea14a0d96`.
- Accepted database: 704,847,872 bytes.
- Public generation: `749b1131e0074a59826403c63110a47f`, schema v1, generated
  `2026-11-07T17:55:17.617166+00:00`.
- Public index SHA-256:
  `0f150ee5d7470de53575d03e6fde827e14d9ccfb685b03d132510cf1a15a7127`.
- Live source pin remains `d473d60ec46783750fcaa1795035603ca43a9100`; live format
  selection remains v2; recovery remains `github-draft`. No collector was active
  at the baseline check.

## Installation verification

The missing profile passthrough was reproduced by a failing workflow contract
test. The installed/template identity and existing-profile regression then passed
with the certification/capacity tests: 41 tests passed. Ruff, formatting,
actionlint and whitespace checks passed. The template's read-only gates and
artifact restrictions remain unchanged.

Dispatch and final certification results are recorded below when observed. A
passing local installation test is not a hosted candidate acceptance result.

## Hosted attempts and permission proposal

- [First run](https://github.com/abedegno/infrastructure-impact/actions/runs/42495298670)
  failed during accepted-state restore. No stage or validation ran.
- [Diagnostic retry](https://github.com/abedegno/infrastructure-impact/actions/runs/42496077029)
  also failed at restore. Its bounded allowlisted result reports
  `restore_error: {category: remote_http, http_status: 403}` and
  `stage_step: skipped`. No actual vault or ciphertext was downloaded locally.

The denial is consistent with GitHub's documented push-access requirement for
[draft release visibility](https://docs.github.com/en/rest/releases/releases#list-releases).
A separate proposal changes certification's `contents: read` to `contents: write`
so the existing authenticated draft recovery reader can operate. It retains
`actions: read`, no Pages or OIDC permissions, no persisted checkout credentials,
no remote-write commands and no publication or promotion steps. The stage step
receives neither the GitHub token nor the recovery key.

The maintainer explicitly approved this broader credential scope on 8 November
2026. [PR #43](https://github.com/abedegno/infrastructure-impact/pull/43) merged as
`4cbcfde0391615641ba417a24f21c0c7c3758d06` at `17:12:40Z`. No fallback to an
older recovery checkpoint or public recovery release is proposed. A passing
workflow contract test cannot establish that hosted restore or certification has
succeeded; that requires an approved hosted run.

## Proposal verification

The permission contract failed against the existing read-only template before
this change, then all 31 certification tests passed. Ruff, formatting,
actionlint and whitespace checks passed. Tests also check that stage receives
neither `GH_TOKEN` nor `IMPACT_STATE_KEY`, and capture encryption receives no
`GH_TOKEN`.

After both failed runs, the accepted manifest SHA-256 remained
`744f1a07352338c2da81ca7ec75d5d815763636e3628519632cc16a53c9317af`;
the public index SHA-256 remained
`0f150ee5d7470de53575d03e6fde827e14d9ccfb685b03d132510cf1a15a7127`;
and the live source pin remained
`d473d60ec46783750fcaa1795035603ca43a9100`.

## Approved certification retry

[Run 42503815667](https://github.com/abedegno/infrastructure-impact/actions/runs/42503815667)
uses workflow revision `4cbcfde0391615641ba417a24f21c0c7c3758d06` and the same reviewed
source `3c6652a7d5eedfb9292f1a701938677054dbec6e`. Accepted-state restore succeeded
in three seconds (`17:13:04Z` to `17:13:07Z`), confirming the permission fix.
Preview passed; staging ran from `17:13:08Z` to `17:56:02Z`. The final job failed
with `failure_code: candidate_validation` and `candidate_validated: false`.
The allowlisted result was inspected; actual encrypted capture bytes and private
state remained on GitHub.

All **174 targets imported**, using 174 HTTP attempts and 32,176,699 received/input
bytes. The import audit passed. The worker completed normally (return code 0)
after **2,368.08 seconds**, with candidate rejection recorded in its result; this
was neither the outer 40-minute worker timeout nor a failed recovery/download.
Its native/static query-comparison phase failed; the existing sanitized events
do not disclose which internal check or exception caused that failure. Do not
claim a proven semantic mismatch, capacity failure or OOM from these events.

| Phase | Elapsed seconds | Peak resident bytes |
| --- | ---: | ---: |
| Initial native query | 87.50 | 2,574,475,264 |
| Initial public projection | 281.60 | 5,732,397,056 |
| Publication writing | 522.32 | 5,732,397,056 |
| Physical inspection | 17.92 | 5,732,397,056 |
| Independent native query | 94.27 | 5,732,397,056 |
| Independent public projection | 288.02 | 5,750,542,336 |
| Native root verification | 509.41 | 5,750,542,336 |
| Native query comparison (failed) | 521.19 | 5,868,761,088 |

CPU time closely tracks wall time in these phases. Validation consumed about
92% of the staging step. The worker's failure came before standalone monitor and
final capacity acceptance, so those checks remain unproven. The result does not
justify raising limits or activating the source pin.

Both artifacts uploaded successfully. The encrypted acquisition checkpoint is
480,275 bytes and can be reused on the GitHub runner via
`previous_capture_run_id=42503815667` within its 14-day retention. A retry must
first address or diagnose the failed comparison; repeating unchanged work would
spend another validation run without new evidence.

Accepted-manifest and public-index hashes and the live source pin were rechecked
after completion and match the unchanged values recorded above. No accepted
recovery, live source activation or public publication was performed.

Next engineering work should isolate the failure inside
`publication.native_queries` with a bounded, closed error classification and a
small reproducer, then address the measured CPU and memory costs. Raw worker
tracebacks, paths, evidence bodies and secrets must remain private. Root
verification passed; removing its checks merely to reduce runtime is not a fix.
